local crypto = require "kong.plugins.basic-auth.crypto"
local constants = require "kong.constants"
local sandbox = require "kong.tools.sandbox".sandbox

local ngx = ngx
local decode_base64 = ngx.decode_base64
local re_gmatch = ngx.re.gmatch
local re_match = ngx.re.match
local error = error
local kong = kong


local realm = 'Basic realm="' .. _KONG._NAME .. '"'

local sandbox_opts = { env = {
  kong = kong,
  ngx = ngx,
  md5    = require("resty.md5"),
  sha1   = require("resty.sha1"),
  sha224 = require("resty.sha224"),
  sha256 = require("resty.sha256"),
  sha384 = require("resty.sha384"),
  sha512 = require("resty.sha512"),
  to_hex = require("resty.string").to_hex,
} }

local _M = {}


-- Fast lookup for credential retrieval depending on the type of the authentication
--
-- All methods must respect:
--
-- @param request ngx request object
-- @param {table} conf Plugin config
-- @return {string} public_key
-- @return {string} private_key
local function retrieve_credentials(header_name, conf)
  local username, password
  local authorization_header = kong.request.get_header(header_name)

  if authorization_header then
    local iterator, iter_err = re_gmatch(authorization_header, "\\s*[Bb]asic\\s*(.+)")
    if not iterator then
      kong.log.err(iter_err)
      return false
    end

    local m, err = iterator()
    if err then
      kong.log.err(err)
      return false
    end

    if m and m[1] then
      local decoded_basic = decode_base64(m[1])
      if decoded_basic then
        local basic_parts, err = re_match(decoded_basic, "([^:]+):(.*)", "oj")
        if err then
          kong.log.err(err)
          return true
        end

        if not basic_parts then
          kong.log.err("header has unrecognized format")
          return true
        end

        username = basic_parts[1]
        password = basic_parts[2]
      end
    end
  end

  if conf.hide_credentials then
    kong.service.request.clear_header(header_name)
  end

  return true, username, password
end


--- Validate a credential in the Authorization header against one fetched from the database.
-- @param credential The retrieved credential from the username passed in the request
-- @param given_password The password as given in the Authorization header
-- @return Success of authentication
local function validate_credentials(conf, credential, given_password)
  if conf.password_hash and #conf.password_hash > 0 then
    for _, expression in ipairs(conf.password_hash) do
      local digest = sandbox(expression, sandbox_opts)(credential, given_password)
      if credential.password == digest then
        return true
      end
    end
  end

  local digest, err = crypto.hash(credential.consumer.id, given_password)
  if err then
    kong.log.err(err)
  end

  return credential.password == digest
end

local function validate_expire_time(credential)
  return not credential.expire_at or credential.expire_at <= 0 or credential.expire_at > ngx.time()
end

local function load_credential_into_memory(username)
  local credential, err = kong.db.basicauth_credentials:select_by_username(username)
  if err then
    return nil, err
  end
  return credential
end


local function load_credential_from_db(username)
  if not username then
    return
  end

  local credential_cache_key = kong.db.basicauth_credentials:cache_key(username)
  local credential, err      = kong.cache:get(credential_cache_key, nil,
                                              load_credential_into_memory,
                                              username)
  if err then
    return error(err)
  end

  return credential
end


local function set_consumer(consumer, credential)
  kong.client.authenticate(consumer, credential)

  local set_header = kong.service.request.set_header
  local clear_header = kong.service.request.clear_header

  if consumer and consumer.id then
    set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
  else
    clear_header(constants.HEADERS.CONSUMER_ID)
  end

  if consumer and consumer.custom_id then
    set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
  else
    clear_header(constants.HEADERS.CONSUMER_CUSTOM_ID)
  end

  if consumer and consumer.username then
    set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
  else
    clear_header(constants.HEADERS.CONSUMER_USERNAME)
  end

  if credential and credential.username then
    set_header(constants.HEADERS.CREDENTIAL_IDENTIFIER, credential.username)
    set_header(constants.HEADERS.CREDENTIAL_USERNAME, credential.username)
  else
    clear_header(constants.HEADERS.CREDENTIAL_IDENTIFIER)
    clear_header(constants.HEADERS.CREDENTIAL_USERNAME)
  end

  if credential then
    clear_header(constants.HEADERS.ANONYMOUS)
  else
    set_header(constants.HEADERS.ANONYMOUS, true)
  end
end


local function fail_authentication()
  return false, { status = 401, reason = "Invalid", message = "Invalid authentication credentials" }
end

local function expired_credential()
  return false, { status = 401, reason = "Expired", message = "Expired authentication credentials" }
end

local function do_authentication(conf)
  -- If both headers are missing, return 401
  if not (kong.request.get_header("authorization") or kong.request.get_header("proxy-authorization")) then
    return true, {
      status = 401,
      reason = "Unauthorized",
      message = "Unauthorized",
      headers = {
        ["WWW-Authenticate"] = realm
      }
    }
  end

  local credential
  local found, given_username, given_password = retrieve_credentials("proxy-authorization", conf)
  if given_username and given_password then
    credential = load_credential_from_db(given_username)
  end

  -- Try with the authorization header
  if not found then
    found, given_username, given_password = retrieve_credentials("authorization", conf)
    if given_username and given_password then
      credential = load_credential_from_db(given_username)
    end
  end

  if not found then
    return true
  end

  if not credential then
    return fail_authentication()
  end

  if not validate_expire_time(credential) then
    return expired_credential()
  end

  if not validate_credentials(conf, credential, given_password) then
    return fail_authentication()
  end

  -- Retrieve consumer
  local consumer_cache_key = kong.db.consumers:cache_key(credential.consumer.id)
  local consumer, err      = kong.cache:get(consumer_cache_key, nil,
                                            kong.client.load_consumer,
                                            credential.consumer.id)
  if err then
    return error(err)
  end

  set_consumer(consumer, credential)

  return true
end


function _M.execute(conf)
  if conf.anonymous and kong.client.get_credential() then
    -- we're already authenticated, and we're configured for using anonymous,
    -- hence we're in a logical OR between auth methods and we're already done.
    return
  end

  local continue, err = do_authentication(conf)
  if err then
    if continue and conf.anonymous then
      -- get anonymous user
      local consumer_cache_key = kong.db.consumers:cache_key(conf.anonymous)
      local consumer, err      = kong.cache:get(consumer_cache_key, nil,
                                                kong.client.load_consumer,
                                                conf.anonymous, true)
      if err then
        return error(err)
      end

      set_consumer(consumer)
    else
      return kong.response.error(err.status, err.message, err.headers)
    end
  end
end


return _M
