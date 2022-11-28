local constants = require "kong.constants"
local sha256 = require "resty.sha256"
local to_hex = require "resty.string".to_hex
local openssl_hmac = require "resty.openssl.hmac"
local utils = require "kong.tools.utils"
local new_tab = require "table.new"

local ngx = ngx
local kong = kong
local error = error
local time = ngx.time
local abs = math.abs
local decode_base64 = ngx.decode_base64
local encode_base64 = ngx.encode_base64
local parse_time = ngx.parse_http_time
local re_gmatch = ngx.re.gmatch
local hmac_sha1 = ngx.hmac_sha1
local ipairs = ipairs
local pairs = pairs
local fmt = string.format
local string_lower = string.lower
local string_find = string.find
local string_sub = string.sub
local insert = table.insert
local concat = table.concat
local sort = table.sort
local kong_request = kong.request
local kong_client = kong.client
local kong_service_request = kong.service.request


local AUTHORIZATION = "authorization"
local PROXY_AUTHORIZATION = "proxy-authorization"
local DATE = "date"
local X_DATE = "x-date"
local TIMESTAMP = "timestamp"
local DIGEST = "digest"
local CONTENT_TYPE = "content-type"
local CREDENTIAL_EXPIRED = "HMAC secret has expired"
local SIGNATURE_NOT_VALID = "HMAC signature cannot be verified"
local SIGNATURE_NOT_SAME = "HMAC signature does not match"

local signature_fields = { "username", "algorithm", "signature_version", "nonce" }

local hmac = {
  ["hmac-sha1"] = function(secret, data)
    return hmac_sha1(secret, data)
  end,
  ["hmac-sha256"] = function(secret, data)
    return openssl_hmac.new(secret, "sha256"):final(data)
  end,
  ["hmac-sha384"] = function(secret, data)
    return openssl_hmac.new(secret, "sha384"):final(data)
  end,
  ["hmac-sha512"] = function(secret, data)
    return openssl_hmac.new(secret, "sha512"):final(data)
  end,
}

local function list_as_set(list)
  local set = kong.table.new(0, #list)
  for _, v in ipairs(list) do
    set[v] = true
  end

  return set
end

local function validate_expire_time(credential)
  return not credential.expire_at or credential.expire_at <= 0 or credential.expire_at > ngx.time()
end

local function validate_params(params, conf)
  -- check username and signature are present
  local missing, fields = false, {}
  for name in pairs(conf.auth_fields) do
    if not params[name] then
      insert(fields, name)
      missing = true
    end
  end

  if missing then
    return nil, "required hmac arguments missing: " .. concat(fields, ',')
  end

  -- check enforced headers are present
  if conf.enforce_headers and #conf.enforce_headers >= 1 then
    local enforced_header_set = list_as_set(conf.enforce_headers)

    if params.hmac_headers then
      for _, header in ipairs(params.hmac_headers) do
        enforced_header_set[header] = nil
      end
    end

    for _, header in ipairs(conf.enforce_headers) do
      if enforced_header_set[header] then
        return nil, "enforced header not used for signature creation"
      end
    end
  end

  -- check supported algorithm used
  for _, algo in ipairs(conf.algorithms) do
    if algo == params.algorithm then
      return true
    end
  end

  return nil, fmt("algorithm %s not supported", params.algorithm)
end

local AUTHORIZATION_HEADER_TEMPLATE = [[\G\s*(?<k>%s)=\"(?<v>[^"]+)\"\s*,?]]
local function retrieve_hmac_fields_in_header(conf, authorization_header)
  -- parse the header to retrieve hmac parameters
  if authorization_header then
    if string_lower(string_sub(authorization_header, 1, 5)) ~= 'hmac ' then
      return
    end
    --local iterator, iter_err = re_gmatch(authorization_header,
    --                                     "\\s*[Hh]mac\\s*username=\"(.+)\"," ..
    --                                     "\\s*algorithm=\"(.+)\",\\s*header" ..
    --                                     "s=\"(.+)\",\\s*signature=\"(.+)\"",
    --                                     "jo")
    local fields_conf = conf.auth_fields
    local field_count = #fields_conf
    local fields = new_tab(field_count, 0)
    local rmap = new_tab(0, field_count)
    for key, name in pairs(fields_conf) do
      rmap[name] = key
      insert(fields, name)
    end

    local regex = fmt(AUTHORIZATION_HEADER_TEMPLATE, concat(fields, '|'))
    local iterator, iter_err = re_gmatch(string_sub(authorization_header, 6), regex, "jo")

    if not iterator then
      kong.log.err(iter_err)
      return nil, "unrecognizable hmac authorization header"
    end

    local params = new_tab(0, field_count)
    for m in iterator do
      if m then
        local name = m['k']
        params[rmap[name]] = m['v']
      end
    end

    if params.hmac_headers then
      params.hmac_headers = utils.split(params.hmac_headers, " ")
    end

    kong.log.inspect("retrieve hmac fields from header:", params)
    return params
    --if m and #m >= 4 then
    --  return {
    --    username = m[1],
    --    algorithm = m[2],
    --    hmac_headers = utils.split(m[3], " "),
    --    signature = m[4],
    --  }
    --end
  end

end

--TODO:
local function retrieve_hmac_fields_in_query(conf, request_args)
  -- parse the header to retrieve hmac parameters
  local fields_conf = conf.auth_fields
  if request_args[fields_conf.username] then
    local params = {
        username = request_args[fields_conf.username],
        algorithm = request_args[fields_conf.algorithm],
        hmac_headers = request_args[fields_conf.hmac_headers],
        signature = request_args[fields_conf.signature],
        nonce = request_args[fields_conf.nonce],
    }

    if params.hmac_headers then
      params.hmac_headers = utils.split(params.hmac_headers, " ")
    end
    return params
  end
end

local function retrieve_hmac_fields(conf)
  local hmac_params, err
  if conf.auth_fields_in_header or not conf.auth_fields_in_query then
    for _, header_name in ipairs({ PROXY_AUTHORIZATION, AUTHORIZATION }) do
      local authorization_header = kong_request.get_header(header_name)
      hmac_params, err = retrieve_hmac_fields_in_header(conf, authorization_header)
      if hmac_params then
        hmac_params.in_header = true
        if conf.hide_credentials then
          kong_service_request.clear_header(header_name)
        end
        break
      elseif err then
        return nil, err
      end
    end
  end

  if not hmac_params and conf.auth_fields_in_query then
    local args = kong_request.get_query()
    hmac_params = retrieve_hmac_fields_in_query(conf, args)
    if conf.hide_credentials then
      for _, name in pairs(conf.auth_fields) do
        args[name] = nil
      end
      kong_service_request.set_query(args)
    end
  end

  if hmac_params then
    hmac_params.use_default = {}
    local hmac_headers = hmac_params.hmac_headers
    if not hmac_headers then
      hmac_params.hmac_headers = conf.enforce_headers or {}
      hmac_params.use_default.hmac_headers = true
    end
    if not hmac_params.algorithm and #conf.algorithms == 1 then
      hmac_params.algorithm = conf.algorithms[1]
      hmac_params.use_default.algorithm = true
    end
    if not hmac_params.signature_version and #conf.signature_versions == 1 then
      hmac_params.signature_version = conf.signature_versions[1]
      hmac_params.use_default.signature_version = true
    end
  end

  return hmac_params
end


-- plugin assumes the request parameters being used for creating
-- signature by client are not changed by core or any other plugin
local function create_hash(request_uri, hmac_params)
  local signing_string = ""
  local hmac_headers = hmac_params.hmac_headers

  local count = #hmac_headers
  for i = 1, count do
    local header = hmac_headers[i]
    local header_value = kong.request.get_header(header)

    if not header_value then
      if header == "@request-target" then
        local request_target = string_lower(kong.request.get_method()) .. " " .. request_uri
        signing_string = signing_string .. header .. ": " .. request_target

      elseif header == "request-line" then
        -- request-line in hmac headers list
        local request_line = fmt("%s %s HTTP/%.01f",
                                 kong_request.get_method(),
                                 request_uri,
                                 assert(kong_request.get_http_version()))
        signing_string = signing_string .. request_line

      else
        signing_string = signing_string .. header .. ":"
      end

    else
      signing_string = signing_string .. header .. ":" .. " " .. header_value
    end

    if i < count then
      signing_string = signing_string .. "\n"
    end
  end

  return hmac[hmac_params.algorithm](hmac_params.secret, signing_string)
end

local function create_hash_v2(conf, hmac_params)
  local hmac_headers = hmac_params.hmac_headers
  local request_args = kong_request.get_query(1000)
  local header_count, args_count = #hmac_headers, #request_args

  local signing_parts = new_tab(header_count + args_count + 2, 0)
  local request_line = concat { kong_request.get_method(), " ", kong_request.get_path() }
  insert(signing_parts, request_line)

  for i = 1, header_count do
    local header = string_lower(hmac_headers[i])
    local header_value = kong.request.get_header(header)
    if type(header_value) == 'table' then
      for _, hv in ipairs(header_value) do
        insert(signing_parts, concat { header, ":", hv })
      end
    elseif header_value then
      insert(signing_parts, concat { header, ":", header_value })
    end
  end

  for key, value in pairs(request_args) do
    if key ~= 'signature' then
      if type(value) == 'table' then
        for _, v in ipairs(value) do
          insert(signing_parts, concat { key, "=", v })
        end
      else
        insert(signing_parts, concat { key, "=", value })
      end
    end
  end

  if hmac_params.in_header then
    for _, key in ipairs(signature_fields) do
      if not hmac_params.use_default[key] then
        insert(signing_parts, concat { conf.auth_fields[key], "=", hmac_params[key] })
      end
    end
  end

  sort(signing_parts)
  local signing_string = concat(signing_parts, "\n")
  return hmac[hmac_params.algorithm](hmac_params.secret, signing_string)
end

local function validate_signature(conf, hmac_params)

  if hmac_params.signature_version == "v2" then
    local signature_1 = create_hash_v2(conf, hmac_params)
    return to_hex(signature_1) == hmac_params.signature
  else
    local signature_1 = create_hash(kong_request.get_path_with_query(), hmac_params)
    local signature_2 = decode_base64(hmac_params.signature)
    if signature_1 == signature_2 then
      return true
    end

    -- DEPRECATED BY: https://github.com/Kong/kong/pull/3339
    local signature_1_deprecated = create_hash(ngx.var.uri, hmac_params)
    return signature_1_deprecated == signature_2
  end
end


local function load_credential_into_memory(username)
  local key, err = kong.db.hmacauth_credentials:select_by_username(username)
  if err then
    return nil, err
  end
  return key
end


local function load_credential(username)
  local credential, err
  if username then
    local credential_cache_key = kong.db.hmacauth_credentials:cache_key(username)
    credential, err = kong.cache:get(credential_cache_key, nil,
                                     load_credential_into_memory,
                                     username)
  end

  if err then
    return error(err)
  end

  return credential
end


local function validate_clock_skew(allowed_clock_skew)
  local header
  local date = kong_request.get_query_arg(TIMESTAMP)
  if not date then
    date = kong_request.get_header(X_DATE)
    if date then
      header = X_DATE
    else
      date = kong_request.get_header(DATE)
      header = DATE
    end
  end

  if not date then
    return false
  end

  local requestTime = parse_time(date)
  if not requestTime then
    return false
  end

  local skew = abs(time() - requestTime)
  if skew > allowed_clock_skew then
    return false
  end

  return true, header
end


local function validate_body()
  local body, err = kong_request.get_raw_body()
  if err then
    kong.log.debug(err)
    return false
  end

  local digest_received = kong_request.get_header(DIGEST)
  if not digest_received then
    -- if there is no digest and no body, it is ok
    return body == ""
  end

  local digest = sha256:new()
  digest:update(body or '')
  local digest_created = "SHA-256=" .. encode_base64(digest:final())

  return digest_created == digest_received
end


local function set_consumer(consumer, credential)
  kong_client.authenticate(consumer, credential)

  local set_header = kong_service_request.set_header
  local clear_header = kong_service_request.clear_header

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


local function do_authentication(conf)

  -- retrieve hmac parameter from header or query
  local hmac_params, err = retrieve_hmac_fields(conf)
  if err then
    return false, { status = 401, message = err }
  end

  -- If both headers and request_args are missing, return 401
  if not hmac_params then
    return false, { status = 401, message = "Unauthorized" }, true
  end

  -- validate clock skew
  local allowed_clock_skew, date_header = validate_clock_skew(conf.clock_skew)
  if not allowed_clock_skew then
    return false, {
      status = 401,
      message = "HMAC signature cannot be verified, a valid date or " ..
                "x-date header or timestamp query argument is required for HMAC Authentication"
    }
  end

  if date_header then
    insert(hmac_params.hmac_headers, date_header)
  end

  local ok, err = validate_params(hmac_params, conf)
  if not ok then
    kong.log.debug(err)
    return false, { status = 401, message = err }
  end

  -- validate signature
  local credential = load_credential(hmac_params.username)
  if not credential then
    kong.log.debug("failed to retrieve hmac credential for ", hmac_params.username)
    return false, { status = 401, message = SIGNATURE_NOT_VALID }
  end

  -- credential expired
  if not validate_expire_time(credential) then
    kong.log.debug("hmac credential has expired: ", hmac_params.username)
    return false, { status = 401, message = CREDENTIAL_EXPIRED }
  end
  hmac_params.secret = credential.secret

  -- If request body validation is enabled, then verify digest.
  if conf.validate_request_body then
    -- ignore file upload body
    local ct = kong_request.get_header(CONTENT_TYPE)
    if string_find(ct, "multipart/form-data;", 1, true) == 1 then
      if not validate_body() then
        kong.log.debug("digest validation failed")
        return false, { status = 401, message = SIGNATURE_NOT_SAME }
      end
    end
    if kong_request.get_header(DIGEST) then
      insert(hmac_params.hmac_headers, DIGEST)
    end
  end

  if not validate_signature(conf, hmac_params) then
    return false, { status = 401, message = SIGNATURE_NOT_SAME }
  end

  -- Retrieve consumer
  local consumer_cache_key, consumer
  consumer_cache_key = kong.db.consumers:cache_key(credential.consumer.id)
  consumer, err      = kong.cache:get(consumer_cache_key, nil,
                                      kong_client.load_consumer,
                                      credential.consumer.id)
  if err then
    return error(err)
  end

  set_consumer(consumer, credential)

  return true
end


local _M = {}


function _M.execute(conf)
  if conf.anonymous and kong_client.get_credential() then
    -- we're already authenticated, and we're configured for using anonymous,
    -- hence we're in a logical OR between auth methods and we're already done.
    return
  end

  local ok, err, continue = do_authentication(conf)
  if not ok then
    if continue and conf.anonymous then
      -- get anonymous user
      local consumer_cache_key = kong.db.consumers:cache_key(conf.anonymous)
      local consumer, err      = kong.cache:get(consumer_cache_key, nil,
                                                kong_client.load_consumer,
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
