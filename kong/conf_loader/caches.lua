local pl_stringx = require "pl.stringx"
local nkeys      = require("table.nkeys")
local new_tab    = require("table.new")

local ngx      = ngx
local re_match = ngx.re.match
local tonumber = tonumber
local insert   = table.insert
local fmt      = string.format

local parser = {}

local usage = "must be of form: <name1> [size=<cache_size>[:<miss_cache_size>]] [ttl=<ttl>[:<neg_ttl>[:<resurrect_ttl>]]] [, <name2>...] "

-- This meta table will prevent the parsed table to be passed on in the
-- intermediate Kong config file in the prefix directory.
-- We thus avoid 'table: 0x41c3fa58' from appearing into the prefix
-- hidden configuration file.
-- This is only to be applied to values that are injected into the
-- configuration object, and not configuration properties themselves,
-- otherwise we would prevent such properties from being specifiable
-- via environment variables.
local _nop_tostring_mt = {
  __tostring = function() return "" end,
}

local function parse_size(size_conf)
  local m = re_match(size_conf, [[^size=(?<size>\d+[km]{1})(?::(?<miss>\g<size>))?$]], "jos")
  if not m then
    return nil, nil, fmt("invalid cache size '%s', unit of size must be 'm' or 'k'", size_conf)
  end
  return m['size'], m['miss']
end

local function parse_ttl(ttl_conf)
  local m = re_match(ttl_conf, [[^ttl=(?<ttl>\d+)(?::(?<neg>\d+)(?::(?<re>\d+))?)?$]], "jos")
  if not m then
    return nil, nil, nil, fmt("invalid ttl '%s'", ttl_conf)
  end
  return m['ttl'], m['neg'] or m['ttl'], m['re']
end

local function parse_cache(cache_conf)
  local name, conf1, conf2 = pl_stringx.splitv(cache_conf)

  if not re_match(name, "^[a-z][a-z0-9_]*$", "jos") then
    return nil, fmt("bad cache name '%s', allowed characters are a-z, numeric, '_' and start with a-z", name)
  end

  local size, miss_size, ttl, neg_ttl, resurrect_ttl

  for _, flag in ipairs({ conf1, conf2 }) do
    if flag then
      local err
      if pl_stringx.startswith(flag, 'size=') then
        size, miss_size, err = parse_size(flag)
      elseif pl_stringx.startswith(flag, 'ttl=') then
        ttl, neg_ttl, resurrect_ttl, err = parse_ttl(flag)
      else
        err = "unknown flags: " .. flag
      end
      if err then
        return nil, err
      end
    end
  end

  return {
    name = name,
    size = size or '16m',
    miss_size = miss_size or '4m',
    ttl = ttl and tonumber(ttl) or 0,
    neg_ttl = neg_ttl and tonumber(neg_ttl) or 0,
    resurrect_ttl = resurrect_ttl and tonumber(resurrect_ttl) or 0
  }
end

-- Parse a set of "additional_caches" flags from the configuration.
--   format:  {name} size={size|default 16m}:{miss_size|default 4m} ttl={ttl|default 0}:{neg_ttl|default 0}:{resurrect_ttl|default 0}
-- @tparam table conf The main configuration table
-- @tparam table listener_config The listener configuration to parse.
function parser.parse(conf)
  local cache_conf_all = conf['additional_caches']
  if cache_conf_all then
    local cnt = nkeys(cache_conf_all)
    if cnt == 0 then
      return false, usage
    end

    local parsed = new_tab(0, cnt)
    local caches = setmetatable(new_tab(cnt, 0), _nop_tostring_mt)
    conf['additional_cache_directives'] = caches

    for i = 1, cnt do
      local cache_conf, err = parse_cache(cache_conf_all[i])
      if err then
        return false, usage .. err
      end
      if parsed[cache_conf.name] then
        return false, "duplicated additional cache name: " .. cache_conf.name
      end
      parsed[cache_conf.name] = true
      insert(caches, cache_conf)
    end
  else
    conf['additional_cache_directives'] = {}
  end
  return true
end

return parser
