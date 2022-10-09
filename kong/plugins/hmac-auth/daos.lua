local tablex   = require "pl.tablex"
local typedefs = require "kong.db.schema.typedefs"


return {
  {
    primary_key = { "id" },
    name = "hmacauth_credentials",
    endpoint_key = "username",
    cache_key = { "username" },
    workspaceable = true,

    admin_api_name = "hmac-auths",
    admin_api_nested_name = "hmac-auth",
    fields = {
      { id = typedefs.uuid },
      { created_at = typedefs.auto_timestamp_s },
      { expire_at  = { type = "integer", timestamp = true, default = 0 } },
      { consumer = { type = "foreign", reference = "consumers", required = true, on_delete = "cascade", }, },
      { username = { type = "string", required = true, unique = true }, },
      { secret = { type = "string", auto = true }, },
      { status = { type = "set", elements = { type = "string" } }, },
      { tags   = typedefs.tags },
    },
    transformations = {
      {
        input = { "status" },
        on_read = function(status)
          return { status = tablex.makeset(status) }
        end,
      },
    },
  },
}
