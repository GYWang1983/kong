local typedefs = require "kong.db.schema.typedefs"


local ALGORITHMS = {
  "hmac-sha1",
  "hmac-sha256",
  "hmac-sha384",
  "hmac-sha512",
}

local SIGNATURE_VERSIONS = {
  "v1",
  "v2",
}

return {
  name = "hmac-auth",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { hide_credentials = { type = "boolean", required = true, default = false }, },
          { clock_skew = { type = "number", default = 300, gt = 0 }, },
          { anonymous = { type = "string" }, },
          { validate_request_body = { type = "boolean", required = true, default = false }, },
          { auth_fields_in_header = { type = "boolean", default = true }, },
          { auth_fields_in_query = { type = "boolean", default = false }, },
          { auth_fields = {
            type = "record",
            fields = {
              { username  = { type = "string", default = "username" } },
              { algorithm = { type = "string", default = "algorithm" } },
              { hmac_headers = { type = "string", default = "headers" } },
              { nonce     = { type = "string", default = "nonce" } },
              { signature = { type = "string", default = "signature" } },
              { signature_version = { type = "string", default = "signature_version" } },
            }
          }, },
          { enforce_headers = {
              type = "array",
              elements = { type = "string" },
              default = {},
          }, },
          { algorithms = {
              type = "array",
              elements = { type = "string", one_of = ALGORITHMS },
              default = ALGORITHMS,
          }, },
          { signature_versions = {
            type = "array",
            elements = { type = "string", one_of = SIGNATURE_VERSIONS },
            default = SIGNATURE_VERSIONS,
          }, },
        },
      },
    },
  },
}
