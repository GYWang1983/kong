return {
  postgres = {
    up = [[
      DO $$
      BEGIN
        ALTER TABLE IF EXISTS ONLY "basicauth_credentials"
          ADD COLUMN "expire_at"     TIMESTAMP(0) WITH TIME ZONE DEFAULT TO_TIMESTAMP(0),
          ADD COLUMN "retry_limits"  JSONB,
          ADD COLUMN "status"        TEXT[];
      EXCEPTION WHEN DUPLICATE_COLUMN THEN
        -- Do nothing, accept existing state
      END$$;

    ]],
  },
  cassandra = {
    up = [[
      ALTER TABLE basicauth_credentials ADD expire_at timestamp;
      ALTER TABLE basicauth_credentials ADD retry_limits text;
      ALTER TABLE basicauth_credentials ADD status set<text>;
    ]],
  }
}
