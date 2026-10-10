# PMServers device auth

This service gives `pms login` a device code flow. It uses Supabase Postgres and Auth.

Required environment: `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, `DATABASE_URL`, and `PUBLIC_URL`.

Apply migration `0010_device_logins.sql` from `pmservers-api/supabase/migrations` to the local Supabase project before starting this service. Run with `cargo run`. The service listens on port 8080 and exposes `/livez`.

Do not use the production Supabase project for local development. Keep the service role key in the pod secret only.

## GitHub email

The CLI needs a fresh Supabase session. The service creates that session from the approved user's email. If GitHub does not provide an email address, the service returns `email_required` before claiming the device code, so the user can make an email address public in GitHub settings and retry. The test suite covers the missing-email response with a mock user. A live private-email GitHub account has not been tested.

Five wrong user codes from one IP return `wrong_code_limit` and block code entry from that IP for 10 minutes. This applies even when a guessed code has no database row.
