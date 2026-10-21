-- Run manually via the Cloudflare D1 dashboard Console (same as 0001-0005).
--
-- Backs a two-step, passwordless flow for teachers and students: enter a
-- school email, receive a 6-digit code by email, enter the code to either
-- finish joining (via an invite/class code) or sign back in later.
-- `payload` carries whatever the join step needs to remember between
-- requesting the code and verifying it (e.g. the invite code and display
-- name), as JSON; NULL for a plain returning-login code.
--
-- Headteacher and admin are unaffected — they keep the existing
-- username/password and token-based auth respectively.

CREATE TABLE email_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  code TEXT NOT NULL,
  purpose TEXT NOT NULL,
  payload TEXT,
  expires_at TEXT NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE INDEX idx_email_codes_email_purpose ON email_codes(email, purpose);
