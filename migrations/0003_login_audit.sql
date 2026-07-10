-- Run manually via the Cloudflare D1 dashboard Console (same as 0001/0002).
--
-- Records every login attempt for security review: successes AND failures,
-- for regular account logins (headteacher/teacher/student via /api/login)
-- as well as every use of the admin token against /api/admin/* routes
-- (role = 'admin', account_id NULL since admin isn't a row in `schools`).
--
-- Failures matter most here — an unknown username, wrong password, or bad
-- admin token all land in this table, which is what makes brute-force
-- attempts against any account (including yours) visible after the fact.

CREATE TABLE login_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  role TEXT,
  account_id INTEGER REFERENCES schools(id),
  success INTEGER NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX idx_login_audit_created_at ON login_audit(created_at);
CREATE INDEX idx_login_audit_account_id ON login_audit(account_id);
