-- Run manually via the Cloudflare D1 dashboard Console (no local wrangler CLI
-- available). This file is a git-tracked record of what has been applied to
-- the live omnishell-auth database, not an auto-applied migration.
--
-- Purely additive: adds columns/tables only, never renames or drops anything,
-- so the currently-deployed production Worker keeps working unmodified while
-- this migration is live and the new code is still being developed/tested.

ALTER TABLE schools ADD COLUMN role TEXT NOT NULL DEFAULT 'teacher';
ALTER TABLE schools ADD COLUMN teacher_id INTEGER REFERENCES schools(id);

CREATE TABLE quiz_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL REFERENCES schools(id),
  provider TEXT NOT NULL,
  score INTEGER NOT NULL,
  total INTEGER NOT NULL,
  completed_at TEXT NOT NULL
);

CREATE INDEX idx_quiz_attempts_student ON quiz_attempts(student_id);
CREATE INDEX idx_schools_teacher_id ON schools(teacher_id);
