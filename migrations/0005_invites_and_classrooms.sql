-- Run manually via the Cloudflare D1 dashboard Console (same as 0001-0004).
--
-- Supports self-service account creation via invite codes, so a headteacher
-- no longer has to manually create every teacher, and a teacher no longer
-- has to manually create every student:
--   - `invite_code` on a headteacher's own row lets a teacher join that
--     school themselves (POST /api/join/teacher).
--   - `classrooms` lets a teacher split students into more than one class
--     (a teacher may teach several groups). Each classroom has its own
--     `join_code` a student uses to join that specific class
--     (POST /api/join/student).
--   - `email` is captured now (optional) so it's available later for
--     email-based login/notifications, without requiring that work yet.
--
-- Purely additive — existing rows are unaffected. Students created the old
-- way (teacher manually adding them) keep classroom_id NULL, which the UI
-- treats as "unassigned".

CREATE TABLE classrooms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  teacher_id INTEGER NOT NULL REFERENCES schools(id),
  name TEXT NOT NULL,
  join_code TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX idx_classrooms_teacher_id ON classrooms(teacher_id);
CREATE UNIQUE INDEX idx_classrooms_join_code ON classrooms(join_code);

ALTER TABLE schools ADD COLUMN email TEXT;
ALTER TABLE schools ADD COLUMN invite_code TEXT;
ALTER TABLE schools ADD COLUMN classroom_id INTEGER REFERENCES classrooms(id);

CREATE UNIQUE INDEX idx_schools_invite_code ON schools(invite_code) WHERE invite_code IS NOT NULL;
