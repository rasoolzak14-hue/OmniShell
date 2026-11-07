-- Run manually via the Cloudflare D1 dashboard Console (same as 0001-0007).
--
-- Backs the badges and streaks on the learner profile page.
--
--   quiz_correct  - each *different* command a learner has ever answered
--                   correctly, per language. This is what language mastery
--                   (Bronze / Silver / Gold) is counted from. One row per
--                   learner + language + command; answering it correctly
--                   again changes nothing.
--   user_badges   - the badges a learner has earned, and when. Badges are
--                   awarded automatically by the Worker after each quiz.
--
-- Purely additive: two new tables, nothing existing is changed. Streaks need
-- no table of their own; they are worked out from quiz_attempts.
--
-- The Worker is written so that a quiz still saves normally if these tables
-- are missing, but no badges will be awarded until this has been run.

CREATE TABLE quiz_correct (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL REFERENCES schools(id),
  provider TEXT NOT NULL,
  command TEXT NOT NULL,
  first_correct_at TEXT NOT NULL,
  UNIQUE (student_id, provider, command)
);

CREATE INDEX idx_quiz_correct_student ON quiz_correct(student_id, provider);

CREATE TABLE user_badges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES schools(id),
  badge_id TEXT NOT NULL,
  earned_at TEXT NOT NULL,
  UNIQUE (user_id, badge_id)
);

CREATE INDEX idx_user_badges_user ON user_badges(user_id);
