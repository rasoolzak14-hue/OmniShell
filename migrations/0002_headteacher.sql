-- Run manually via the Cloudflare D1 dashboard Console (same as 0001).
--
-- Introduces a 4th role, "headteacher", sitting between admin and teacher:
--   Admin (token-based, not a row in this table) creates Headteachers
--   Headteacher creates Teachers
--   Teacher creates Students
--
-- No schema change needed: `role` is free-text TEXT with no CHECK constraint,
-- and `teacher_id` (already nullable, already indexed) is reused generically
-- as "parent account id" for any role, not just students-under-a-teacher.
--
-- Data migration: every existing role='teacher' account was created directly
-- by admin (the only account-creation path that existed until now), so any
-- teacher row with no parent becomes a headteacher.

UPDATE schools SET role = 'headteacher' WHERE role = 'teacher' AND teacher_id IS NULL;
