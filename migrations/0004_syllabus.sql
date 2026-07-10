-- Run manually via the Cloudflare D1 dashboard Console (same as 0001/0002/0003).
--
-- Lets a headteacher pick which GCSE Computer Science exam board their
-- school follows. Stored on the headteacher's own row in `schools`; nullable
-- because a headteacher may not have chosen one yet.

ALTER TABLE schools ADD COLUMN syllabus TEXT;
