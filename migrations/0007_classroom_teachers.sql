-- Run manually via the Cloudflare D1 dashboard Console (same as 0001-0006).
--
-- Supports co-teaching: a classroom is still created and "owned" by one
-- teacher (classrooms.teacher_id, unchanged), but the owner can now grant
-- other teachers in the same school shared access — e.g. a TA or a
-- colleague covering lessons — without transferring ownership. Access is
-- purely additive: removing a row here just revokes that teacher's access,
-- it never touches the classroom or its students.

CREATE TABLE classroom_teachers (
  classroom_id INTEGER NOT NULL REFERENCES classrooms(id),
  teacher_id INTEGER NOT NULL REFERENCES schools(id),
  added_at TEXT NOT NULL,
  PRIMARY KEY (classroom_id, teacher_id)
);

CREATE INDEX idx_classroom_teachers_teacher ON classroom_teachers(teacher_id);
