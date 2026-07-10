// Auth gateway in front of the static OmniShell site (web/ assets binding).
// Every request except the small allow-list below requires a valid signed
// session cookie. See wrangler.jsonc for the ASSETS/DB bindings.

const SESSION_COOKIE = "session";
const SESSION_DAYS = 30;
const PBKDF2_ITERATIONS = 100000; // Cloudflare Workers' crypto.subtle caps PBKDF2 at 100,000 iterations
const DUMMY_SALT_HEX = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // used to equalize timing for unknown usernames

// ---------- encoding helpers ----------

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function base64urlEncode(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// Constant-time-ish comparison: always walks the full (max) length rather
// than short-circuiting on the first mismatch or on a length difference.
function constantTimeEqual(a, b) {
  const len = Math.max(a.length, b.length);
  let diff = a.length === b.length ? 0 : 1;
  for (let i = 0; i < len; i++) {
    const x = i < a.length ? a[i] : 0;
    const y = i < b.length ? b[i] : 0;
    diff |= x ^ y;
  }
  return diff === 0;
}

// ---------- crypto helpers ----------

async function pbkdf2Hash(password, saltBytes, iterations = PBKDF2_ITERATIONS) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return new Uint8Array(bits);
}

async function getHmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

// ---------- session cookie ----------

function sessionCookieHeader(value, maxAgeSeconds = SESSION_DAYS * 24 * 60 * 60) {
  return `${SESSION_COOKIE}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAgeSeconds}`;
}

async function signSession({ userId, username, role }, env, days = SESSION_DAYS) {
  const exp = Math.floor(Date.now() / 1000) + days * 24 * 60 * 60;
  const payload = JSON.stringify({ userId, username, role, exp });
  const payloadB64 = base64urlEncode(new TextEncoder().encode(payload));
  const key = await getHmacKey(env.SESSION_SECRET);
  const sigBytes = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64))
  );
  return `${payloadB64}.${base64urlEncode(sigBytes)}`;
}

async function verifySession(cookieValue, env) {
  if (!cookieValue) return null;
  const parts = cookieValue.split(".");
  if (parts.length !== 2) return null;
  const [payloadB64, sigB64] = parts;

  let sigBytes;
  try {
    sigBytes = base64urlDecode(sigB64);
  } catch {
    return null;
  }

  const key = await getHmacKey(env.SESSION_SECRET);
  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    sigBytes,
    new TextEncoder().encode(payloadB64)
  );
  if (!valid) return null;

  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64urlDecode(payloadB64)));
  } catch {
    return null;
  }
  if (!payload || typeof payload.exp !== "number" || typeof payload.username !== "string") {
    return null;
  }
  if (payload.exp < Math.floor(Date.now() / 1000)) return null;

  // Cookies issued before userId/role existed are missing fields the newer
  // handlers require (e.g. teacher_id on student creation). Rather than let
  // those silently misbehave, treat them as invalid so the user is prompted
  // to log in again and pick up a session with the current shape.
  if (typeof payload.userId !== "number") {
    return null;
  }
  if (payload.role !== "headteacher" && payload.role !== "teacher" && payload.role !== "student") {
    payload.role = "teacher";
  }

  return payload;
}

function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  const cookies = {};
  header.split(";").forEach((part) => {
    const idx = part.indexOf("=");
    if (idx === -1) return;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (key) cookies[key] = value;
  });
  return cookies;
}

// ---------- responses ----------

function jsonError(status, message) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

// ---------- route handlers ----------

// Best-effort audit write. Never throws — a logging failure must not block
// an actual login or admin action.
async function logLoginAttempt(env, { request, username, role, accountId, success }) {
  try {
    await env.DB
      .prepare(
        "INSERT INTO login_audit (username, role, account_id, success, ip_address, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
      )
      .bind(
        username,
        role || null,
        accountId || null,
        success ? 1 : 0,
        request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || null,
        request.headers.get("User-Agent") || null,
        new Date().toISOString()
      )
      .run();
  } catch {
    // Swallowed deliberately — see comment above.
  }
}

async function handleLogin(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const username = ((body && body.username) || "").trim();
  const password = (body && body.password) || "";
  if (!username || !password) {
    return jsonError(401, "Invalid username or password");
  }

  const row = await env.DB
    .prepare("SELECT id, username, salt, hash, active, role FROM schools WHERE username = ?")
    .bind(username)
    .first();

  // Always hash, even for an unknown username, so response time doesn't
  // reveal whether the username exists.
  const saltBytes = fromHex(row ? row.salt : DUMMY_SALT_HEX);
  const computedHash = await pbkdf2Hash(password, saltBytes);

  if (!row || !row.active) {
    await logLoginAttempt(env, {
      request,
      username,
      role: row ? row.role : null,
      accountId: row ? row.id : null,
      success: false
    });
    return jsonError(401, "Invalid username or password");
  }

  const storedHash = fromHex(row.hash);
  if (!constantTimeEqual(computedHash, storedHash)) {
    await logLoginAttempt(env, { request, username, role: row.role, accountId: row.id, success: false });
    return jsonError(401, "Invalid username or password");
  }

  await logLoginAttempt(env, { request, username: row.username, role: row.role, accountId: row.id, success: true });

  const cookieValue = await signSession(
    { userId: row.id, username: row.username, role: row.role || "teacher" },
    env
  );
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": sessionCookieHeader(cookieValue)
    }
  });
}

function handleLogout() {
  const headers = new Headers();
  headers.set("Set-Cookie", `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`);
  headers.set("Location", "/login.html");
  return new Response(null, { status: 302, headers });
}

// Shared by every /api/admin/* handler. Fails closed if the secret was never
// configured, and compares in constant time.
function checkAdminToken(request, env) {
  if (!env.ADMIN_TOKEN) return false;
  const authHeader = request.headers.get("Authorization") || "";
  const provided = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  const providedBytes = new TextEncoder().encode(provided);
  const expectedBytes = new TextEncoder().encode(env.ADMIN_TOKEN);
  return Boolean(provided) && constantTimeEqual(providedBytes, expectedBytes);
}

// Same check as checkAdminToken, but also writes an audit row — admin has no
// session/login step of its own, so every token use (success or failure) is
// treated as the equivalent of a login attempt for that account.
async function requireAdmin(request, env) {
  const ok = checkAdminToken(request, env);
  await logLoginAttempt(env, { request, username: "admin", role: "admin", accountId: null, success: ok });
  return ok;
}

async function handleAdminCreateSchool(request, env) {
  // Admin creates headteacher accounts, which in turn create teachers, which
  // create students.
  if (!(await requireAdmin(request, env))) {
    return jsonError(403, "Forbidden");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const username = ((body && body.username) || "").trim();
  const password = (body && body.password) || "";
  const displayName = ((body && body.displayName) || "").trim();
  if (!username || !password) {
    return jsonError(400, "username and password are required");
  }

  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const hashBytes = await pbkdf2Hash(password, saltBytes);

  try {
    await env.DB
      .prepare(
        "INSERT INTO schools (username, salt, hash, display_name, active, role, created_at) VALUES (?, ?, ?, ?, 1, 'headteacher', ?)"
      )
      .bind(username, toHex(saltBytes), toHex(hashBytes), displayName || username, new Date().toISOString())
      .run();
  } catch {
    return jsonError(409, "Username already exists or database error");
  }

  // Deliberately never echoes back the hash/salt.
  return new Response(JSON.stringify({ ok: true, username }), {
    status: 201,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleAdminListHeadteachers(request, env) {
  if (!(await requireAdmin(request, env))) {
    return jsonError(403, "Forbidden");
  }

  const result = await env.DB
    .prepare("SELECT id, username, display_name, active, created_at FROM schools WHERE role = 'headteacher' ORDER BY display_name")
    .all();

  return new Response(JSON.stringify({ rows: result.results || [] }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleAdminListTeachers(request, env) {
  if (!(await requireAdmin(request, env))) {
    return jsonError(403, "Forbidden");
  }

  const url = new URL(request.url);
  const headteacherId = Number(url.searchParams.get("headteacherId"));
  if (!Number.isInteger(headteacherId)) {
    return jsonError(400, "headteacherId is required");
  }

  const result = await env.DB
    .prepare("SELECT id, username, display_name, active FROM schools WHERE role = 'teacher' AND teacher_id = ? ORDER BY display_name")
    .bind(headteacherId)
    .all();

  return new Response(JSON.stringify({ rows: result.results || [] }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleAdminListStudents(request, env) {
  if (!(await requireAdmin(request, env))) {
    return jsonError(403, "Forbidden");
  }

  const url = new URL(request.url);
  const teacherId = Number(url.searchParams.get("teacherId"));
  if (!Number.isInteger(teacherId)) {
    return jsonError(400, "teacherId is required");
  }

  const result = await env.DB
    .prepare("SELECT id, username, display_name, active FROM schools WHERE role = 'student' AND teacher_id = ? ORDER BY display_name")
    .bind(teacherId)
    .all();

  return new Response(JSON.stringify({ rows: result.results || [] }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleAdminResetPassword(request, env) {
  if (!(await requireAdmin(request, env))) {
    return jsonError(403, "Forbidden");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const accountId = Number(body && body.accountId);
  const newPassword = (body && body.newPassword) || "";
  if (!Number.isInteger(accountId) || !newPassword) {
    return jsonError(400, "accountId and newPassword are required");
  }

  const account = await env.DB.prepare("SELECT id FROM schools WHERE id = ?").bind(accountId).first();
  if (!account) {
    return jsonError(404, "Account not found");
  }

  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const hashBytes = await pbkdf2Hash(newPassword, saltBytes);

  await env.DB
    .prepare("UPDATE schools SET salt = ?, hash = ? WHERE id = ?")
    .bind(toHex(saltBytes), toHex(hashBytes), accountId)
    .run();

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleAdminRename(request, env) {
  if (!(await requireAdmin(request, env))) {
    return jsonError(403, "Forbidden");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const accountId = Number(body && body.accountId);
  const displayName = ((body && body.displayName) || "").trim();
  if (!Number.isInteger(accountId) || !displayName) {
    return jsonError(400, "accountId and displayName are required");
  }

  const account = await env.DB.prepare("SELECT id FROM schools WHERE id = ?").bind(accountId).first();
  if (!account) {
    return jsonError(404, "Account not found");
  }

  await env.DB.prepare("UPDATE schools SET display_name = ? WHERE id = ?").bind(displayName, accountId).run();

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleAdminSetActive(request, env) {
  if (!(await requireAdmin(request, env))) {
    return jsonError(403, "Forbidden");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const accountId = Number(body && body.accountId);
  if (!Number.isInteger(accountId) || typeof (body && body.active) !== "boolean") {
    return jsonError(400, "accountId and active are required");
  }

  const account = await env.DB.prepare("SELECT id FROM schools WHERE id = ?").bind(accountId).first();
  if (!account) {
    return jsonError(404, "Account not found");
  }

  await env.DB.prepare("UPDATE schools SET active = ? WHERE id = ?").bind(body.active ? 1 : 0, accountId).run();

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleAdminDeleteAccount(request, env) {
  if (!(await requireAdmin(request, env))) {
    return jsonError(403, "Forbidden");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const accountId = Number(body && body.accountId);
  if (!Number.isInteger(accountId)) {
    return jsonError(400, "accountId is required");
  }

  const account = await env.DB.prepare("SELECT id, role FROM schools WHERE id = ?").bind(accountId).first();
  if (!account) {
    return jsonError(404, "Account not found");
  }

  // Cascade deletion depth depends on the account's own role, so every
  // descendant and their quiz history is cleaned up, nothing orphaned.
  if (account.role === "headteacher") {
    await env.DB
      .prepare(
        `DELETE FROM quiz_attempts WHERE student_id IN (
           SELECT id FROM schools WHERE role = 'student' AND teacher_id IN (
             SELECT id FROM schools WHERE role = 'teacher' AND teacher_id = ?
           )
         )`
      )
      .bind(accountId)
      .run();
    await env.DB
      .prepare(
        `DELETE FROM schools WHERE role = 'student' AND teacher_id IN (
           SELECT id FROM schools WHERE role = 'teacher' AND teacher_id = ?
         )`
      )
      .bind(accountId)
      .run();
    await env.DB.prepare("DELETE FROM schools WHERE role = 'teacher' AND teacher_id = ?").bind(accountId).run();
  } else if (account.role === "teacher") {
    await env.DB
      .prepare("DELETE FROM quiz_attempts WHERE student_id IN (SELECT id FROM schools WHERE teacher_id = ? AND role = 'student')")
      .bind(accountId)
      .run();
    await env.DB.prepare("DELETE FROM schools WHERE teacher_id = ? AND role = 'student'").bind(accountId).run();
  } else {
    await env.DB.prepare("DELETE FROM quiz_attempts WHERE student_id = ?").bind(accountId).run();
  }

  await env.DB.prepare("DELETE FROM schools WHERE id = ?").bind(accountId).run();

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleAdminLoginAudit(request, env) {
  if (!(await requireAdmin(request, env))) {
    return jsonError(403, "Forbidden");
  }

  const result = await env.DB
    .prepare(
      "SELECT username, role, account_id, success, ip_address, user_agent, created_at FROM login_audit ORDER BY created_at DESC LIMIT 200"
    )
    .all();

  return new Response(JSON.stringify({ rows: result.results || [] }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleTeacherCreateStudent(request, env, session) {
  if (session.role !== "teacher") {
    return jsonError(403, "Forbidden");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const username = ((body && body.username) || "").trim();
  const password = (body && body.password) || "";
  const displayName = ((body && body.displayName) || "").trim();
  if (!username || !password) {
    return jsonError(400, "username and password are required");
  }

  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const hashBytes = await pbkdf2Hash(password, saltBytes);

  try {
    await env.DB
      .prepare(
        "INSERT INTO schools (username, salt, hash, display_name, active, role, teacher_id, created_at) VALUES (?, ?, ?, ?, 1, 'student', ?, ?)"
      )
      .bind(
        username,
        toHex(saltBytes),
        toHex(hashBytes),
        displayName || username,
        session.userId,
        new Date().toISOString()
      )
      .run();
  } catch {
    return jsonError(409, "Username already exists or database error");
  }

  return new Response(JSON.stringify({ ok: true, username }), {
    status: 201,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleTeacherDeleteStudent(request, env, session) {
  if (session.role !== "teacher") {
    return jsonError(403, "Forbidden");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const studentId = Number(body && body.studentId);
  if (!Number.isInteger(studentId)) {
    return jsonError(400, "studentId is required");
  }

  // Only allow deleting a student that actually belongs to the calling
  // teacher — never trust studentId alone.
  const student = await env.DB
    .prepare("SELECT id FROM schools WHERE id = ? AND teacher_id = ? AND role = 'student'")
    .bind(studentId, session.userId)
    .first();

  if (!student) {
    return jsonError(404, "Student not found");
  }

  await env.DB.prepare("DELETE FROM quiz_attempts WHERE student_id = ?").bind(studentId).run();
  await env.DB.prepare("DELETE FROM schools WHERE id = ?").bind(studentId).run();

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleTeacherResetStudentPassword(request, env, session) {
  if (session.role !== "teacher") {
    return jsonError(403, "Forbidden");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const studentId = Number(body && body.studentId);
  const newPassword = (body && body.newPassword) || "";
  if (!Number.isInteger(studentId) || !newPassword) {
    return jsonError(400, "studentId and newPassword are required");
  }

  // Only allow resetting a password for a student that actually belongs to
  // the calling teacher — never trust studentId alone.
  const student = await env.DB
    .prepare("SELECT id FROM schools WHERE id = ? AND teacher_id = ? AND role = 'student'")
    .bind(studentId, session.userId)
    .first();

  if (!student) {
    return jsonError(404, "Student not found");
  }

  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const hashBytes = await pbkdf2Hash(newPassword, saltBytes);

  await env.DB
    .prepare("UPDATE schools SET salt = ?, hash = ? WHERE id = ?")
    .bind(toHex(saltBytes), toHex(hashBytes), studentId)
    .run();

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleTeacherProgress(env, session) {
  if (session.role !== "teacher") {
    return jsonError(403, "Forbidden");
  }

  const result = await env.DB
    .prepare(
      `SELECT s.id AS student_id, s.username, s.display_name,
              qa.provider, qa.score, qa.total, qa.completed_at
       FROM schools s
       LEFT JOIN quiz_attempts qa ON qa.student_id = s.id
       WHERE s.teacher_id = ?
       ORDER BY qa.completed_at DESC
       LIMIT 500`
    )
    .bind(session.userId)
    .all();

  return new Response(JSON.stringify({ rows: result.results || [] }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleHeadteacherCreateTeacher(request, env, session) {
  if (session.role !== "headteacher") {
    return jsonError(403, "Forbidden");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const username = ((body && body.username) || "").trim();
  const password = (body && body.password) || "";
  const displayName = ((body && body.displayName) || "").trim();
  if (!username || !password) {
    return jsonError(400, "username and password are required");
  }

  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const hashBytes = await pbkdf2Hash(password, saltBytes);

  try {
    await env.DB
      .prepare(
        "INSERT INTO schools (username, salt, hash, display_name, active, role, teacher_id, created_at) VALUES (?, ?, ?, ?, 1, 'teacher', ?, ?)"
      )
      .bind(
        username,
        toHex(saltBytes),
        toHex(hashBytes),
        displayName || username,
        session.userId,
        new Date().toISOString()
      )
      .run();
  } catch {
    return jsonError(409, "Username already exists or database error");
  }

  return new Response(JSON.stringify({ ok: true, username }), {
    status: 201,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleHeadteacherTeachers(env, session) {
  if (session.role !== "headteacher") {
    return jsonError(403, "Forbidden");
  }

  const result = await env.DB
    .prepare(
      "SELECT id, username, display_name FROM schools WHERE teacher_id = ? AND role = 'teacher' ORDER BY display_name"
    )
    .bind(session.userId)
    .all();

  return new Response(JSON.stringify({ rows: result.results || [] }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleHeadteacherResetTeacherPassword(request, env, session) {
  if (session.role !== "headteacher") {
    return jsonError(403, "Forbidden");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const teacherId = Number(body && body.teacherId);
  const newPassword = (body && body.newPassword) || "";
  if (!Number.isInteger(teacherId) || !newPassword) {
    return jsonError(400, "teacherId and newPassword are required");
  }

  // Only allow resetting a password for a teacher that actually belongs to
  // the calling headteacher — never trust teacherId alone.
  const teacher = await env.DB
    .prepare("SELECT id FROM schools WHERE id = ? AND teacher_id = ? AND role = 'teacher'")
    .bind(teacherId, session.userId)
    .first();

  if (!teacher) {
    return jsonError(404, "Teacher not found");
  }

  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const hashBytes = await pbkdf2Hash(newPassword, saltBytes);

  await env.DB
    .prepare("UPDATE schools SET salt = ?, hash = ? WHERE id = ?")
    .bind(toHex(saltBytes), toHex(hashBytes), teacherId)
    .run();

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleHeadteacherStudents(request, env, session) {
  if (session.role !== "headteacher") {
    return jsonError(403, "Forbidden");
  }

  const url = new URL(request.url);
  const teacherId = Number(url.searchParams.get("teacherId"));
  if (!Number.isInteger(teacherId)) {
    return jsonError(400, "teacherId is required");
  }

  // Only allow browsing students of a teacher that actually belongs to the
  // calling headteacher — never trust teacherId alone.
  const teacher = await env.DB
    .prepare("SELECT id FROM schools WHERE id = ? AND teacher_id = ? AND role = 'teacher'")
    .bind(teacherId, session.userId)
    .first();

  if (!teacher) {
    return jsonError(404, "Teacher not found");
  }

  const result = await env.DB
    .prepare("SELECT id, username, display_name, active FROM schools WHERE role = 'student' AND teacher_id = ? ORDER BY display_name")
    .bind(teacherId)
    .all();

  return new Response(JSON.stringify({ rows: result.results || [] }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleHeadteacherDeleteTeacher(request, env, session) {
  if (session.role !== "headteacher") {
    return jsonError(403, "Forbidden");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const teacherId = Number(body && body.teacherId);
  if (!Number.isInteger(teacherId)) {
    return jsonError(400, "teacherId is required");
  }

  const teacher = await env.DB
    .prepare("SELECT id FROM schools WHERE id = ? AND teacher_id = ? AND role = 'teacher'")
    .bind(teacherId, session.userId)
    .first();

  if (!teacher) {
    return jsonError(404, "Teacher not found");
  }

  // Deleting a teacher cascades to their students and those students' quiz
  // attempts, so nothing orphaned is left behind.
  await env.DB
    .prepare(
      "DELETE FROM quiz_attempts WHERE student_id IN (SELECT id FROM schools WHERE teacher_id = ? AND role = 'student')"
    )
    .bind(teacherId)
    .run();
  await env.DB.prepare("DELETE FROM schools WHERE teacher_id = ? AND role = 'student'").bind(teacherId).run();
  await env.DB.prepare("DELETE FROM schools WHERE id = ?").bind(teacherId).run();

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleQuizAttempt(request, env, session) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const provider = ((body && body.provider) || "").trim();
  const score = Number(body && body.score);
  const total = Number(body && body.total);

  const isValidCount = (n) => Number.isInteger(n) && n >= 0;
  if (!provider || !isValidCount(score) || !isValidCount(total) || score > total) {
    return jsonError(400, "Invalid quiz result");
  }

  await env.DB
    .prepare(
      "INSERT INTO quiz_attempts (student_id, provider, score, total, completed_at) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(session.userId, provider, score, total, new Date().toISOString())
    .run();

  return new Response(JSON.stringify({ ok: true }), {
    status: 201,
    headers: { "Content-Type": "application/json" }
  });
}

// ---------- main fetch handler ----------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method;

    // Allow-list: no session required.
    if (pathname === "/login.html" && method === "GET") {
      return env.ASSETS.fetch(request);
    }
    if (pathname === "/admin.html" && method === "GET") {
      return env.ASSETS.fetch(request);
    }
    if (pathname === "/api/login" && method === "POST") {
      return handleLogin(request, env);
    }
    if (pathname === "/api/logout" && (method === "GET" || method === "POST")) {
      return handleLogout();
    }
    if (pathname === "/api/admin/schools" && method === "POST") {
      return handleAdminCreateSchool(request, env);
    }
    if (pathname === "/api/admin/headteachers" && method === "GET") {
      return handleAdminListHeadteachers(request, env);
    }
    if (pathname === "/api/admin/teachers" && method === "GET") {
      return handleAdminListTeachers(request, env);
    }
    if (pathname === "/api/admin/students" && method === "GET") {
      return handleAdminListStudents(request, env);
    }
    if (pathname === "/api/admin/accounts/reset-password" && method === "POST") {
      return handleAdminResetPassword(request, env);
    }
    if (pathname === "/api/admin/accounts/rename" && method === "POST") {
      return handleAdminRename(request, env);
    }
    if (pathname === "/api/admin/accounts/set-active" && method === "POST") {
      return handleAdminSetActive(request, env);
    }
    if (pathname === "/api/admin/accounts/delete" && method === "POST") {
      return handleAdminDeleteAccount(request, env);
    }
    if (pathname === "/api/admin/login-audit" && method === "GET") {
      return handleAdminLoginAudit(request, env);
    }

    // Everything else requires a valid session.
    const cookies = parseCookies(request);
    const session = await verifySession(cookies[SESSION_COOKIE], env);

    if (!session) {
      const acceptsHtml = (request.headers.get("Accept") || "").includes("text/html");
      if (acceptsHtml) {
        return Response.redirect(`${url.origin}/login.html`, 302);
      }
      return jsonError(401, "unauthorized");
    }

    if (pathname === "/api/me" && method === "GET") {
      return new Response(JSON.stringify({ username: session.username, role: session.role }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }
    if (pathname === "/api/teacher/students" && method === "POST") {
      return handleTeacherCreateStudent(request, env, session);
    }
    if (pathname === "/api/teacher/students/reset-password" && method === "POST") {
      return handleTeacherResetStudentPassword(request, env, session);
    }
    if (pathname === "/api/teacher/students/delete" && method === "POST") {
      return handleTeacherDeleteStudent(request, env, session);
    }
    if (pathname === "/api/teacher/progress" && method === "GET") {
      return handleTeacherProgress(env, session);
    }
    if (pathname === "/api/headteacher/teachers" && method === "POST") {
      return handleHeadteacherCreateTeacher(request, env, session);
    }
    if (pathname === "/api/headteacher/teachers" && method === "GET") {
      return handleHeadteacherTeachers(env, session);
    }
    if (pathname === "/api/headteacher/teachers/reset-password" && method === "POST") {
      return handleHeadteacherResetTeacherPassword(request, env, session);
    }
    if (pathname === "/api/headteacher/teachers/delete" && method === "POST") {
      return handleHeadteacherDeleteTeacher(request, env, session);
    }
    if (pathname === "/api/headteacher/students" && method === "GET") {
      return handleHeadteacherStudents(request, env, session);
    }
    if (pathname === "/api/quiz/attempts" && method === "POST") {
      return handleQuizAttempt(request, env, session);
    }

    // With html_handling set to "none" (needed to stop /login.html <-> /login
    // redirect loops), Cloudflare no longer auto-resolves "/" to index.html,
    // so we do it ourselves rather than relying on assets-layer behavior.
    let assetRequest = request;
    if (pathname === "/") {
      const indexUrl = new URL(request.url);
      indexUrl.pathname = "/index.html";
      assetRequest = new Request(indexUrl.toString(), request);
    }

    const assetResponse = await env.ASSETS.fetch(assetRequest);
    const headers = new Headers(assetResponse.headers);
    headers.set("Cache-Control", "private, no-store");
    headers.append("Set-Cookie", sessionCookieHeader(await signSession(session, env)));

    return new Response(assetResponse.body, {
      status: assetResponse.status,
      statusText: assetResponse.statusText,
      headers
    });
  }
};
