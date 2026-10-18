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

// Excludes visually-confusable characters (0/O, 1/I/L) since these codes get
// read off a screen and typed in by hand.
const INVITE_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

function generateInviteCode(length = 8) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let code = "";
  for (let i = 0; i < length; i++) {
    code += INVITE_CODE_ALPHABET[bytes[i] % INVITE_CODE_ALPHABET.length];
  }
  return code;
}

// Plain digits — this one gets typed in off an email, not read off a screen
// alongside a link, so it matches the familiar "6-digit code" pattern.
function generateNumericCode(length = 6) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let code = "";
  for (let i = 0; i < length; i++) {
    code += (bytes[i] % 10).toString();
  }
  return code;
}

// Long and random rather than typed — this rides in a URL, not read off a
// screen and copied by hand, so it doesn't need the visually-distinct
// alphabet the other code types use.
function generateMagicToken() {
  return toHex(crypto.getRandomValues(new Uint8Array(24)));
}

const EMAIL_CODE_TTL_MINUTES = 10;
const EMAIL_CODE_RESEND_COOLDOWN_SECONDS = 30;
const EMAIL_CODE_MAX_PER_HOUR = 6;
const TEACHER_INVITE_TTL_MINUTES = 7 * 24 * 60;

// Best-effort email send via Resend (https://resend.com). Returns true/false
// rather than throwing, so a misconfigured or not-yet-set-up provider never
// breaks the request that triggered it — the code still gets created and
// stored, it just won't reach an inbox until RESEND_API_KEY is set.
async function sendEmail(env, { to, subject, text }) {
  if (!env.RESEND_API_KEY || !env.EMAIL_FROM) {
    console.error(`sendEmail: no email provider configured — would have sent to ${to}: ${subject}`);
    return false;
  }

  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ from: env.EMAIL_FROM, to: [to], subject, text })
    });
    if (!res.ok) {
      console.error(`sendEmail: provider returned ${res.status} for ${to}`);
      return false;
    }
    return true;
  } catch (e) {
    console.error(`sendEmail: request failed for ${to}: ${e.message}`);
    return false;
  }
}

// Shared by every request-code / invite endpoint: creates and emails a fresh
// code, throttling repeat requests for the same email+purpose so "Resend"
// can't be used to spam someone's inbox. Defaults to a short numeric OTP;
// pass `code`/`ttlMinutes` to issue a long-lived magic-link token instead.
async function issueEmailCode(env, { email, purpose, payload, subject, bodyText, code, ttlMinutes }) {
  const recent = await env.DB
    .prepare("SELECT created_at FROM email_codes WHERE email = ? AND purpose = ? ORDER BY created_at DESC LIMIT 1")
    .bind(email, purpose)
    .first();
  if (recent) {
    const ageSeconds = (Date.now() - new Date(recent.created_at).getTime()) / 1000;
    if (ageSeconds < EMAIL_CODE_RESEND_COOLDOWN_SECONDS) {
      return { ok: false, error: "Please wait before requesting another code." };
    }
  }

  // Hourly cap per address, across every purpose. Open signup means anyone
  // can type any email in, so this stops the form being used to flood an
  // inbox. (Pair with a Cloudflare Rate Limiting rule for per-IP limits.)
  const hourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const lastHour = await env.DB
    .prepare("SELECT COUNT(*) AS n FROM email_codes WHERE email = ? AND created_at > ?")
    .bind(email, hourAgo)
    .first();
  if (lastHour && lastHour.n >= EMAIL_CODE_MAX_PER_HOUR) {
    return { ok: false, error: "Too many codes requested. Please try again later." };
  }

  const finalCode = code || generateNumericCode();
  const expiresAt = new Date(Date.now() + (ttlMinutes || EMAIL_CODE_TTL_MINUTES) * 60 * 1000).toISOString();

  await env.DB
    .prepare("INSERT INTO email_codes (email, code, purpose, payload, expires_at, consumed, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)")
    .bind(email, finalCode, purpose, payload ? JSON.stringify(payload) : null, expiresAt, new Date().toISOString())
    .run();

  await sendEmail(env, { to: email, subject, text: bodyText(finalCode) });

  return { ok: true };
}

// Looks up and consumes a matching, unexpired code. Returns the parsed
// payload (or null) on success, or null if the code didn't match.
async function consumeEmailCode(env, { email, purpose, code }) {
  const row = await env.DB
    .prepare(
      "SELECT id, payload, expires_at FROM email_codes WHERE email = ? AND purpose = ? AND code = ? AND consumed = 0 ORDER BY created_at DESC LIMIT 1"
    )
    .bind(email, purpose, code)
    .first();

  if (!row || new Date(row.expires_at).getTime() < Date.now()) {
    return { found: false };
  }

  await env.DB.prepare("UPDATE email_codes SET consumed = 1 WHERE id = ?").bind(row.id).run();

  return { found: true, payload: row.payload ? JSON.parse(row.payload) : null };
}

// Magic-link variant: the token itself (long and random) is the only thing
// the client has — it doesn't know the email in advance — so lookup is by
// purpose+code alone rather than email+purpose+code.
async function lookupEmailCode(env, { purpose, code }) {
  const row = await env.DB
    .prepare(
      "SELECT email, payload, expires_at FROM email_codes WHERE purpose = ? AND code = ? AND consumed = 0 ORDER BY created_at DESC LIMIT 1"
    )
    .bind(purpose, code)
    .first();
  if (!row || new Date(row.expires_at).getTime() < Date.now()) return null;
  return { email: row.email, payload: row.payload ? JSON.parse(row.payload) : null };
}

async function consumeEmailCodeByToken(env, { purpose, code }) {
  const row = await env.DB
    .prepare(
      "SELECT id, email, payload, expires_at FROM email_codes WHERE purpose = ? AND code = ? AND consumed = 0 ORDER BY created_at DESC LIMIT 1"
    )
    .bind(purpose, code)
    .first();

  if (!row || new Date(row.expires_at).getTime() < Date.now()) {
    return { found: false };
  }

  await env.DB.prepare("UPDATE email_codes SET consumed = 1 WHERE id = ?").bind(row.id).run();

  return { found: true, email: row.email, payload: row.payload ? JSON.parse(row.payload) : null };
}

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
  if (
    payload.role !== "headteacher" &&
    payload.role !== "teacher" &&
    payload.role !== "student" &&
    payload.role !== "independent"
  ) {
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
  } catch (e) {
    // Swallowed deliberately — see comment above. Logged so a missing
    // login_audit table (e.g. migration 0003 not yet run) is visible in
    // `wrangler tail` instead of failing completely silently.
    console.error("logLoginAttempt failed:", e.message);
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

// Returning-login counterpart to the join flow, for teacher/student accounts
// that have no usable password (created via email+code in the first place).
// Always reports success regardless of whether the email matches an
// account, so this endpoint can't be used to enumerate registered emails.
async function handleLoginRequestCode(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const email = ((body && body.email) || "").trim().toLowerCase();
  if (!email) {
    return jsonError(400, "email is required");
  }

  const account = await env.DB
    .prepare("SELECT id FROM schools WHERE email = ? AND active = 1 AND role IN ('teacher', 'student', 'independent')")
    .bind(email)
    .first();

  if (account) {
    await issueEmailCode(env, {
      email,
      purpose: "login",
      payload: null,
      subject: "Your OmniShell sign-in code",
      bodyText: (verificationCode) =>
        `Your OmniShell sign-in code is ${verificationCode}. It expires in ${EMAIL_CODE_TTL_MINUTES} minutes.`
    });
  }

  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "Content-Type": "application/json" } });
}

async function handleLoginVerifyCode(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const email = ((body && body.email) || "").trim().toLowerCase();
  const code = ((body && body.code) || "").trim();
  if (!email || !code) {
    return jsonError(400, "email and code are required");
  }

  const result = await consumeEmailCode(env, { email, purpose: "login", code });
  if (!result.found) {
    await logLoginAttempt(env, { request, username: email, role: null, accountId: null, success: false });
    return jsonError(400, "That code is invalid or has expired.");
  }

  const account = await env.DB
    .prepare("SELECT id, username, role, active FROM schools WHERE email = ? AND role IN ('teacher', 'student', 'independent')")
    .bind(email)
    .first();

  if (!account || !account.active) {
    await logLoginAttempt(env, { request, username: email, role: null, accountId: null, success: false });
    return jsonError(404, "Account not found");
  }

  await logLoginAttempt(env, { request, username: account.username, role: account.role, accountId: account.id, success: true });

  const cookieValue = await signSession({ userId: account.id, username: account.username, role: account.role }, env);
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
  headers.set("Location", "/");
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
// session/login step of its own, so token use is treated as the equivalent
// of a login attempt for that account.
//
// Failures are always logged — a burst of them is the actual signal this
// exists to catch. Successes are throttled: admin.html re-sends the token on
// every single click (refresh, reset, delete, ...), so logging every one
// would bury a real incident under routine browsing noise. Only log a fresh
// "admin session" marker if the last successful entry was more than
// ADMIN_LOG_THROTTLE_MS ago.
const ADMIN_LOG_THROTTLE_MS = 5 * 60 * 1000;

async function requireAdmin(request, env) {
  const ok = checkAdminToken(request, env);

  if (!ok) {
    await logLoginAttempt(env, { request, username: "admin", role: "admin", accountId: null, success: false });
    return false;
  }

  try {
    const last = await env.DB
      .prepare("SELECT created_at FROM login_audit WHERE username = 'admin' AND success = 1 ORDER BY created_at DESC LIMIT 1")
      .first();
    const lastTime = last ? new Date(last.created_at).getTime() : 0;
    if (Date.now() - lastTime > ADMIN_LOG_THROTTLE_MS) {
      await logLoginAttempt(env, { request, username: "admin", role: "admin", accountId: null, success: true });
    }
  } catch (e) {
    console.error("requireAdmin throttle check failed:", e.message);
  }

  return true;
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

async function handleAdminListLearners(request, env) {
  if (!(await requireAdmin(request, env))) {
    return jsonError(403, "Forbidden");
  }

  const result = await env.DB
    .prepare("SELECT id, username, display_name, active, created_at FROM schools WHERE role = 'independent' ORDER BY created_at DESC")
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

  let result;
  try {
    result = await env.DB
      .prepare(
        "SELECT username, role, account_id, success, ip_address, user_agent, created_at FROM login_audit ORDER BY created_at DESC LIMIT 200"
      )
      .all();
  } catch (e) {
    // Most likely cause: migration 0003_login_audit.sql was never run against
    // this database, so the table doesn't exist yet.
    return jsonError(500, "Could not read login_audit — has migration 0003_login_audit.sql been run on this database? (" + e.message + ")");
  }

  return new Response(JSON.stringify({ rows: result.results || [] }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

function csvField(value) {
  const str = value === null || value === undefined ? "" : String(value);
  if (/["\n,]/.test(str)) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

async function handleAdminLoginAuditExport(request, env) {
  if (!(await requireAdmin(request, env))) {
    return jsonError(403, "Forbidden");
  }

  let result;
  try {
    result = await env.DB
      .prepare(
        "SELECT username, role, account_id, success, ip_address, user_agent, created_at FROM login_audit ORDER BY created_at DESC"
      )
      .all();
  } catch (e) {
    return jsonError(500, "Could not read login_audit — has migration 0003_login_audit.sql been run on this database? (" + e.message + ")");
  }

  // Exports every row, not just the 200 shown in the UI, so nothing is lost
  // if the admin clears the table right after exporting.
  const header = ["Timestamp", "Username", "Role", "Account ID", "Success", "IP address", "User agent"];
  const lines = [header.map(csvField).join(",")];
  for (const row of result.results || []) {
    lines.push(
      [row.created_at, row.username, row.role, row.account_id, row.success ? "Yes" : "No", row.ip_address, row.user_agent]
        .map(csvField)
        .join(",")
    );
  }

  return new Response(lines.join("\r\n"), {
    status: 200,
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename="login-audit-${new Date().toISOString().slice(0, 10)}.csv"`
    }
  });
}

async function handleAdminLoginAuditClear(request, env) {
  if (!(await requireAdmin(request, env))) {
    return jsonError(403, "Forbidden");
  }

  await env.DB.prepare("DELETE FROM login_audit").run();

  return new Response(JSON.stringify({ ok: true }), {
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

// A student is manageable by a teacher if that teacher directly owns them
// (teacher_id, set when the teacher added them directly or owns the
// classroom they joined) or has co-teacher access to their classroom.
// Never trust a studentId from the client without this check.
async function findManageableStudent(env, { studentId, teacherId }) {
  return env.DB
    .prepare(
      `SELECT s.id FROM schools s
       WHERE s.id = ? AND s.role = 'student' AND (
         s.teacher_id = ?
         OR s.classroom_id IN (SELECT classroom_id FROM classroom_teachers WHERE teacher_id = ?)
       )`
    )
    .bind(studentId, teacherId, teacherId)
    .first();
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

  const student = await findManageableStudent(env, { studentId, teacherId: session.userId });

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

  const student = await findManageableStudent(env, { studentId, teacherId: session.userId });

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
      `SELECT s.id AS student_id, s.username, s.display_name, c.name AS classroom_name,
              qa.provider, qa.score, qa.total, qa.completed_at
       FROM schools s
       LEFT JOIN classrooms c ON c.id = s.classroom_id
       LEFT JOIN quiz_attempts qa ON qa.student_id = s.id
       WHERE s.role = 'student' AND (
         s.teacher_id = ?
         OR s.classroom_id IN (SELECT classroom_id FROM classroom_teachers WHERE teacher_id = ?)
       )
       ORDER BY qa.completed_at DESC
       LIMIT 500`
    )
    .bind(session.userId, session.userId)
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

const VALID_SYLLABUSES = ["aqa_gcse_cs", "ocr_gcse_cs", "edexcel_gcse_cs"];

// Walks teacher_id up to the headteacher and returns their chosen syllabus,
// regardless of whether the caller is the headteacher, one of their
// teachers, or one of those teachers' students.
async function resolveSyllabus(env, session) {
  let headteacherId = null;

  if (session.role === "headteacher") {
    headteacherId = session.userId;
  } else if (session.role === "teacher") {
    const row = await env.DB.prepare("SELECT teacher_id FROM schools WHERE id = ?").bind(session.userId).first();
    headteacherId = row ? row.teacher_id : null;
  } else if (session.role === "student") {
    const teacherRow = await env.DB.prepare("SELECT teacher_id FROM schools WHERE id = ?").bind(session.userId).first();
    if (teacherRow && teacherRow.teacher_id) {
      const htRow = await env.DB.prepare("SELECT teacher_id FROM schools WHERE id = ?").bind(teacherRow.teacher_id).first();
      headteacherId = htRow ? htRow.teacher_id : null;
    }
  }

  if (!headteacherId) return null;
  const ht = await env.DB.prepare("SELECT syllabus FROM schools WHERE id = ?").bind(headteacherId).first();
  return ht ? ht.syllabus : null;
}

// Read-only view for teachers/students of the syllabus their headteacher
// chose. Deliberately returns null for the headteacher's own role — the
// headteacher picks the syllabus but doesn't browse it themselves through
// this endpoint (they use /api/headteacher/syllabus for that).
async function handleGetSyllabus(env, session) {
  if (session.role === "headteacher") {
    return new Response(JSON.stringify({ syllabus: null }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }

  const syllabus = await resolveSyllabus(env, session);
  return new Response(JSON.stringify({ syllabus }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleHeadteacherGetSyllabus(env, session) {
  if (session.role !== "headteacher") {
    return jsonError(403, "Forbidden");
  }

  const row = await env.DB.prepare("SELECT syllabus FROM schools WHERE id = ?").bind(session.userId).first();

  return new Response(JSON.stringify({ syllabus: (row && row.syllabus) || null }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleHeadteacherSetSyllabus(request, env, session) {
  if (session.role !== "headteacher") {
    return jsonError(403, "Forbidden");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const syllabus = (body && body.syllabus) || "";
  if (!VALID_SYLLABUSES.includes(syllabus)) {
    return jsonError(400, "Invalid syllabus");
  }

  await env.DB.prepare("UPDATE schools SET syllabus = ? WHERE id = ?").bind(syllabus, session.userId).run();

  return new Response(JSON.stringify({ ok: true, syllabus }), {
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

// ---------- self-service joining: teacher invites & classrooms ----------

// Creates a teacher/student account with no usable password — these accounts
// authenticate purely via emailed 6-digit codes (join flow, then returning
// login), so a long random value is stored just to satisfy the NOT NULL
// salt/hash columns. Nobody ever knows it, so the password-login path is
// effectively locked out for this account.
async function createPasswordlessAccount(env, { email, displayName, role, teacherId, classroomId }) {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const unusablePassword = toHex(crypto.getRandomValues(new Uint8Array(32)));
  const hashBytes = await pbkdf2Hash(unusablePassword, saltBytes);

  const result = await env.DB
    .prepare(
      "INSERT INTO schools (username, salt, hash, display_name, email, active, role, teacher_id, classroom_id, created_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)"
    )
    .bind(
      email,
      toHex(saltBytes),
      toHex(hashBytes),
      displayName || email,
      email,
      role,
      teacherId,
      classroomId || null,
      new Date().toISOString()
    )
    .run();

  return result.meta.last_row_id;
}

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Headteacher-initiated: enters one or more teacher emails, each gets a
// personal one-click invite link — no shared code, no code to type at all.
async function handleHeadteacherInviteTeachers(request, env, session) {
  if (session.role !== "headteacher") {
    return jsonError(403, "Forbidden");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const emails = [
    ...new Set(
      String((body && body.emails) || "")
        .split(/[\n,;]+/)
        .map((e) => e.trim().toLowerCase())
        .filter(Boolean)
    )
  ];

  if (emails.length === 0) {
    return jsonError(400, "Enter at least one email address");
  }

  const origin = new URL(request.url).origin;
  const sent = [];
  const skipped = [];

  for (const email of emails) {
    if (!EMAIL_PATTERN.test(email)) {
      skipped.push({ email, reason: "not a valid email address" });
      continue;
    }

    const existing = await env.DB.prepare("SELECT id FROM schools WHERE username = ? OR email = ?").bind(email, email).first();
    if (existing) {
      skipped.push({ email, reason: "already has an account" });
      continue;
    }

    const token = generateMagicToken();
    const link = `${origin}/join-teacher.html?token=${token}`;

    const result = await issueEmailCode(env, {
      email,
      purpose: "invite_teacher",
      payload: { headteacherId: session.userId },
      code: token,
      ttlMinutes: TEACHER_INVITE_TTL_MINUTES,
      subject: "You're invited to join OmniShell",
      bodyText: () =>
        `You've been invited to join OmniShell as a teacher. Click the link below to create your account:\n\n${link}\n\nThis link expires in 7 days.`
    });

    if (result.ok) sent.push(email);
    else skipped.push({ email, reason: result.error });
  }

  return new Response(JSON.stringify({ sent, skipped }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

// Public — lets the accept-invite page show which email the link is for
// before the teacher submits their name.
async function handleInviteTeacherLookup(request, env) {
  const url = new URL(request.url);
  const token = (url.searchParams.get("token") || "").trim();
  if (!token) {
    return jsonError(400, "token is required");
  }

  const found = await lookupEmailCode(env, { purpose: "invite_teacher", code: token });
  if (!found) {
    return jsonError(404, "This invite link is invalid or has expired.");
  }

  return new Response(JSON.stringify({ email: found.email }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

// Public — a prospective teacher isn't authenticated yet. The token itself
// (only ever sent to their inbox) is what proves the email is really theirs
// and that they were actually invited.
async function handleInviteTeacherAccept(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const token = ((body && body.token) || "").trim();
  const displayName = ((body && body.displayName) || "").trim();
  if (!token || !displayName) {
    return jsonError(400, "token and name are required");
  }

  const result = await consumeEmailCodeByToken(env, { purpose: "invite_teacher", code: token });
  if (!result.found) {
    return jsonError(400, "This invite link is invalid or has expired.");
  }

  const { email, payload } = result;
  const headteacher = await env.DB
    .prepare("SELECT id, active FROM schools WHERE id = ? AND role = 'headteacher'")
    .bind(payload.headteacherId)
    .first();
  if (!headteacher || !headteacher.active) {
    return jsonError(404, "This invite is no longer valid.");
  }

  let newId;
  try {
    newId = await createPasswordlessAccount(env, { email, displayName, role: "teacher", teacherId: headteacher.id });
  } catch {
    return jsonError(409, "An account with this email already exists — sign in instead.");
  }

  await logLoginAttempt(env, { request, username: email, role: "teacher", accountId: newId, success: true });

  const cookieValue = await signSession({ userId: newId, username: email, role: "teacher" }, env);
  return new Response(JSON.stringify({ ok: true }), {
    status: 201,
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": sessionCookieHeader(cookieValue)
    }
  });
}

// Every classroom the teacher can see — the ones they own, plus any they've
// been given co-teacher access to. `is_owner` tells the UI whether to show
// owner-only controls (regenerate code, manage co-teachers).
async function handleTeacherClassrooms(env, session) {
  if (session.role !== "teacher") {
    return jsonError(403, "Forbidden");
  }

  const result = await env.DB
    .prepare(
      `SELECT id, name, join_code, created_at, 1 AS is_owner FROM classrooms WHERE teacher_id = ?
       UNION
       SELECT c.id, c.name, c.join_code, c.created_at, 0 AS is_owner
       FROM classrooms c
       JOIN classroom_teachers ct ON ct.classroom_id = c.id
       WHERE ct.teacher_id = ?
       ORDER BY name`
    )
    .bind(session.userId, session.userId)
    .all();

  return new Response(JSON.stringify({ rows: result.results || [] }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleTeacherCreateClassroom(request, env, session) {
  if (session.role !== "teacher") {
    return jsonError(403, "Forbidden");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const name = ((body && body.name) || "").trim();
  if (!name) {
    return jsonError(400, "name is required");
  }

  for (let attempt = 0; attempt < 3; attempt++) {
    const joinCode = generateInviteCode();
    try {
      const result = await env.DB
        .prepare("INSERT INTO classrooms (teacher_id, name, join_code, created_at) VALUES (?, ?, ?, ?)")
        .bind(session.userId, name, joinCode, new Date().toISOString())
        .run();
      return new Response(JSON.stringify({ id: result.meta.last_row_id, name, join_code: joinCode }), {
        status: 201,
        headers: { "Content-Type": "application/json" }
      });
    } catch {
      // Unique join_code collision — loop and try a fresh code.
    }
  }

  return jsonError(500, "Could not create classroom, try again");
}

async function handleTeacherRegenerateClassroomCode(request, env, session) {
  if (session.role !== "teacher") {
    return jsonError(403, "Forbidden");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const classroomId = Number(body && body.classroomId);
  if (!Number.isInteger(classroomId)) {
    return jsonError(400, "classroomId is required");
  }

  // Only allow regenerating the code for a classroom that actually belongs
  // to the calling teacher — never trust classroomId alone.
  const classroom = await env.DB
    .prepare("SELECT id FROM classrooms WHERE id = ? AND teacher_id = ?")
    .bind(classroomId, session.userId)
    .first();

  if (!classroom) {
    return jsonError(404, "Classroom not found");
  }

  for (let attempt = 0; attempt < 3; attempt++) {
    const joinCode = generateInviteCode();
    try {
      await env.DB.prepare("UPDATE classrooms SET join_code = ? WHERE id = ?").bind(joinCode, classroomId).run();
      return new Response(JSON.stringify({ join_code: joinCode }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    } catch {
      // Unique join_code collision — loop and try a fresh code.
    }
  }

  return jsonError(500, "Could not generate a unique join code, try again");
}

// Co-teacher management is owner-only — a single point of accountability
// for who has access to a classroom, rather than any co-teacher being able
// to add further co-teachers.
async function handleTeacherAddCoTeacher(request, env, session) {
  if (session.role !== "teacher") {
    return jsonError(403, "Forbidden");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const classroomId = Number(body && body.classroomId);
  const email = ((body && body.email) || "").trim().toLowerCase();
  if (!Number.isInteger(classroomId) || !email) {
    return jsonError(400, "classroomId and email are required");
  }

  const classroom = await env.DB
    .prepare("SELECT id, teacher_id FROM classrooms WHERE id = ? AND teacher_id = ?")
    .bind(classroomId, session.userId)
    .first();
  if (!classroom) {
    return jsonError(404, "Classroom not found");
  }

  // Get the calling teacher's own headteacher, so we can confirm the
  // invited teacher belongs to the same school — never let someone add a
  // co-teacher from another school entirely.
  const owner = await env.DB.prepare("SELECT teacher_id FROM schools WHERE id = ?").bind(session.userId).first();

  const coTeacher = await env.DB
    .prepare("SELECT id FROM schools WHERE email = ? AND role = 'teacher' AND active = 1 AND teacher_id = ?")
    .bind(email, owner ? owner.teacher_id : null)
    .first();
  if (!coTeacher) {
    return jsonError(404, "No active teacher at your school found with that email");
  }

  if (coTeacher.id === session.userId) {
    return jsonError(400, "You already have access to your own classroom");
  }

  try {
    await env.DB
      .prepare("INSERT INTO classroom_teachers (classroom_id, teacher_id, added_at) VALUES (?, ?, ?)")
      .bind(classroomId, coTeacher.id, new Date().toISOString())
      .run();
  } catch {
    return jsonError(409, "That teacher already has access to this classroom");
  }

  return new Response(JSON.stringify({ ok: true, email }), {
    status: 201,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleTeacherRemoveCoTeacher(request, env, session) {
  if (session.role !== "teacher") {
    return jsonError(403, "Forbidden");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const classroomId = Number(body && body.classroomId);
  const teacherId = Number(body && body.teacherId);
  if (!Number.isInteger(classroomId) || !Number.isInteger(teacherId)) {
    return jsonError(400, "classroomId and teacherId are required");
  }

  const classroom = await env.DB
    .prepare("SELECT id FROM classrooms WHERE id = ? AND teacher_id = ?")
    .bind(classroomId, session.userId)
    .first();
  if (!classroom) {
    return jsonError(404, "Classroom not found");
  }

  await env.DB
    .prepare("DELETE FROM classroom_teachers WHERE classroom_id = ? AND teacher_id = ?")
    .bind(classroomId, teacherId)
    .run();

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function handleTeacherListCoTeachers(request, env, session) {
  if (session.role !== "teacher") {
    return jsonError(403, "Forbidden");
  }

  const url = new URL(request.url);
  const classroomId = Number(url.searchParams.get("classroomId"));
  if (!Number.isInteger(classroomId)) {
    return jsonError(400, "classroomId is required");
  }

  const classroom = await env.DB
    .prepare("SELECT id FROM classrooms WHERE id = ? AND teacher_id = ?")
    .bind(classroomId, session.userId)
    .first();
  if (!classroom) {
    return jsonError(404, "Classroom not found");
  }

  const result = await env.DB
    .prepare(
      `SELECT s.id, s.username, s.display_name, s.email
       FROM classroom_teachers ct
       JOIN schools s ON s.id = ct.teacher_id
       WHERE ct.classroom_id = ?
       ORDER BY s.display_name`
    )
    .bind(classroomId)
    .all();

  return new Response(JSON.stringify({ rows: result.results || [] }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

// Public — a prospective student isn't authenticated yet. The classroom join
// code is what proves they're allowed to join that class; the emailed code
// proves the email address is really theirs.
async function handleJoinStudentRequestCode(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const code = ((body && body.code) || "").trim().toUpperCase();
  const email = ((body && body.email) || "").trim().toLowerCase();
  const displayName = ((body && body.displayName) || "").trim();
  if (!code || !email || !displayName) {
    return jsonError(400, "code, email, and name are required");
  }

  const classroom = await env.DB.prepare("SELECT id, teacher_id FROM classrooms WHERE join_code = ?").bind(code).first();
  if (!classroom) {
    return jsonError(404, "Invalid class code");
  }

  const existing = await env.DB.prepare("SELECT id FROM schools WHERE username = ? OR email = ?").bind(email, email).first();
  if (existing) {
    return jsonError(409, "An account with this email already exists — sign in instead.");
  }

  const result = await issueEmailCode(env, {
    email,
    purpose: "join_student",
    payload: { classCode: code, displayName, classroomId: classroom.id },
    subject: "Your OmniShell verification code",
    bodyText: (verificationCode) =>
      `Your OmniShell verification code is ${verificationCode}. It expires in ${EMAIL_CODE_TTL_MINUTES} minutes.`
  });

  if (!result.ok) {
    return jsonError(429, result.error);
  }

  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "Content-Type": "application/json" } });
}

async function handleJoinStudentVerifyCode(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const email = ((body && body.email) || "").trim().toLowerCase();
  const code = ((body && body.code) || "").trim();
  if (!email || !code) {
    return jsonError(400, "email and code are required");
  }

  const result = await consumeEmailCode(env, { email, purpose: "join_student", code });
  if (!result.found) {
    return jsonError(400, "That code is invalid or has expired.");
  }

  const { classCode, displayName, classroomId } = result.payload;

  // Re-check the class code is still valid — it may have been regenerated in
  // the time between requesting and entering the code.
  const classroom = await env.DB
    .prepare("SELECT id, teacher_id FROM classrooms WHERE id = ? AND join_code = ?")
    .bind(classroomId, classCode)
    .first();
  if (!classroom) {
    return jsonError(404, "This class code is no longer valid — ask your teacher for a new one.");
  }

  let newId;
  try {
    newId = await createPasswordlessAccount(env, {
      email,
      displayName,
      role: "student",
      teacherId: classroom.teacher_id,
      classroomId: classroom.id
    });
  } catch {
    return jsonError(409, "An account with this email already exists — sign in instead.");
  }

  await logLoginAttempt(env, { request, username: email, role: "student", accountId: newId, success: true });

  const cookieValue = await signSession({ userId: newId, username: email, role: "student" }, env);
  return new Response(JSON.stringify({ ok: true }), {
    status: 201,
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": sessionCookieHeader(cookieValue)
    }
  });
}

// Independent learners — no school, no teacher. Public signup, so the emailed
// code is the only thing proving the address is theirs; nothing is created
// until it's entered. Name is collected up front and held in the code's
// payload, mirroring the student join flow.
async function handleLearnerSignupRequestCode(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const email = ((body && body.email) || "").trim().toLowerCase();
  const displayName = ((body && body.displayName) || "").trim();
  if (!email || !displayName) {
    return jsonError(400, "name and email are required");
  }
  if (!EMAIL_PATTERN.test(email) || email.length > 200) {
    return jsonError(400, "Enter a valid email address");
  }
  if (displayName.length > 80) {
    return jsonError(400, "Name is too long");
  }

  const existing = await env.DB.prepare("SELECT id FROM schools WHERE username = ? OR email = ?").bind(email, email).first();
  if (existing) {
    return jsonError(409, "An account with this email already exists. Log in instead, or use School Login if you're with a school.");
  }

  const result = await issueEmailCode(env, {
    email,
    purpose: "learner_signup",
    payload: { displayName },
    subject: "Your OmniShell verification code",
    bodyText: (verificationCode) =>
      `Your OmniShell verification code is ${verificationCode}. It expires in ${EMAIL_CODE_TTL_MINUTES} minutes.`
  });

  if (!result.ok) {
    return jsonError(429, result.error);
  }

  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "Content-Type": "application/json" } });
}

async function handleLearnerSignupVerifyCode(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const email = ((body && body.email) || "").trim().toLowerCase();
  const code = ((body && body.code) || "").trim();
  if (!email || !code) {
    return jsonError(400, "email and code are required");
  }

  const result = await consumeEmailCode(env, { email, purpose: "learner_signup", code });
  if (!result.found) {
    return jsonError(400, "That code is invalid or has expired.");
  }

  let newId;
  try {
    newId = await createPasswordlessAccount(env, {
      email,
      displayName: result.payload.displayName,
      role: "independent",
      teacherId: null,
      classroomId: null
    });
  } catch {
    return jsonError(409, "An account with this email already exists. Log in instead.");
  }

  await logLoginAttempt(env, { request, username: email, role: "independent", accountId: newId, success: true });

  const cookieValue = await signSession({ userId: newId, username: email, role: "independent" }, env);
  return new Response(JSON.stringify({ ok: true }), {
    status: 201,
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": sessionCookieHeader(cookieValue)
    }
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
    if (pathname === "/join-teacher.html" && method === "GET") {
      return env.ASSETS.fetch(request);
    }
    if (pathname === "/join-student.html" && method === "GET") {
      return env.ASSETS.fetch(request);
    }
    if (pathname === "/email-login.html" && method === "GET") {
      return env.ASSETS.fetch(request);
    }
    if (pathname === "/learner.html" && method === "GET") {
      return env.ASSETS.fetch(request);
    }
    if (pathname === "/api/learner/signup/request-code" && method === "POST") {
      return handleLearnerSignupRequestCode(request, env);
    }
    if (pathname === "/api/learner/signup/verify-code" && method === "POST") {
      return handleLearnerSignupVerifyCode(request, env);
    }
    if (pathname === "/api/admin/learners" && method === "GET") {
      return handleAdminListLearners(request, env);
    }
    if (pathname === "/api/login" && method === "POST") {
      return handleLogin(request, env);
    }
    if (pathname === "/api/invite/teacher/lookup" && method === "GET") {
      return handleInviteTeacherLookup(request, env);
    }
    if (pathname === "/api/invite/teacher/accept" && method === "POST") {
      return handleInviteTeacherAccept(request, env);
    }
    if (pathname === "/api/join/student/request-code" && method === "POST") {
      return handleJoinStudentRequestCode(request, env);
    }
    if (pathname === "/api/join/student/verify-code" && method === "POST") {
      return handleJoinStudentVerifyCode(request, env);
    }
    if (pathname === "/api/login/request-code" && method === "POST") {
      return handleLoginRequestCode(request, env);
    }
    if (pathname === "/api/login/verify-code" && method === "POST") {
      return handleLoginVerifyCode(request, env);
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
    if (pathname === "/api/admin/login-audit/export" && method === "GET") {
      return handleAdminLoginAuditExport(request, env);
    }
    if (pathname === "/api/admin/login-audit/clear" && method === "POST") {
      return handleAdminLoginAuditClear(request, env);
    }

    // Everything else requires a valid session.
    const cookies = parseCookies(request);
    const session = await verifySession(cookies[SESSION_COOKIE], env);

    if (!session) {
      // The public front door: logged-out visitors to "/" see the landing page
      // with the School Login / Login choice. Logged-in users still get the app.
      if (pathname === "/" && method === "GET") {
        const landingUrl = new URL(request.url);
        landingUrl.pathname = "/landing.html";
        return env.ASSETS.fetch(new Request(landingUrl.toString(), request));
      }
      const acceptsHtml = (request.headers.get("Accept") || "").includes("text/html");
      if (acceptsHtml) {
        return Response.redirect(`${url.origin}/`, 302);
      }
      return jsonError(401, "unauthorized");
    }

    if (pathname === "/api/me" && method === "GET") {
      return new Response(JSON.stringify({ username: session.username, role: session.role }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }
    if (pathname === "/api/syllabus" && method === "GET") {
      return handleGetSyllabus(env, session);
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
    if (pathname === "/api/teacher/classrooms" && method === "GET") {
      return handleTeacherClassrooms(env, session);
    }
    if (pathname === "/api/teacher/classrooms" && method === "POST") {
      return handleTeacherCreateClassroom(request, env, session);
    }
    if (pathname === "/api/teacher/classrooms/regenerate-code" && method === "POST") {
      return handleTeacherRegenerateClassroomCode(request, env, session);
    }
    if (pathname === "/api/teacher/classrooms/add-coteacher" && method === "POST") {
      return handleTeacherAddCoTeacher(request, env, session);
    }
    if (pathname === "/api/teacher/classrooms/remove-coteacher" && method === "POST") {
      return handleTeacherRemoveCoTeacher(request, env, session);
    }
    if (pathname === "/api/teacher/classrooms/coteachers" && method === "GET") {
      return handleTeacherListCoTeachers(request, env, session);
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
    if (pathname === "/api/headteacher/syllabus" && method === "GET") {
      return handleHeadteacherGetSyllabus(env, session);
    }
    if (pathname === "/api/headteacher/syllabus" && method === "POST") {
      return handleHeadteacherSetSyllabus(request, env, session);
    }
    if (pathname === "/api/headteacher/invite-teachers" && method === "POST") {
      return handleHeadteacherInviteTeachers(request, env, session);
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
