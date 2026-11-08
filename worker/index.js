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
async function sendEmail(env, { to, subject, text, html }) {
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
      // `text` is always sent alongside `html` so email apps that don't show
      // HTML still get a readable message (and it helps spam filters).
      body: JSON.stringify({ from: env.EMAIL_FROM, to: [to], subject, text, ...(html ? { html } : {}) })
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

// Set this to the public address of your logo image once you have one (for
// example "https://omni-shell.com/email-logo.png" — the file must be reachable
// without logging in, so it has to be added to the Worker's public-file
// allow-list). While it's null the emails show a text "OmniShell" wordmark
// instead, which looks fine and works in every email app.
const EMAIL_LOGO_URL = null;

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Builds the HTML version of an OmniShell email. Uses old-fashioned table
// layout and inline styles on purpose — it's the only thing every email app
// (Gmail, Outlook, Apple Mail) renders reliably. Anything that's passed in is
// escaped, so a name or address can't inject markup.
//   heading, intro  - the title and the sentence under it
//   code            - optional big 6-digit code
//   buttonText/Url  - optional call-to-action button (used for invites)
//   note            - optional small print under the main content
function renderEmailHtml({ preheader, heading, intro, code, buttonText, buttonUrl, note }) {
  const logo = EMAIL_LOGO_URL
    ? `<img src="${escapeHtml(EMAIL_LOGO_URL)}" alt="OmniShell" height="36" style="display:block;border:0;height:36px;">`
    : `<span style="font-family:Arial,Helvetica,sans-serif;font-size:24px;font-weight:700;letter-spacing:1px;color:#0f172a;"><span style="display:inline-block;background:#0284c7;color:#ffffff;border-radius:6px;padding:2px 8px;margin-right:8px;font-family:Consolas,Menlo,monospace;font-size:18px;">&gt;_</span>OmniShell</span>`;

  const codeBlock = code
    ? `<tr><td align="center" style="padding:8px 0 20px;">
         <div style="display:inline-block;background:#f1f5f9;border:1px solid #e2e8f0;border-radius:10px;padding:14px 28px;font-family:Consolas,Menlo,monospace;font-size:34px;font-weight:700;letter-spacing:8px;color:#0f172a;">${escapeHtml(code)}</div>
       </td></tr>`
    : "";

  const buttonBlock = buttonUrl
    ? `<tr><td align="center" style="padding:8px 0 20px;">
         <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td style="background:#0284c7;border-radius:8px;">
           <a href="${escapeHtml(buttonUrl)}" style="display:inline-block;padding:13px 26px;font-family:Arial,Helvetica,sans-serif;font-size:16px;font-weight:700;color:#ffffff;text-decoration:none;">${escapeHtml(buttonText || "Open")}</a>
         </td></tr></table>
       </td></tr>
       <tr><td align="center" style="padding:0 0 12px;font-family:Arial,Helvetica,sans-serif;font-size:12px;color:#64748b;word-break:break-all;">If the button doesn't work, copy this address into your browser:<br>${escapeHtml(buttonUrl)}</td></tr>`
    : "";

  const noteBlock = note
    ? `<tr><td style="padding:4px 0 0;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.5;color:#64748b;">${escapeHtml(note)}</td></tr>`
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="light">
<title>${escapeHtml(heading)}</title>
</head>
<body style="margin:0;padding:0;background:#f4f6f9;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:#f4f6f9;">${escapeHtml(preheader || heading)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f4f6f9;">
  <tr><td align="center" style="padding:32px 12px;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:520px;">
      <tr><td align="center" style="padding:0 0 20px;">${logo}</td></tr>
      <tr><td style="background:#ffffff;border:1px solid #e2e8f0;border-radius:14px;padding:32px 28px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
          <tr><td style="font-family:Arial,Helvetica,sans-serif;font-size:22px;font-weight:700;color:#0f172a;padding:0 0 10px;">${escapeHtml(heading)}</td></tr>
          <tr><td style="font-family:Arial,Helvetica,sans-serif;font-size:16px;line-height:1.55;color:#334155;padding:0 0 18px;">${escapeHtml(intro)}</td></tr>
          ${codeBlock}
          ${buttonBlock}
          ${noteBlock}
        </table>
      </td></tr>
      <tr><td align="center" style="padding:18px 8px 0;font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:1.5;color:#94a3b8;">
        OmniShell will never ask for your password by email.<br>omni-shell.com
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`;
}

// Shared by every request-code / invite endpoint: creates and emails a fresh
// code, throttling repeat requests for the same email+purpose so "Resend"
// can't be used to spam someone's inbox. Defaults to a short numeric OTP;
// pass `code`/`ttlMinutes` to issue a long-lived magic-link token instead.
// `bodyHtml` is optional: when given, the email is sent as a styled HTML
// message (with `bodyText` still included as the plain-text fallback).
async function issueEmailCode(env, { email, purpose, payload, subject, bodyText, bodyHtml, code, ttlMinutes }) {
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

  await sendEmail(env, {
    to: email,
    subject,
    text: bodyText(finalCode),
    html: bodyHtml ? bodyHtml(finalCode) : undefined
  });

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
        `Your OmniShell sign-in code is ${verificationCode}. It expires in ${EMAIL_CODE_TTL_MINUTES} minutes.`,
      bodyHtml: (verificationCode) =>
        renderEmailHtml({
          preheader: `Your sign-in code is ${verificationCode}`,
          heading: "Your sign-in code",
          intro: "Enter this code on the OmniShell sign-in page to log in.",
          code: verificationCode,
          note: `This code expires in ${EMAIL_CODE_TTL_MINUTES} minutes. If you didn't ask for it, you can safely ignore this email.`
        })
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
    await deleteBadgeData(
      env,
      "SELECT id FROM schools WHERE role = 'student' AND teacher_id IN (SELECT id FROM schools WHERE role = 'teacher' AND teacher_id = ?)",
      accountId
    );
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
    await deleteBadgeData(env, "SELECT id FROM schools WHERE teacher_id = ? AND role = 'student'", accountId);
    await env.DB.prepare("DELETE FROM schools WHERE teacher_id = ? AND role = 'student'").bind(accountId).run();
  } else {
    await env.DB.prepare("DELETE FROM quiz_attempts WHERE student_id = ?").bind(accountId).run();
    await deleteBadgeData(env, "SELECT id FROM schools WHERE id = ?", accountId);
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
  await deleteBadgeData(env, "SELECT id FROM schools WHERE id = ?", studentId);
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

// A combined set of notes drawing on all the exam boards. Only independent
// learners can use it (a school always chooses one real board), and it's what
// they get if they don't pick a board.
const GENERAL_SYLLABUS = "general_cs";
const INDEPENDENT_SYLLABUSES = [...VALID_SYLLABUSES, GENERAL_SYLLABUS];

// Turns what a sign-up form or profile page sends into the value we store:
// nothing / "none" / "general_cs" all mean "the combined notes".
function normaliseIndependentSyllabus(raw) {
  const value = String(raw || "").trim();
  if (value === "" || value === "none" || value === GENERAL_SYLLABUS) return GENERAL_SYLLABUS;
  return INDEPENDENT_SYLLABUSES.includes(value) ? value : null; // null = not allowed
}

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
  } else if (session.role === "independent") {
    // No school: an independent learner picks their own exam board, or the
    // combined notes (which is also the default if they never chose).
    const own = await env.DB.prepare("SELECT syllabus FROM schools WHERE id = ?").bind(session.userId).first();
    return own && own.syllabus ? own.syllabus : GENERAL_SYLLABUS;
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
  await deleteBadgeData(env, "SELECT id FROM schools WHERE teacher_id = ? AND role = 'student'", teacherId);
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
        `You've been invited to join OmniShell as a teacher. Click the link below to create your account:\n\n${link}\n\nThis link expires in 7 days.`,
      bodyHtml: () =>
        renderEmailHtml({
          preheader: "You've been invited to join OmniShell as a teacher",
          heading: "You're invited to OmniShell",
          intro: "Your headteacher has invited you to join their school on OmniShell as a teacher. Click the button below to create your account.",
          buttonText: "Create my account",
          buttonUrl: link,
          note: "This invitation link expires in 7 days. If you weren't expecting it, you can safely ignore this email."
        })
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
      `Your OmniShell verification code is ${verificationCode}. It expires in ${EMAIL_CODE_TTL_MINUTES} minutes.`,
    bodyHtml: (verificationCode) =>
      renderEmailHtml({
        preheader: `Your verification code is ${verificationCode}`,
        heading: "Confirm your email",
        intro: `Hi ${displayName}, enter this code to finish joining your class on OmniShell.`,
        code: verificationCode,
        note: `This code expires in ${EMAIL_CODE_TTL_MINUTES} minutes. If you didn't ask for it, you can safely ignore this email.`
      })
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

  // Which notes they want: one of the three exam boards, or the combined notes
  // covering all of them. Held with the code and saved when it's verified.
  const syllabus = normaliseIndependentSyllabus(body && body.syllabus);
  if (syllabus === null) {
    return jsonError(400, "Choose one of the exam boards, or the combined notes");
  }

  const existing = await env.DB.prepare("SELECT id FROM schools WHERE username = ? OR email = ?").bind(email, email).first();
  if (existing) {
    return jsonError(409, "An account with this email already exists. Log in instead, or use School Login if you're with a school.");
  }

  const result = await issueEmailCode(env, {
    email,
    purpose: "learner_signup",
    payload: { displayName, syllabus },
    subject: "Your OmniShell verification code",
    bodyText: (verificationCode) =>
      `Your OmniShell verification code is ${verificationCode}. It expires in ${EMAIL_CODE_TTL_MINUTES} minutes.`,
    bodyHtml: (verificationCode) =>
      renderEmailHtml({
        preheader: `Your verification code is ${verificationCode}`,
        heading: "Welcome to OmniShell",
        intro: `Hi ${displayName}, enter this code to finish creating your account.`,
        code: verificationCode,
        note: `This code expires in ${EMAIL_CODE_TTL_MINUTES} minutes. If you didn't ask for it, you can safely ignore this email.`
      })
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

  const chosenBoard = result.payload && result.payload.syllabus;
  if (chosenBoard && INDEPENDENT_SYLLABUSES.includes(chosenBoard)) {
    await env.DB.prepare("UPDATE schools SET syllabus = ? WHERE id = ?").bind(chosenBoard, newId).run();
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

  const now = new Date().toISOString();
  await env.DB
    .prepare(
      "INSERT INTO quiz_attempts (student_id, provider, score, total, completed_at) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(session.userId, provider, score, total, now)
    .run();

  // Remember which commands were answered correctly (this is what language
  // mastery is counted from). Sanity-limited: it can't list more commands than
  // the score, and a failure here must never lose the quiz result above.
  const claimed = Array.isArray(body && body.correctCommands) ? body.correctCommands : [];
  const correctCommands = [
    ...new Set(
      claimed
        .filter((c) => typeof c === "string")
        .map((c) => c.trim())
        .filter((c) => c.length > 0 && c.length <= 200)
    )
  ].slice(0, Math.min(score, 50));
  if (correctCommands.length > 0 && /^[a-z0-9_]{1,60}$/.test(provider)) {
    try {
      await env.DB.batch(
        correctCommands.map((command) =>
          env.DB
            .prepare("INSERT OR IGNORE INTO quiz_correct (student_id, provider, command, first_correct_at) VALUES (?, ?, ?, ?)")
            .bind(session.userId, provider, command, now)
        )
      );
    } catch {
      // quiz_correct not created yet: the quiz still counts, mastery just isn't tracked
    }
  }

  const { newIds } = await awardBadges(env, session.userId);

  return new Response(JSON.stringify({ ok: true, newBadges: newIds }), {
    status: 201,
    headers: { "Content-Type": "application/json" }
  });
}

// ---------- badges and streaks ----------
//
// Badges are awarded automatically by the server after each quiz, from what
// is stored about the learner (never from anything the browser claims about
// badges). The rules live in badgesFromStats() below as a plain function so
// they're easy to read and to test. How badges *look* is in web/badges.js.

const LANGUAGE_PROVIDERS = ["linux", "powershell", "python", "javascript", "java", "cpp", "sql", "git"];

// Language mastery counts DIFFERENT commands answered correctly at least once.
const MASTERY_TIERS = [
  { tier: "bronze", count: 25 },
  { tier: "silver", count: 75 },
  { tier: "gold", count: 150 }
];

const STREAK_BADGES = [
  { id: "streak_3", days: 3 },
  { id: "streak_7", days: 7 },
  { id: "streak_30", days: 30 }
];

// The calendar day, in UK time, that a timestamp falls on ("2026-11-07").
function londonDay(isoOrDate) {
  return new Date(isoOrDate).toLocaleDateString("en-CA", { timeZone: "Europe/London" });
}

function previousDay(day) {
  const d = new Date(`${day}T12:00:00Z`);
  d.setUTCDate(d.getUTCDate() - 1);
  return d.toISOString().slice(0, 10);
}

// Current streak: consecutive days with a quiz, counting back from today.
// Weekends are forgiving: taking a quiz on a Saturday or Sunday adds to the
// streak, but missing one never breaks it (so it suits school pupils). Not
// having done a quiz *yet today* doesn't break it either.
function computeStreak(quizDays, today) {
  let streak = 0;
  let day = today;
  for (let i = 0; i < 400; i++) {
    const dow = new Date(`${day}T12:00:00Z`).getUTCDay();
    const isWeekend = dow === 0 || dow === 6;
    if (quizDays.has(day)) {
      streak++;
    } else if (!isWeekend && i > 0) {
      break;
    }
    day = previousDay(day);
  }
  return streak;
}

// attempts: [{ provider, score, total, completed_at }] oldest first
// correctByProvider: { python: 42, linux: 10, ... } (different commands answered correctly)
function summariseAttempts(attempts, correctByProvider, now) {
  const quizDays = new Set(attempts.map((a) => londonDay(a.completed_at)));
  const lastPercentByProvider = {};
  let comeback = false;
  let highScores = 0;
  let fullMarks = false;
  const tried = new Set();

  for (const a of attempts) {
    if (!(a.total > 0)) continue;
    const pct = (100 * a.score) / a.total;
    if (pct >= 90) highScores++;
    if (a.total >= 5 && a.score === a.total) fullMarks = true;
    if (LANGUAGE_PROVIDERS.includes(a.provider)) tried.add(a.provider);
    const prev = lastPercentByProvider[a.provider];
    if (prev !== undefined && pct - prev >= 20) comeback = true;
    lastPercentByProvider[a.provider] = pct;
  }

  return {
    attemptCount: attempts.length,
    fullMarks,
    highScores,
    comeback,
    languagesTried: tried.size,
    streak: computeStreak(quizDays, londonDay(now)),
    correctByProvider: correctByProvider || {}
  };
}

// The badge rules. Returns every badge id the learner has earned so far.
function badgesFromStats(stats) {
  const earned = [];
  if (stats.attemptCount >= 1) earned.push("first_quiz");
  if (stats.attemptCount >= 10) earned.push("quizzes_10");
  if (stats.attemptCount >= 50) earned.push("quizzes_50");
  if (stats.attemptCount >= 100) earned.push("quizzes_100");
  if (stats.fullMarks) earned.push("full_marks");
  if (stats.highScores >= 3) earned.push("hat_trick");
  if (stats.comeback) earned.push("comeback");
  if (stats.languagesTried >= LANGUAGE_PROVIDERS.length) earned.push("polyglot");

  for (const s of STREAK_BADGES) {
    if (stats.streak >= s.days) earned.push(s.id);
  }

  for (const provider of LANGUAGE_PROVIDERS) {
    const n = stats.correctByProvider[provider] || 0;
    for (const t of MASTERY_TIERS) {
      if (n >= t.count) earned.push(`mastery_${provider}_${t.tier}`);
    }
  }
  return earned;
}

// Reads what we need about a learner. The commands table is read separately
// so a missing table (migration 0008 not run yet) only switches mastery off.
async function loadLearnerStats(env, userId) {
  const attemptRows = await env.DB
    .prepare("SELECT provider, score, total, completed_at FROM quiz_attempts WHERE student_id = ? ORDER BY completed_at LIMIT 5000")
    .bind(userId)
    .all();

  const correctByProvider = {};
  try {
    const correctRows = await env.DB
      .prepare("SELECT provider, COUNT(*) AS n FROM quiz_correct WHERE student_id = ? GROUP BY provider")
      .bind(userId)
      .all();
    for (const r of correctRows.results || []) correctByProvider[r.provider] = r.n;
  } catch {
    // table not created yet: no mastery badges until it is
  }

  return summariseAttempts(attemptRows.results || [], correctByProvider, new Date());
}

// Works out what's been earned and saves anything new. Safe to run as often as
// you like: badges already held are never touched. Returns the ids that were
// newly awarded, plus the stats it used. Never throws, so a badge problem can
// never stop a quiz result being saved.
async function awardBadges(env, userId) {
  try {
    const stats = await loadLearnerStats(env, userId);
    const shouldHave = badgesFromStats(stats);
    const held = await env.DB.prepare("SELECT badge_id FROM user_badges WHERE user_id = ?").bind(userId).all();
    const heldIds = new Set((held.results || []).map((r) => r.badge_id));
    const newIds = shouldHave.filter((id) => !heldIds.has(id));
    const now = new Date().toISOString();
    for (const id of newIds) {
      await env.DB
        .prepare("INSERT OR IGNORE INTO user_badges (user_id, badge_id, earned_at) VALUES (?, ?, ?)")
        .bind(userId, id, now)
        .run();
    }
    return { newIds, stats };
  } catch {
    return { newIds: [], stats: null };
  }
}

// Called when an account's quiz history is deleted, so no badge data is left
// behind. Each table is tried on its own so a missing one can't block deletion.
async function deleteBadgeData(env, idsSql, ...binds) {
  for (const [table, column] of [["quiz_correct", "student_id"], ["user_badges", "user_id"]]) {
    try {
      await env.DB.prepare(`DELETE FROM ${table} WHERE ${column} IN (${idsSql})`).bind(...binds).run();
    } catch {
      // table not created yet
    }
  }
}

// ---------- profile ----------

// Who's logged in, for the header. The name is best-effort: if the lookup
// fails the page still works and just falls back to the username.
async function handleMe(env, session) {
  let displayName = null;
  try {
    const row = await env.DB.prepare("SELECT display_name FROM schools WHERE id = ?").bind(session.userId).first();
    displayName = row && row.display_name ? row.display_name : null;
  } catch {
    displayName = null;
  }
  return new Response(JSON.stringify({ username: session.username, role: session.role, displayName }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

// Everything the profile page shows, and only ever about the logged-in user:
// the account id always comes from the signed session cookie, never from the
// request, so nobody can ask for someone else's profile.
async function handleProfile(env, session) {
  const me = await env.DB
    .prepare("SELECT id, username, display_name, email, role, teacher_id, classroom_id, syllabus, created_at FROM schools WHERE id = ?")
    .bind(session.userId)
    .first();
  if (!me) {
    return jsonError(404, "Account not found");
  }

  const nameOf = (row) => (row ? row.display_name || row.username : null);

  const profile = {
    displayName: me.display_name || null,
    username: me.username,
    email: me.email || (String(me.username).includes("@") ? me.username : null),
    role: me.role,
    memberSince: me.created_at || null,
    headteacher: null,
    teacher: null,
    classroom: null,
    classrooms: [],
    counts: null,
    syllabus: null,
    canChooseBoard: me.role === "independent",
    stats: null,
    badges: null
  };

  if (me.role === "student") {
    if (me.classroom_id) {
      const room = await env.DB.prepare("SELECT name FROM classrooms WHERE id = ?").bind(me.classroom_id).first();
      profile.classroom = room ? room.name : null;
    }
    if (me.teacher_id) {
      const teacher = await env.DB
        .prepare("SELECT display_name, username, teacher_id FROM schools WHERE id = ?")
        .bind(me.teacher_id)
        .first();
      profile.teacher = nameOf(teacher);
      if (teacher && teacher.teacher_id) {
        const head = await env.DB
          .prepare("SELECT display_name, username FROM schools WHERE id = ?")
          .bind(teacher.teacher_id)
          .first();
        profile.headteacher = nameOf(head);
      }
    }
  } else if (me.role === "teacher") {
    if (me.teacher_id) {
      const head = await env.DB
        .prepare("SELECT display_name, username FROM schools WHERE id = ?")
        .bind(me.teacher_id)
        .first();
      profile.headteacher = nameOf(head);
    }
    const rooms = await env.DB
      .prepare(
        `SELECT c.id, c.name, COUNT(s.id) AS students
         FROM classrooms c
         LEFT JOIN schools s ON s.classroom_id = c.id AND s.role = 'student'
         WHERE c.teacher_id = ?
         GROUP BY c.id, c.name
         ORDER BY c.name`
      )
      .bind(me.id)
      .all();
    profile.classrooms = (rooms.results || []).map((r) => ({ name: r.name, students: r.students }));
  } else if (me.role === "headteacher") {
    const teachers = await env.DB
      .prepare("SELECT COUNT(*) AS n FROM schools WHERE role = 'teacher' AND teacher_id = ?")
      .bind(me.id)
      .first();
    const students = await env.DB
      .prepare("SELECT COUNT(*) AS n FROM schools WHERE role = 'student' AND teacher_id IN (SELECT id FROM schools WHERE role = 'teacher' AND teacher_id = ?)")
      .bind(me.id)
      .first();
    profile.counts = { teachers: teachers ? teachers.n : 0, students: students ? students.n : 0 };
  }

  // Exam board: a headteacher picks it, their teachers and students inherit it.
  if (me.role === "headteacher") {
    profile.syllabus = me.syllabus || null;
  } else if (me.role === "independent") {
    profile.syllabus = me.syllabus || GENERAL_SYLLABUS;
  } else if (me.role === "teacher" || me.role === "student") {
    profile.syllabus = await resolveSyllabus(env, session);
  }

  // Quiz progress (students and independent learners are the ones who take quizzes).
  if (me.role === "student" || me.role === "independent") {
    const perProvider = await env.DB
      .prepare(
        `SELECT provider,
                COUNT(*) AS attempts,
                MAX(100.0 * score / total) AS best_percent,
                AVG(100.0 * score / total) AS average_percent
         FROM quiz_attempts
         WHERE student_id = ? AND total > 0
         GROUP BY provider
         ORDER BY provider`
      )
      .bind(me.id)
      .all();
    const rows = (perProvider.results || []).map((r) => ({
      provider: r.provider,
      attempts: r.attempts,
      bestPercent: Math.round(r.best_percent),
      averagePercent: Math.round(r.average_percent)
    }));
    const totalAttempts = rows.reduce((sum, r) => sum + r.attempts, 0);
    const weightedAverage = totalAttempts
      ? Math.round(rows.reduce((sum, r) => sum + r.averagePercent * r.attempts, 0) / totalAttempts)
      : 0;
    profile.stats = { quizzesTaken: totalAttempts, averagePercent: weightedAverage, byProvider: rows };

    // Badges. Running the award check here also gives anyone with quiz history
    // from before badges existed the badges they'd already earned.
    const award = await awardBadges(env, me.id);
    if (award.stats) {
      let earned = [];
      try {
        const held = await env.DB
          .prepare("SELECT badge_id, earned_at FROM user_badges WHERE user_id = ? ORDER BY earned_at")
          .bind(me.id)
          .all();
        earned = (held.results || []).map((r) => ({ id: r.badge_id, earnedAt: r.earned_at }));
      } catch {
        earned = [];
      }
      profile.badges = {
        earned,
        streak: award.stats.streak,
        mastery: award.stats.correctByProvider,
        tiers: MASTERY_TIERS,
        languages: LANGUAGE_PROVIDERS
      };
    }
  }

  return new Response(JSON.stringify(profile), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

// An independent learner changing which exam board's notes they see. School
// accounts can't: their board is chosen by their headteacher. "none" (or
// empty) means no exam board: just the general notes.
async function handleSetOwnSyllabus(request, env, session) {
  if (session.role !== "independent") {
    return jsonError(403, "Your exam board is chosen by your school");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid request");
  }

  const value = normaliseIndependentSyllabus(body && body.syllabus);
  if (value === null) {
    return jsonError(400, "Invalid syllabus");
  }

  await env.DB.prepare("UPDATE schools SET syllabus = ? WHERE id = ?").bind(value, session.userId).run();

  return new Response(JSON.stringify({ ok: true, syllabus: value }), {
    status: 200,
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
      return handleMe(env, session);
    }
    if (pathname === "/api/profile" && method === "GET") {
      return handleProfile(env, session);
    }
    if (pathname === "/api/profile/syllabus" && method === "POST") {
      return handleSetOwnSyllabus(request, env, session);
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
