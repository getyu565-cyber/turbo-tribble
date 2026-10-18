const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 5900;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* ============================================================ STORAGE ============================================================ */

const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const APPS_FILE = path.join(DATA_DIR, "oauth-apps.json");
const SECRET_FILE = path.join(DATA_DIR, "oauth-secret.key");
const REVOKED_TOKENS_FILE = path.join(DATA_DIR, "revoked-tokens.json");
const AUTH_CODES_FILE = path.join(DATA_DIR, "auth-codes.json");
const ACCESS_TOKENS_FILE = path.join(DATA_DIR, "access-tokens.json");
const REFRESH_TOKENS_FILE = path.join(DATA_DIR, "refresh-tokens.json");
const PROJECTS_FILE = path.join(DATA_DIR, "projects.json");
const API_TOKENS_FILE = path.join(DATA_DIR, "api-tokens.json");

fs.mkdirSync(DATA_DIR, { recursive: true });
for (const [file, init] of [
  [USERS_FILE, "[]"],
  [APPS_FILE, "[]"],
  [REVOKED_TOKENS_FILE, "[]"],
  [AUTH_CODES_FILE, "[]"],
  [ACCESS_TOKENS_FILE, "[]"],
  [REFRESH_TOKENS_FILE, "[]"],
  [PROJECTS_FILE, "[]"],
  [API_TOKENS_FILE, "[]"],
]) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, init);
}

let OAUTH_SECRET;
if (fs.existsSync(SECRET_FILE)) {
  OAUTH_SECRET = fs.readFileSync(SECRET_FILE, "utf8").trim();
} else {
  OAUTH_SECRET = crypto.randomBytes(64).toString("hex");
  fs.writeFileSync(SECRET_FILE, OAUTH_SECRET, { mode: 0o600 });
}
console.log("OAuth secret key loaded/generated.");

const deviceCodes = new Map();

/* ============================================================ HELPERS ============================================================ */

const readJson = (f) => { try { return JSON.parse(fs.readFileSync(f, "utf8")); } catch { return []; } };
const writeJson = (f, v) => fs.writeFileSync(f, JSON.stringify(v, null, 2));
const randomHex = (n) => crypto.randomBytes(n).toString("hex");
const generateClientId = () => "client_" + randomHex(16);
const generateClientSecret = () => "secret_" + randomHex(32);
const generateDeviceCode = () => crypto.randomBytes(4).toString("hex").toUpperCase();
const hashPassword = (p) => crypto.createHash("sha256").update(p).digest("hex");
const baseUrl = (req) => `${req.headers["x-forwarded-proto"] || req.protocol}://${req.get("host")}`;

function isTokenRevoked(jti) {
  if (!jti) return false;
  return readJson(REVOKED_TOKENS_FILE).some((i) => i.jti === jti);
}
function revokeToken(jti, exp) {
  const revoked = readJson(REVOKED_TOKENS_FILE);
  if (revoked.some((i) => i.jti === jti)) return;
  revoked.push({ jti, exp: exp || null, revokedAt: new Date().toISOString() });
  writeJson(REVOKED_TOKENS_FILE, revoked);
}

const SCOPES_SUPPORTED = [
  "openid",
  "profile",
  "email",
  "offline_access",
  "api.connectors.read",
  "api.connectors.invoke",
];

function base64UrlEncode(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64UrlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Buffer.from(str, "base64");
}
function verifyPkce(codeVerifier, codeChallenge, method) {
  if (!codeChallenge) return true;
  if (!codeVerifier) return false;
  if (method === "S256" || !method) {
    const hash = base64UrlEncode(crypto.createHash("sha256").update(codeVerifier).digest());
    return hash === codeChallenge;
  }
  if (method === "plain") return codeVerifier === codeChallenge;
  return false;
}

function issueAccessToken(user, scope, extra = {}) {
  const jti = randomHex(32);
  const token = jwt.sign(
    { sub: user.username, username: user.username, scope: scope || "", jti, ...extra },
    OAUTH_SECRET,
    { expiresIn: "1h" }
  );
  const tokens = readJson(ACCESS_TOKENS_FILE);
  const decoded = jwt.decode(token);
  tokens.push({
    jti,
    token,
    username: user.username,
    scope: scope || "",
    client_id: extra.client_id || null,
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(decoded.exp * 1000).toISOString(),
    revoked: false,
  });
  writeJson(ACCESS_TOKENS_FILE, tokens);
  return { token, jti, decoded };
}

function issueRefreshToken(user, scope, clientId) {
  const token = "rt_" + randomHex(32);
  const refresh = readJson(REFRESH_TOKENS_FILE);
  refresh.push({
    token,
    username: user.username,
    scope: scope || "",
    client_id: clientId || null,
    createdAt: new Date().toISOString(),
    revoked: false,
  });
  writeJson(REFRESH_TOKENS_FILE, refresh);
  return token;
}

/* ============================================================ DEVICE LOGIN HTML ============================================================ */

const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect Account</title>
<style>
body { background: #111; color: #00ff66; font-family: monospace; padding: 25px; }
.container { max-width: 520px; margin: auto; background: #1b1b1b; padding: 25px; border-radius: 8px; }
h1, h2 { border-bottom: 1px solid #333; padding-bottom: 8px; }
input, button { width: 100%; box-sizing: border-box; padding: 12px; margin: 6px 0; background: #222; color: white; border: 1px solid #444; font-family: monospace; }
button { background: #0088cc; cursor: pointer; font-weight: bold; }
button:hover { background: #00aaff; }
hr { border: 0; border-top: 1px solid #333; margin: 25px 0; }
</style>
</head>
<body>
<div class="container">
<h1>Connect Account</h1>
<p>Enter your device code to connect your account.</p>
<form method="POST" action="/login/device">
<input name="device_code" placeholder="Enter your device code" required>
<h2>Login</h2>
<input name="username" placeholder="Enter username" required>
<input type="password" name="password" placeholder="Enter password" required>
<button type="submit">Connect Account</button>
</form>
<hr>
<h2>Register Account</h2>
<form method="POST" action="/api/auth/register">
<input name="username" placeholder="Enter username" required>
<input type="password" name="password" placeholder="Enter password" required>
<button type="submit">Create Account</button>
</form>
</div>
</body>
</html>
`;

app.get("/oauth/device", (req, res) => res.send(htmlContent));
app.get("/login/device", (req, res) => res.send(htmlContent));

/* ============================================================ DEVICE CODE ============================================================ */

app.post("/oauth/device/code", (req, res) => {
  const deviceCode = randomHex(32);
  const userCode = generateDeviceCode();
  const expiresIn = 600;
  deviceCodes.set(deviceCode, {
    deviceCode,
    userCode,
    clientId: req.body.client_id || null,
    scope: req.body.scope || "",
    username: null,
    status: "pending",
    createdAt: Date.now(),
    expiresAt: Date.now() + expiresIn * 1000,
  });
  res.json({
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: `${baseUrl(req)}/oauth/device`,
    verification_uri_complete: `${baseUrl(req)}/oauth/device?code=${userCode}`,
    expires_in: expiresIn,
    interval: 5,
  });
});

/* ============================================================ REGISTER + LOGIN ============================================================ */

app.post("/api/auth/register", (req, res) => {
  const { username, password } = req.body;
  if (typeof username !== "string" || typeof password !== "string")
    return res.status(400).json({ error: "username_and_password_required" });
  if (username.length < 3 || password.length < 8)
    return res.status(400).json({ error: "invalid_registration", message: "Username >= 3 and password >= 8 chars." });
  const users = readJson(USERS_FILE);
  if (users.some((u) => u.username === username))
    return res.status(409).json({ error: "username_already_exists" });
  users.push({
    id: randomHex(16),
    username,
    passwordHash: hashPassword(password),
    createdAt: new Date().toISOString(),
  });
  writeJson(USERS_FILE, users);
  res.status(201).json({ status: "success", message: "Account created", username });
});

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body;
  const users = readJson(USERS_FILE);
  const user = users.find((u) => u.username === username);
  if (!user || user.passwordHash !== hashPassword(password || ""))
    return res.status(401).json({ error: "invalid_credentials" });

  const { token } = issueAccessToken(user, "openid profile email", { jti_type: "login" });
  res.json({ access_token: token, token_type: "Bearer", expires_in: 3600 });
});

/* ============================================================ DEVICE APPROVAL ============================================================ */

app.post("/login/device", (req, res) => {
  const { device_code, username, password } = req.body;
  if (!device_code || !username || !password)
    return res.status(400).send("Device code, username and password are required.");
  let device = null;
  for (const item of deviceCodes.values()) {
    if (item.deviceCode === device_code || item.userCode === device_code.toUpperCase()) {
      device = item; break;
    }
  }
  if (!device) return res.status(400).send("Invalid device code.");
  if (Date.now() > device.expiresAt) return res.status(400).send("Device code expired.");
  const users = readJson(USERS_FILE);
  const user = users.find((u) => u.username === username);
  if (!user || user.passwordHash !== hashPassword(password))
    return res.status(401).send("Invalid username or password.");
  device.status = "approved";
  device.username = username;
  res.redirect(`/login/device/success?device_code=${encodeURIComponent(device.deviceCode)}`);
});

app.get("/login/device/success", (req, res) => {
  const { device_code } = req.query;
  const device = deviceCodes.get(device_code);
  if (!device) return res.status(404).send("Device code not found.");
  res.send(`
    <!DOCTYPE html><html><head><title>Device Connected</title>
    <style>body{background:#111;color:#00ff66;font-family:monospace;padding:30px;}
    .box{max-width:600px;margin:auto;background:#1b1b1b;padding:25px;}</style></head>
    <body><div class="box"><h1>Device Connected</h1>
    <p>Account successfully connected.</p>
    <p>Username: <strong>${device.username}</strong></p>
    <p>You can return to your application.</p></div></body></html>`);
});

/* ============================================================ OAUTH AUTHORIZE (PKCE) ============================================================ */

app.get("/oauth/authorize", (req, res) => {
  const {
    response_type, client_id, redirect_uri, code_challenge, code_challenge_method,
    state, scope, originator,
  } = req.query;

  if (response_type !== "code")
    return res.status(400).json({ error: "unsupported_response_type" });
  if (!client_id) return res.status(400).json({ error: "invalid_request", message: "client_id required" });
  if (!redirect_uri) return res.status(400).json({ error: "invalid_request", message: "redirect_uri required" });

  const apps = readJson(APPS_FILE);
  const oauthApp = apps.find((a) => a.client_id === client_id);
  if (!oauthApp) return res.status(400).json({ error: "invalid_client" });
  if (oauthApp.redirect_uri && oauthApp.redirect_uri !== redirect_uri)
    return res.status(400).json({ error: "invalid_redirect_uri" });

  const loginPage = `
    <!DOCTYPE html><html><head><title>Authorize ${oauthApp.name}</title>
    <style>body{background:#111;color:#00ff66;font-family:monospace;padding:25px;}
    .box{max-width:520px;margin:auto;background:#1b1b1b;padding:25px;border-radius:8px;}
    input,button{width:100%;box-sizing:border-box;padding:12px;margin:6px 0;
    background:#222;color:#fff;border:1px solid #444;font-family:monospace;}
    button{background:#0088cc;cursor:pointer;font-weight:bold;}</style></head>
    <body><div class="box">
    <h1>Authorize App</h1>
    <p><strong>${oauthApp.name}</strong> is requesting access.</p>
    <p>Scopes: <code>${scope || "openid profile email"}</code></p>
    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="client_id" value="${client_id}">
      <input type="hidden" name="redirect_uri" value="${redirect_uri}">
      <input type="hidden" name="code_challenge" value="${code_challenge || ""}">
      <input type="hidden" name="code_challenge_method" value="${code_challenge_method || ""}">
      <input type="hidden" name="state" value="${state || ""}">
      <input type="hidden" name="scope" value="${scope || "openid profile email"}">
      <input type="hidden" name="originator" value="${originator || ""}">
      <input name="username" placeholder="Username" required>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">Approve</button>
    </form></div></body></html>`;
  res.send(loginPage);
});

app.post("/oauth/authorize", (req, res) => {
  const {
    client_id, redirect_uri, code_challenge, code_challenge_method,
    state, scope, username, password, originator,
  } = req.body;

  const users = readJson(USERS_FILE);
  const user = users.find((u) => u.username === username);
  if (!user || user.passwordHash !== hashPassword(password || ""))
    return res.status(401).send("Invalid username or password.");

  const code = "ac_" + randomHex(24);
  const codes = readJson(AUTH_CODES_FILE);
  codes.push({
    code,
    client_id,
    redirect_uri,
    code_challenge: code_challenge || null,
    code_challenge_method: code_challenge_method || null,
    scope: scope || "openid profile email",
    username,
    originator: originator || null,
    createdAt: Date.now(),
    expiresAt: Date.now() + 10 * 60 * 1000,
    used: false,
  });
  writeJson(AUTH_CODES_FILE, codes);

  const url = new URL(redirect_uri);
  url.searchParams.set("code", code);
  if (state) url.searchParams.set("state", state);
  res.redirect(url.toString());
});

/* ============================================================ OAUTH APPS ============================================================ */

app.post(["/oauth/apps", "/create"], (req, res) => {
  const { name, redirect_uri } = req.body;
  if (!name) return res.status(400).json({ error: "application_name_required" });
  const apps = readJson(APPS_FILE);
  const app_ = {
    id: randomHex(16),
    name,
    client_id: generateClientId(),
    client_secret: generateClientSecret(),
    redirect_uri: redirect_uri || null,
    createdAt: new Date().toISOString(),
  };
  apps.push(app_);
  writeJson(APPS_FILE, apps);
  res.status(201).json({ status: "success", ...app_ });
});

app.get("/oauth/apps", (req, res) => {
  const apps = readJson(APPS_FILE).map(({ client_secret, ...rest }) => rest);
  res.json({ apps });
});

app.get("/oauth/apps/:client_id", (req, res) => {
  const app_ = readJson(APPS_FILE).find((a) => a.client_id === req.params.client_id);
  if (!app_) return res.status(404).json({ error: "app_not_found" });
  const { client_secret, ...rest } = app_;
  res.json(rest);
});

app.delete("/oauth/apps/:client_id", (req, res) => {
  const apps = readJson(APPS_FILE);
  const idx = apps.findIndex((a) => a.client_id === req.params.client_id);
  if (idx === -1) return res.status(404).json({ error: "app_not_found" });
  const [removed] = apps.splice(idx, 1);
  writeJson(APPS_FILE, apps);
  res.json({ status: "success", deleted: removed.client_id });
});

app.get("/create", (req, res) => {
  res.send(`
    <!DOCTYPE html><html lang="en"><head><title>Create OAuth App</title></head>
    <body style="background:#111;color:#00ff66;font-family:monospace;padding:30px;">
    <h2>Register OAuth App</h2>
    <form method="POST" action="/create">
      <input name="name" placeholder="App Name" required style="padding:10px;background:#222;color:#fff;border:1px solid #444;margin-bottom:10px;display:block;"><br>
      <input name="redirect_uri" placeholder="Redirect URI (optional)" style="padding:10px;background:#222;color:#fff;border:1px solid #444;margin-bottom:10px;display:block;"><br>
      <button type="submit" style="padding:10px 20px;background:#0088cc;color:#fff;border:none;cursor:pointer;">Create App</button>
    </form></body></html>`);
});

/* ============================================================ TOKEN ENDPOINT ============================================================ */

app.post("/oauth/token", (req, res) => {
  const { grant_type } = req.body;

  /* ---- Authorization Code + PKCE ---- */
  if (grant_type === "authorization_code" || (!grant_type && req.body.code)) {
    const { code, client_id, client_secret, redirect_uri, code_verifier } = req.body;
    if (!code) return res.status(400).json({ error: "invalid_request", message: "code required" });
    const codes = readJson(AUTH_CODES_FILE);
    const entry = codes.find((c) => c.code === code);
    if (!entry) return res.status(400).json({ error: "invalid_grant" });
    if (entry.used) return res.status(400).json({ error: "invalid_grant", message: "code already used" });
    if (Date.now() > entry.expiresAt) return res.status(400).json({ error: "invalid_grant", message: "code expired" });
    if (redirect_uri && entry.redirect_uri !== redirect_uri)
      return res.status(400).json({ error: "invalid_grant", message: "redirect_uri mismatch" });
    if (client_id && entry.client_id !== client_id)
      return res.status(400).json({ error: "invalid_client" });

    if (!verifyPkce(code_verifier, entry.code_challenge, entry.code_challenge_method))
      return res.status(400).json({ error: "invalid_grant", message: "PKCE verification failed" });

    entry.used = true;
    writeJson(AUTH_CODES_FILE, codes);

    const users = readJson(USERS_FILE);
    const user = users.find((u) => u.username === entry.username);
    if (!user) return res.status(400).json({ error: "invalid_grant" });

    const { token } = issueAccessToken(user, entry.scope, {
      client_id: entry.client_id, grant: "authorization_code",
    });
    const body = {
      access_token: token,
      token_type: "Bearer",
      expires_in: 3600,
      scope: entry.scope,
    };
    if ((entry.scope || "").includes("offline_access")) {
      body.refresh_token = issueRefreshToken(user, entry.scope, entry.client_id);
    }
    if ((entry.scope || "").includes("openid")) {
      body.id_token = jwt.sign(
        { sub: user.username, aud: entry.client_id, iss: baseUrl(req), iat: Math.floor(Date.now() / 1000) },
        OAUTH_SECRET, { expiresIn: "1h" }
      );
    }
    return res.json(body);
  }

  /* ---- Device Code ---- */
  if (grant_type === "urn:ietf:params:oauth:grant-type:device_code" || req.body.device_code) {
    const { device_code, client_id, client_secret } = req.body;
    if (!device_code) return res.status(400).json({ error: "device_code_required" });
    if (client_id) {
      const apps = readJson(APPS_FILE);
      const oauthApp = apps.find((a) => a.client_id === client_id && a.client_secret === client_secret);
      if (!oauthApp) return res.status(401).json({ error: "invalid_client" });
    }
    const device = deviceCodes.get(device_code);
    if (!device) return res.status(400).json({ error: "invalid_device_code" });
    if (Date.now() > device.expiresAt) {
      deviceCodes.delete(device_code);
      return res.status(400).json({ error: "expired_device_code" });
    }
    if (device.status === "pending") return res.status(428).json({ error: "authorization_pending" });
    if (device.status !== "approved") return res.status(400).json({ error: "invalid_device_state" });

    const users = readJson(USERS_FILE);
    const user = users.find((u) => u.username === device.username);
    const { token } = issueAccessToken(user, device.scope, {
      device_code: device.deviceCode, grant: "device_code",
    });
    deviceCodes.delete(device_code);
    return res.json({ access_token: token, token_type: "Bearer", expires_in: 3600, scope: device.scope });
  }

  /* ---- Refresh Token ---- */
  if (grant_type === "refresh_token") {
    const { refresh_token, client_id } = req.body;
    const refresh = readJson(REFRESH_TOKENS_FILE);
    const entry = refresh.find((r) => r.token === refresh_token && !r.revoked);
    if (!entry) return res.status(400).json({ error: "invalid_grant" });
    if (client_id && entry.client_id !== client_id) return res.status(400).json({ error: "invalid_client" });
    const users = readJson(USERS_FILE);
    const user = users.find((u) => u.username === entry.username);
    if (!user) return res.status(400).json({ error: "invalid_grant" });
    const { token } = issueAccessToken(user, entry.scope, { grant: "refresh_token" });
    return res.json({ access_token: token, token_type: "Bearer", expires_in: 3600, scope: entry.scope });
  }

  /* ---- Client Credentials ---- */
  if (grant_type === "client_credentials") {
    const { client_id, client_secret } = req.body;
    const apps = readJson(APPS_FILE);
    const oauthApp = apps.find((a) => a.client_id === client_id && a.client_secret === client_secret);
    if (!oauthApp) return res.status(401).json({ error: "invalid_client" });
    const jti = randomHex(32);
    const token = jwt.sign(
      { sub: oauthApp.client_id, client_id: oauthApp.client_id, scope: "client", jti },
      OAUTH_SECRET, { expiresIn: "1h" }
    );
    const decoded = jwt.decode(token);
    const tokens = readJson(ACCESS_TOKENS_FILE);
    tokens.push({
      jti, token, username: `client:${oauthApp.client_id}`, scope: "client",
      client_id: oauthApp.client_id, issuedAt: new Date().toISOString(),
      expiresAt: new Date(decoded.exp * 1000).toISOString(), revoked: false,
    });
    writeJson(ACCESS_TOKENS_FILE, tokens);
    return res.json({ access_token: token, token_type: "Bearer", expires_in: 3600 });
  }

  return res.status(400).json({ error: "unsupported_grant_type" });
});

/* ============================================================ ACCESS TOKEN LISTING ============================================================ */

app.get("/oauth/token", (req, res) => {
  const tokens = readJson(ACCESS_TOKENS_FILE).map((t) => ({
    jti: t.jti,
    username: t.username,
    client_id: t.client_id,
    scope: t.scope,
    issuedAt: t.issuedAt,
    expiresAt: t.expiresAt,
    revoked: t.revoked || isTokenRevoked(t.jti),
  }));
  res.json({ tokens });
});

app.get("/oauth/token/:jti", (req, res) => {
  const t = readJson(ACCESS_TOKENS_FILE).find((x) => x.jti === req.params.jti);
  if (!t) return res.status(404).json({ error: "token_not_found" });
  res.json({ ...t, revoked: t.revoked || isTokenRevoked(t.jti) });
});

app.delete("/oauth/token/:jti", (req, res) => {
  const t = readJson(ACCESS_TOKENS_FILE).find((x) => x.jti === req.params.jti);
  if (!t) return res.status(404).json({ error: "token_not_found" });
  revokeToken(t.jti, t.expiresAt);
  res.json({ status: "success", revoked: t.jti });
});

/* ============================================================ JWT MIDDLEWARE ============================================================ */

function authenticateJWT(req, res, next) {
  const authorization = req.headers.authorization || "";
  if (!authorization.startsWith("Bearer "))
    return res.status(401).json({ error: "unauthorized", message: "Bearer access token required" });
  const token = authorization.substring(7);
  try {
    const decoded = jwt.verify(token, OAUTH_SECRET);
    if (decoded.jti && isTokenRevoked(decoded.jti))
      return res.status(401).json({ error: "invalid_token", message: "Token has been logged out" });
    req.user = decoded;
    req.accessToken = token;
    next();
  } catch {
    return res.status(401).json({ error: "invalid_token", message: "Invalid or expired access token" });
  }
}

/* ============================================================ LOGOUT ============================================================ */

app.post("/api/auth/logout", authenticateJWT, (req, res) => {
  if (!req.user.jti) return res.status(400).json({ error: "token_missing_jti" });
  revokeToken(req.user.jti, req.user.exp);
  res.json({ status: "success", message: "Logged out successfully" });
});

/* ============================================================ ME / USERINFO ============================================================ */

app.get(["/api/auth/me", "/api/whoami", "/oauth/userinfo"], authenticateJWT, (req, res) => {
  res.json({
    authenticated: true,
    sub: req.user.sub,
    username: req.user.username,
    scope: req.user.scope || "",
    token_type: "Bearer",
  });
});

/* ============================================================ SCOPES ============================================================ */

app.get("/api/auth/scope", (req, res) => {
  res.json({
    scopes: SCOPES_SUPPORTED.map((name) => ({
      name,
      description: {
        openid: "OpenID subject identifier",
        profile: "Basic profile info",
        email: "Email address",
        offline_access: "Issue refresh token",
        "api.connectors.read": "Read connectors",
        "api.connectors.invoke": "Invoke connectors",
      }[name] || name,
    })),
  });
});

/* ============================================================ RESET ============================================================ */

app.post("/api/auth/reset", authenticateJWT, (req, res) => {
  revokeToken(req.user.jti, req.user.exp);
  res.json({ status: "success", message: "Token revoked — re-authenticate to continue." });
});

/* ============================================================ PROJECTS ============================================================ */

function requireProjectName(req, res, next) {
  const name = req.query.project || req.body.project;
  if (!name) return res.status(400).json({ error: "project_name_required" });
  const projects = readJson(PROJECTS_FILE);
  const project = projects.find((p) => p.name === name && p.username === req.user.username);
  if (!project) return res.status(404).json({ error: "project_not_found", project: name });
  req.project = project;
  next();
}

app.post("/api/projects", authenticateJWT, (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: "project_name_required" });
  const projects = readJson(PROJECTS_FILE);
  if (projects.some((p) => p.name === name && p.username === req.user.username))
    return res.status(409).json({ error: "project_already_exists" });
  const project = {
    id: randomHex(16),
    name,
    username: req.user.username,
    ram_mb: req.body.ram_mb || 1024,
    active: false,
    createdAt: new Date().toISOString(),
  };
  projects.push(project);
  writeJson(PROJECTS_FILE, projects);
  res.status(201).json({ status: "success", project });
});

app.get("/api/projects", authenticateJWT, (req, res) => {
  const projects = readJson(PROJECTS_FILE).filter((p) => p.username === req.user.username);
  res.json({ projects });
});

app.get("/api/projects/:name", authenticateJWT, (req, res) => {
  const projects = readJson(PROJECTS_FILE);
  const project = projects.find((p) => p.name === req.params.name && p.username === req.user.username);
  if (!project) return res.status(404).json({ error: "project_not_found" });
  res.json(project);
});

app.delete("/api/projects/:name", authenticateJWT, (req, res) => {
  const projects = readJson(PROJECTS_FILE);
  const idx = projects.findIndex((p) => p.name === req.params.name && p.username === req.user.username);
  if (idx === -1) return res.status(404).json({ error: "project_not_found" });
  const [removed] = projects.splice(idx, 1);
  writeJson(PROJECTS_FILE, projects);
  res.json({ status: "success", deleted: removed.name });
});

app.post("/api/projects/switch/use", authenticateJWT, (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: "project_name_required" });
  const projects = readJson(PROJECTS_FILE);
  let found = false;
  for (const p of projects) {
    if (p.username !== req.user.username) continue;
    p.active = p.name === name;
    if (p.active) found = true;
  }
  if (!found) return res.status(404).json({ error: "no_project_active", message: "Project not found." });
  writeJson(PROJECTS_FILE, projects);
  res.json({ status: "success", active_project: name });
});

/* ============================================================ GET-RAM (project-scoped) ============================================================ */

app.get("/api/get-ram", authenticateJWT, (req, res) => {
  const projectName = req.query.project;
  const projects = readJson(PROJECTS_FILE);

  if (projectName) {
    const project = projects.find((p) => p.name === projectName && p.username === req.user.username);
    if (!project) return res.status(404).json({ error: "project_not_found", project: projectName });
    return res.json({ ram_mb: project.ram_mb, username: req.user.username, project: project.name });
  }

  const active = projects.find((p) => p.username === req.user.username && p.active);
  if (active) {
    return res.json({ ram_mb: active.ram_mb, username: req.user.username, project: active.name });
  }

  return res.json({ ram_mb: 1024, username: req.user.username, project: null });
});

/* ============================================================ OAUTH STATUS ============================================================ */

app.get("/api/oauth/status", authenticateJWT, (req, res) => {
  res.json({ authenticated: true, username: req.user.username, token_type: "Bearer", ram_mb: 1024 });
});

/* ============================================================ API TOKENS ============================================================ */

app.post("/api/api-tokens", authenticateJWT, (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: "token_name_required" });
  const apiTokens = readJson(API_TOKENS_FILE);
  const id = randomHex(16);
  const jti = randomHex(32);
  const token = jwt.sign(
    { sub: req.user.username, username: req.user.username, jti, scope: "api-token", token_name: name },
    OAUTH_SECRET,
    { expiresIn: req.body.expires_in || "30d" }
  );
  apiTokens.push({
    id, name, jti, token, username: req.user.username,
    createdAt: new Date().toISOString(), revoked: false,
  });
  writeJson(API_TOKENS_FILE, apiTokens);
  res.status(201).json({ status: "success", id, name, token });
});

app.get("/api/api-tokens", authenticateJWT, (req, res) => {
  const tokens = readJson(API_TOKENS_FILE)
    .filter((t) => t.username === req.user.username)
    .map(({ token, ...rest }) => rest);
  res.json({ tokens });
});

app.delete("/api/api-tokens/:id", authenticateJWT, (req, res) => {
  const apiTokens = readJson(API_TOKENS_FILE);
  const idx = apiTokens.findIndex((t) => t.id === req.params.id && t.username === req.user.username);
  if (idx === -1) return res.status(404).json({ error: "token_not_found" });
  const [removed] = apiTokens.splice(idx, 1);
  writeJson(API_TOKENS_FILE, apiTokens);
  revokeToken(removed.jti);
  res.json({ status: "success", deleted: removed.id });
});

/* ============================================================ DISCOVERY ============================================================ */

app.get("/.well-known/oauth-authorization-server", (req, res) => {
  const base = baseUrl(req);
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    userinfo_endpoint: `${base}/oauth/userinfo`,
    device_authorization_endpoint: `${base}/oauth/device/code`,
    registration_endpoint: `${base}/oauth/apps`,
    scopes_supported: SCOPES_SUPPORTED,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: [
      "authorization_code", "refresh_token", "client_credentials",
      "urn:ietf:params:oauth:grant-type:device_code",
    ],
    code_challenge_methods_supported: ["S256", "plain"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
    service_documentation: `${base}/`,
  });
});

app.get("/.well-known/openid-configuration", (req, res) => {
  const base = baseUrl(req);
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    userinfo_endpoint: `${base}/oauth/userinfo`,
    jwks_uri: `${base}/.well-known/jwks.json`,
    device_authorization_endpoint: `${base}/oauth/device/code`,
    registration_endpoint: `${base}/oauth/apps`,
    scopes_supported: SCOPES_SUPPORTED,
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["HS256"],
    code_challenge_methods_supported: ["S256", "plain"],
    grant_types_supported: [
      "authorization_code", "refresh_token", "client_credentials",
      "urn:ietf:params:oauth:grant-type:device_code",
    ],
  });
});

app.get("/.well-known/jwks.json", (req, res) => {
  res.json({ keys: [] });
});

/* ============================================================ DASHBOARD ============================================================ */

const dashboardHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OAuth Dashboard</title>
<style>
body { background:#111; color:#00ff66; font-family:monospace; padding:25px; }
.container { max-width:720px; margin:auto; background:#1b1b1b; padding:25px; border-radius:8px; }
h1,h2 { border-bottom:1px solid #333; padding-bottom:8px; }
input,button { width:100%; box-sizing:border-box; padding:12px; margin:6px 0;
  background:#222; color:#fff; border:1px solid #444; font-family:monospace; }
button { background:#0088cc; cursor:pointer; font-weight:bold; }
button:hover { background:#00aaff; }
pre { background:#000; padding:12px; overflow:auto; border:1px solid #333; }
</style>
</head>
<body>
<div class="container">
<h1>OAuth Dashboard</h1>
<p>Paste your access token below to fetch RAM info.</p>
<input id="token" placeholder="Paste access token">
<button onclick="fetchRam()">Fetch RAM</button>
<h2>Result</h2>
<pre id="out">—</pre>
</div>
<script>
async function fetchRam() {
  const token = document.getElementById('token').value.trim();
  const out = document.getElementById('out');
  if (!token) { out.textContent = 'No token provided.'; return; }
  try {
    const res = await fetch('/api/get-ram', { headers: { Authorization: 'Bearer ' + token } });
    const data = await res.json();
    out.textContent = JSON.stringify(data, null, 2);
  } catch (e) {
    out.textContent = 'Error: ' + e.message;
  }
}
</script>
</body>
</html>
`;

app.get(["/dashboard", "/"], (req, res) => res.send(dashboardHtml));

/* ============================================================ HEALTH ============================================================ */

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", service: "oauth-device-server", time: new Date().toISOString() });
});

/* ============================================================ 404 ============================================================ */

app.use((req, res) => res.status(404).json({ error: "not_found" }));

/* ============================================================ START ============================================================ */

app.listen(PORT, "0.0.0.0", () => {
  console.log(`OAuth server running on port ${PORT}`);
  console.log(`Dashboard:   http://localhost:${PORT}/`);
  console.log(`Device login:http://localhost:${PORT}/oauth/device`);
  console.log(`Create App:  http://localhost:${PORT}/create`);
  console.log(`Discovery:   /.well-known/oauth-authorization-server`);
});
