const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "1mb" }));

const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const SESSION_SECRET = process.env.SESSION_SECRET;
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const DATABASE_URL = process.env.DATABASE_URL;

const COOKIE_NAME = "rumble_session";
const STATE_COOKIE_NAME = "rumble_oauth_state";
const SESSION_SECONDS = 24 * 60 * 60;
const DISCORD_API = "https://discord.com/api/v10";

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL ? { rejectUnauthorized: false } : undefined,
  max: 3,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 10000
});

let databaseReadyPromise = null;

function requireEnv() {
  const missing = [];
  if (!CLIENT_ID) missing.push("DISCORD_CLIENT_ID");
  if (!CLIENT_SECRET) missing.push("DISCORD_CLIENT_SECRET");
  if (!REDIRECT_URI) missing.push("DISCORD_REDIRECT_URI");
  if (!SESSION_SECRET) missing.push("SESSION_SECRET");
  if (!BOT_TOKEN) missing.push("DISCORD_BOT_TOKEN");
  if (!DATABASE_URL) missing.push("DATABASE_URL");
  return missing;
}

function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("base64url");
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function encodeSigned(payload) {
  const value = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${value}.${sign(value)}`;
}

function decodeSigned(value) {
  if (!value || !SESSION_SECRET) return null;
  const dot = value.lastIndexOf(".");
  if (dot < 1) return null;
  const data = value.slice(0, dot);
  const signature = value.slice(dot + 1);
  if (!safeEqual(signature, sign(data))) return null;
  try {
    return JSON.parse(Buffer.from(data, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

function parseCookies(req) {
  const result = {};
  const header = req.headers.cookie || "";
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    try {
      result[key] = decodeURIComponent(value);
    } catch {
      result[key] = value;
    }
  }
  return result;
}

function setCookie(res, name, value, maxAge) {
  res.cookie(name, value, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: maxAge * 1000
  });
}

function clearCookie(res, name) {
  res.clearCookie(name, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/"
  });
}

function setSessionCookie(res, session) {
  const payload = {
    sid: session.sid,
    user: session.user,
    expires: session.expires
  };
  setCookie(res, COOKIE_NAME, encodeSigned(payload), SESSION_SECONDS);
}

function readSessionCookie(req) {
  const cookies = parseCookies(req);
  const payload = decodeSigned(cookies[COOKIE_NAME]);
  if (!payload || !payload.sid || !payload.expires || payload.expires < Date.now()) {
    return null;
  }
  return payload;
}

function setStateCookie(res, state) {
  setCookie(res, STATE_COOKIE_NAME, encodeSigned({
    state,
    expires: Date.now() + 10 * 60 * 1000
  }), 600);
}

function readStateCookie(req) {
  const cookies = parseCookies(req);
  const payload = decodeSigned(cookies[STATE_COOKIE_NAME]);
  if (!payload || !payload.state || payload.expires < Date.now()) return null;
  return payload;
}

function encryptionKey() {
  return crypto.scryptSync(SESSION_SECRET, "rumble-system-oauth-v1", 32);
}

function encryptToken(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [
    iv.toString("base64url"),
    tag.toString("base64url"),
    encrypted.toString("base64url")
  ].join(".");
}

function decryptToken(value) {
  const parts = String(value || "").split(".");
  if (parts.length !== 3) throw new Error("Invalid encrypted token");
  const iv = Buffer.from(parts[0], "base64url");
  const tag = Buffer.from(parts[1], "base64url");
  const encrypted = Buffer.from(parts[2], "base64url");
  const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
}

async function ensureDatabase() {
  if (!databaseReadyPromise) {
    databaseReadyPromise = (async () => {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS saved_embeds (
          id BIGSERIAL PRIMARY KEY,
          guild_id TEXT NOT NULL,
          embed_name TEXT NOT NULL,
          embed_data JSONB NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);
      await pool.query(`
        CREATE INDEX IF NOT EXISTS saved_embeds_guild_id_idx
        ON saved_embeds (guild_id)
      `);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS oauth_sessions (
          sid TEXT PRIMARY KEY,
          user_id TEXT NOT NULL,
          user_data JSONB NOT NULL,
          access_token TEXT NOT NULL,
          refresh_token TEXT NOT NULL,
          token_expires_at BIGINT NOT NULL,
          expires_at BIGINT NOT NULL,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);
      await pool.query(`
        CREATE INDEX IF NOT EXISTS oauth_sessions_expires_at_idx
        ON oauth_sessions (expires_at)
      `);
    })().catch(error => {
      databaseReadyPromise = null;
      throw error;
    });
  }
  return databaseReadyPromise;
}

async function discordRequest(path, options = {}) {
  const response = await fetch(`${DISCORD_API}${path}`, {
    ...options,
    headers: {
      ...(options.headers || {}),
      "Content-Type": "application/json"
    }
  });
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { message: text };
  }
  return { response, data };
}

async function refreshOAuthTokens(refreshToken) {
  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    redirect_uri: REDIRECT_URI
  });

  const response = await fetch(`${DISCORD_API}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token || !data.refresh_token) {
    const error = new Error("Discord session refresh failed");
    error.status = response.status;
    throw error;
  }
  return data;
}

/*
 * The PostgreSQL row lock serializes refreshes across Vercel instances.
 * The lock is held only for this one user's session row.
 */
async function getValidSession(req, res, forceRefresh = false) {
  const cookie = readSessionCookie(req);
  if (!cookie) return null;

  await ensureDatabase();
  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    const result = await client.query(
      `SELECT sid, user_id, user_data, access_token, refresh_token,
              token_expires_at, expires_at
       FROM oauth_sessions
       WHERE sid = $1
       FOR UPDATE`,
      [cookie.sid]
    );

    if (!result.rows.length) {
      await client.query("COMMIT");
      clearCookie(res, COOKIE_NAME);
      return null;
    }

    const row = result.rows[0];
    if (Number(row.expires_at) < Date.now()) {
      await client.query("DELETE FROM oauth_sessions WHERE sid = $1", [cookie.sid]);
      await client.query("COMMIT");
      clearCookie(res, COOKIE_NAME);
      return null;
    }

    let accessToken = decryptToken(row.access_token);
    let tokenExpiresAt = Number(row.token_expires_at);

    if (forceRefresh || tokenExpiresAt <= Date.now() + 90 * 1000) {
      const refreshToken = decryptToken(row.refresh_token);
      try {
        const refreshed = await refreshOAuthTokens(refreshToken);
        accessToken = refreshed.access_token;
        tokenExpiresAt = Date.now() + Number(refreshed.expires_in || 3600) * 1000;

        await client.query(
          `UPDATE oauth_sessions
           SET access_token = $1,
               refresh_token = $2,
               token_expires_at = $3,
               updated_at = NOW()
           WHERE sid = $4`,
          [
            encryptToken(refreshed.access_token),
            encryptToken(refreshed.refresh_token),
            tokenExpiresAt,
            cookie.sid
          ]
        );
      } catch (error) {
        await client.query("DELETE FROM oauth_sessions WHERE sid = $1", [cookie.sid]);
        await client.query("COMMIT");
        clearCookie(res, COOKIE_NAME);
        return null;
      }
    }

    const session = {
      sid: row.sid,
      user: typeof row.user_data === "string" ? JSON.parse(row.user_data) : row.user_data,
      expires: Number(row.expires_at)
    };

    await client.query("COMMIT");
    setSessionCookie(res, session);
    return { ...session, accessToken };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

function canManageGuild(user, guild) {
  if (!user || !guild) return false;
  if (guild.owner) return true;
  try {
    const permissions = BigInt(guild.permissions || "0");
    const ADMINISTRATOR = 0x8n;
    const MANAGE_GUILD = 0x20n;
    return (permissions & ADMINISTRATOR) === ADMINISTRATOR ||
      (permissions & MANAGE_GUILD) === MANAGE_GUILD;
  } catch {
    return false;
  }
}

async function getDiscordGuilds(auth) {
  return discordRequest("/users/@me/guilds", {
    headers: { Authorization: `Bearer ${auth.accessToken}` }
  });
}

async function getGuildAuthorization(req, res, guildId) {
  let auth = await getValidSession(req, res);
  if (!auth) {
    res.status(401).json({ error: "login", message: "Please login with Discord again." });
    return null;
  }

  let guildResult = await getDiscordGuilds(auth);
  if (guildResult.response.status === 401) {
    auth = await getValidSession(req, res, true);
    if (!auth) {
      res.status(401).json({ error: "login", message: "Your Discord session expired. Please login again." });
      return null;
    }
    guildResult = await getDiscordGuilds(auth);
  }

  if (!guildResult.response.ok) {
    res.status(502).json({
      error: "discord_guilds",
      message: "Discord could not return your server list. Please try again."
    });
    return null;
  }

  const userGuild = (guildResult.data || []).find(g => g.id === guildId);
  if (!userGuild || !canManageGuild(auth.user, userGuild)) {
    res.status(403).json({ error: "forbidden", message: "You cannot manage this server." });
    return null;
  }

  const botGuild = await discordRequest(`/guilds/${guildId}`, {
    headers: { Authorization: `Bot ${BOT_TOKEN}` }
  });

  if (botGuild.response.status === 404) {
    res.status(403).json({ error: "bot_missing", message: "The bot is not in this server." });
    return null;
  }
  if (!botGuild.response.ok) {
    res.status(502).json({ error: "bot_check", message: "Could not verify the bot in this server." });
    return null;
  }

  return { auth, userGuild, botGuild: botGuild.data };
}

function validSnowflake(value) {
  return typeof value === "string" && /^\d{15,22}$/.test(value);
}

function validateEmbed(embed) {
  if (!embed || typeof embed !== "object" || Array.isArray(embed)) {
    return "Invalid embed data.";
  }

  const textLength = value => typeof value === "string" ? value.length : 0;
  const title = embed.title || "";
  const description = embed.description || "";
  const footer = embed.footer && embed.footer.text ? embed.footer.text : "";

  if (textLength(title) > 256) return "Embed title must be 256 characters or less.";
  if (textLength(description) > 4096) return "Embed description must be 4096 characters or less.";
  if (textLength(footer) > 2048) return "Embed footer must be 2048 characters or less.";

  if (embed.fields !== undefined && !Array.isArray(embed.fields)) {
    return "Embed fields must be a list.";
  }
  const fields = embed.fields || [];
  if (fields.length > 25) return "An embed can have up to 25 fields.";

  let total = textLength(title) + textLength(description) + textLength(footer);
  for (const field of fields) {
    if (!field || typeof field !== "object") return "Invalid embed field.";
    const name = String(field.name || "");
    const value = String(field.value || "");
    if (!name || !value) return "Each field needs a name and a value.";
    if (name.length > 256) return "Field name must be 256 characters or less.";
    if (value.length > 1024) return "Field value must be 1024 characters or less.";
    total += name.length + value.length;
  }
  if (total > 6000) return "The total text in an embed cannot exceed 6000 characters.";

  for (const key of ["url"]) {
    if (embed[key] && !isHttpUrl(embed[key])) return "Embed URL must start with http:// or https://.";
  }
  for (const key of ["image", "thumbnail"]) {
    if (embed[key] && embed[key].url && !isHttpUrl(embed[key].url)) {
      return "Image URLs must start with http:// or https://.";
    }
  }

  if (embed.color !== undefined &&
      (!Number.isInteger(Number(embed.color)) || Number(embed.color) < 0 || Number(embed.color) > 0xffffff)) {
    return "Invalid embed color.";
  }
  return null;
}

function isHttpUrl(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function normalizeEmbedBody(body) {
  const name = String(body.embed_name || body.name || "Untitled Embed").trim().slice(0, 100);
  const data = body.embed_data || body.embed || body.data;
  return { name: name || "Untitled Embed", data };
}

app.get("/api/health", async (req, res) => {
  try {
    await ensureDatabase();
    await pool.query("SELECT 1");
    res.json({ ok: true, service: "Rumble System API" });
  } catch (error) {
    console.error("Health check failed:", error);
    res.status(503).json({ ok: false, error: "database_unavailable" });
  }
});

app.get("/auth/discord", (req, res) => {
  const missing = requireEnv();
  if (missing.length) {
    return res.status(500).send("Server configuration is incomplete.");
  }

  const state = crypto.randomBytes(24).toString("hex");
  setStateCookie(res, state);

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "identify guilds",
    state
  });

  res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
});

app.get("/auth/discord/callback", async (req, res) => {
  clearCookie(res, STATE_COOKIE_NAME);

  try {
    const stateCookie = readStateCookie(req);
    const code = req.query.code;
    const state = req.query.state;

    if (!stateCookie || !code || !state || !safeEqual(stateCookie.state, String(state))) {
      return res.redirect("/?login=failed");
    }

    const body = new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: "authorization_code",
      code: String(code),
      redirect_uri: REDIRECT_URI
    });

    const tokenResponse = await fetch(`${DISCORD_API}/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });
    const tokens = await tokenResponse.json().catch(() => ({}));
    if (!tokenResponse.ok || !tokens.access_token || !tokens.refresh_token) {
      console.error("Discord OAuth token exchange failed:", tokenResponse.status);
      return res.redirect("/?login=failed");
    }

    const meResult = await discordRequest("/users/@me", {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });
    if (!meResult.response.ok || !meResult.data || !meResult.data.id) {
      return res.redirect("/?login=failed");
    }

    await ensureDatabase();

    const user = {
      id: meResult.data.id,
      username: meResult.data.username,
      global_name: meResult.data.global_name || meResult.data.username,
      avatar: meResult.data.avatar || null
    };

    const sid = crypto.randomBytes(32).toString("base64url");
    const expires = Date.now() + SESSION_SECONDS * 1000;
    const tokenExpiresAt = Date.now() + Number(tokens.expires_in || 3600) * 1000;

    await pool.query(
      `INSERT INTO oauth_sessions
       (sid, user_id, user_data, access_token, refresh_token, token_expires_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        sid,
        user.id,
        JSON.stringify(user),
        encryptToken(tokens.access_token),
        encryptToken(tokens.refresh_token),
        tokenExpiresAt,
        expires
      ]
    );

    setSessionCookie(res, { sid, user, expires });
    res.redirect("/");
  } catch (error) {
    console.error("OAuth callback failed:", error);
    res.redirect("/?login=failed");
  }
});

app.get("/api/me", async (req, res) => {
  try {
    const cookie = readSessionCookie(req);
    if (!cookie) return res.json({ loggedIn: false, user: null });

    await ensureDatabase();
    const result = await pool.query(
      `SELECT user_data, expires_at FROM oauth_sessions WHERE sid = $1`,
      [cookie.sid]
    );
    if (!result.rows.length || Number(result.rows[0].expires_at) < Date.now()) {
      clearCookie(res, COOKIE_NAME);
      return res.json({ loggedIn: false, user: null });
    }

    const user = typeof result.rows[0].user_data === "string"
      ? JSON.parse(result.rows[0].user_data)
      : result.rows[0].user_data;

    res.json({ loggedIn: true, user });
  } catch (error) {
    console.error("/api/me failed:", error);
    res.status(503).json({ loggedIn: false, error: "session_check_failed" });
  }
});

app.get("/api/guilds", async (req, res) => {
  try {
    let auth = await getValidSession(req, res);
    if (!auth) return res.status(401).json({ error: "login", message: "Please login with Discord." });

    let result = await getDiscordGuilds(auth);
    if (result.response.status === 401) {
      auth = await getValidSession(req, res, true);
      if (!auth) return res.status(401).json({ error: "login", message: "Please login again." });
      result = await getDiscordGuilds(auth);
    }

    if (!result.response.ok) {
      return res.status(502).json({ error: "discord_guilds", message: "Discord server list is temporarily unavailable." });
    }

    const manageable = (result.data || []).filter(g => canManageGuild(auth.user, g));
    const checked = await Promise.all(manageable.map(async guild => {
      const bot = await discordRequest(`/guilds/${guild.id}`, {
        headers: { Authorization: `Bot ${BOT_TOKEN}` }
      });
      return bot.response.ok ? {
        id: guild.id,
        name: guild.name,
        icon: guild.icon,
        owner: guild.owner,
        permissions: guild.permissions,
        botPresent: true
      } : null;
    }));

    res.json({ guilds: checked.filter(Boolean) });
  } catch (error) {
    console.error("/api/guilds failed:", error);
    res.status(500).json({ error: "server_error", message: "Could not load servers." });
  }
});

app.get("/api/guilds/:guildId/channels", async (req, res) => {
  const { guildId } = req.params;
  if (!validSnowflake(guildId)) return res.status(400).json({ error: "invalid_guild_id" });

  try {
    const access = await getGuildAuthorization(req, res, guildId);
    if (!access) return;

    await ensureDatabase();
    const saved = await pool.query(
      `SELECT embed_data FROM saved_embeds WHERE id = $1 AND guild_id = $2`,
      [embedId, guildId]
    );
    if (!saved.rows.length) return res.status(404).json({ error: "embed_not_found" });

    const channelResult = await discordRequest(`/guilds/${guildId}/channels`, {
      headers: { Authorization: `Bot ${BOT_TOKEN}` }
    });
    if (!channelResult.response.ok) {
      return res.status(502).json({ error: "channel_check_failed", message: "Could not verify the selected channel." });
    }

    const channel = (channelResult.data || []).find(item => item.id === channelId);
    if (!channel || (channel.type !== 0 && channel.type !== 5)) {
      return res.status(400).json({ error: "invalid_channel", message: "The selected channel is not a supported text channel." });
    }

    const embedData = typeof saved.rows[0].embed_data === "string"
      ? JSON.parse(saved.rows[0].embed_data)
      : saved.rows[0].embed_data;

    const validationError = validateEmbed(embedData);
    if (validationError) return res.status(400).json({ error: "invalid_embed", message: validationError });

    const sendResult = await discordRequest(`/channels/${channelId}/messages`, {
      method: "POST",
      headers: { Authorization: `Bot ${BOT_TOKEN}` },
      body: JSON.stringify({ embeds: [embedData] })
    });

    if (!sendResult.response.ok) {
      console.error("Discord send embed failed:", sendResult.response.status, sendResult.data);
      return res.status(502).json({
        error: "discord_send_failed",
        message: sendResult.data && sendResult.data.message
          ? `Discord rejected the message: ${sendResult.data.message}`
          : "Discord could not send the embed."
      });
    }

    res.json({ success: true, messageId: sendResult.data && sendResult.data.id });
  } catch (error) {
    console.error("Send embed failed:", error);
    res.status(500).json({ error: "server_error", message: "Could not send embed." });
  }
});

app.use("/api", (req, res) => {
  res.status(404).json({ error: "not_found" });
});

app.use(express.static("public"));

app.get("*", (req, res) => {
  res.sendFile(require("path").join(process.cwd(), "public", "index.html"));
});

app.use((error, req, res, next) => {
  console.error("Unhandled server error:", error);
  if (res.headersSent) return next(error);
  res.status(500).json({ error: "server_error", message: "An unexpected server error occurred." });
});

module.exports = app;
