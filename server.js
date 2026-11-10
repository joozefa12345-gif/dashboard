const express = require("express");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");

const app = express();

app.set("trust proxy", 1);
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const SESSION_SECRET = process.env.SESSION_SECRET;
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;

const COOKIE_NAME = "rumble_session";

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 3,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
});

const DISCORD_API = "https://discord.com/api/v10";

function sign(value) {
    return crypto
        .createHmac("sha256", SESSION_SECRET)
        .update(value)
        .digest("base64url");
}

function encryptToken(value) {
    const key = crypto.scryptSync(SESSION_SECRET, "rumble-salt", 32);
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

    const encrypted = Buffer.concat([
        cipher.update(value, "utf8"),
        cipher.final()
    ]);

    return [
        iv.toString("base64url"),
        cipher.getAuthTag().toString("base64url"),
        encrypted.toString("base64url")
    ].join(".");
}

function decryptToken(value) {
    const [iv, tag, encrypted] = value.split(".");
    const key = crypto.scryptSync(SESSION_SECRET, "rumble-salt", 32);

    const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        key,
        Buffer.from(iv, "base64url")
    );

    decipher.setAuthTag(Buffer.from(tag, "base64url"));

    return Buffer.concat([
        decipher.update(Buffer.from(encrypted, "base64url")),
        decipher.final()
    ]).toString("utf8");
}

function createCookie(payload) {
    const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
    return data + "." + sign(data);
}

function readCookie(req) {
    try {
        const cookies = (req.headers.cookie || "").split(";").reduce(
            (obj, item) => {
                const index = item.indexOf("=");

                if (index > -1) {
                    obj[item.slice(0, index).trim()] =
                        item.slice(index + 1).trim();
                }

                return obj;
            },
            {}
        );

        const value = cookies[COOKIE_NAME];
        if (!value) return null;

        const [data, signature] = value.split(".");
        if (!data || !signature) return null;

        const expected = sign(data);

        const a = Buffer.from(signature);
        const b = Buffer.from(expected);

        if (
            a.length !== b.length ||
            !crypto.timingSafeEqual(a, b)
        ) {
            return null;
        }

        const payload = JSON.parse(
            Buffer.from(data, "base64url").toString()
        );

        if (!payload.expires || payload.expires < Date.now()) {
            return null;
        }

        return payload;
    } catch {
        return null;
    }
}

function setSessionCookie(res, payload) {
    res.setHeader(
        "Set-Cookie",
        `${COOKIE_NAME}=${createCookie(payload)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`
    );
}

function clearSessionCookie(res) {
    res.setHeader(
        "Set-Cookie",
        `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
    );
}

async function discordFetch(url, options = {}) {
    return fetch(`${DISCORD_API}${url}`, options);
}

async function getValidSession(req, res) {
    const session = readCookie(req);

    if (!session?.user || !session.accessToken) {
        return null;
    }

    if (session.tokenExpiresAt <= Date.now() + 60000) {
        if (!session.refreshToken) return null;

        const refreshToken = decryptToken(session.refreshToken);

        const response = await discordFetch("/oauth2/token", {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                grant_type: "refresh_token",
                refresh_token: refreshToken
            })
        });

        const refreshed = await response.json();

        if (!response.ok || !refreshed.access_token) {
            return null;
        }

        session.accessToken = encryptToken(refreshed.access_token);
        session.refreshToken = encryptToken(refreshed.refresh_token);
        session.tokenExpiresAt =
            Date.now() + refreshed.expires_in * 1000;

        setSessionCookie(res, session);
    }

    return {
        session,
        accessToken: decryptToken(session.accessToken)
    };
}

function canManageGuild(guild) {
    const permissions = BigInt(guild.permissions || "0");

    return (
        guild.owner === true ||
        (permissions & 0x20n) === 0x20n ||
        (permissions & 0x8n) === 0x8n
    );
}

async function verifyGuild(req, res, guildId) {
    const auth = await getValidSession(req, res);

    if (!auth) {
        res.status(401).json({ error: "Please login again." });
        return null;
    }

    if (!BOT_TOKEN) {
        res.status(500).json({ error: "Bot token is not configured." });
        return null;
    }

    const userGuildResponse = await discordFetch("/users/@me/guilds", {
        headers: {
            Authorization: `Bearer ${auth.accessToken}`
        }
    });

    if (!userGuildResponse.ok) {
        res.status(401).json({ error: "Could not load your servers." });
        return null;
    }

    const userGuilds = await userGuildResponse.json();

    const guild = userGuilds.find(
        item => item.id === guildId
    );

    if (!guild || !canManageGuild(guild)) {
        res.status(403).json({
            error: "You do not have permission to manage this server."
        });
        return null;
    }

    const botResponse = await discordFetch(`/guilds/${guildId}`, {
        headers: {
            Authorization: `Bot ${BOT_TOKEN}`
        }
    });

    if (!botResponse.ok) {
        res.status(404).json({
            error: "Rumble System bot is not in this server."
        });
        return null;
    }

    return {
        user: auth.session.user,
        guild
    };
}

function validateEmbed(embed) {
    if (!embed || typeof embed !== "object" || Array.isArray(embed)) {
        return "Invalid embed data.";
    }

    const title = embed.title || "";
    const description = embed.description || "";
    const footer = embed.footer?.text || "";

    if (title.length > 256) return "Title is too long.";
    if (description.length > 4096) return "Description is too long.";
    if (footer.length > 2048) return "Footer is too long.";

    if (embed.fields !== undefined) {
        if (!Array.isArray(embed.fields) || embed.fields.length > 25) {
            return "Invalid fields.";
        }

        for (const field of embed.fields) {
            if (
                typeof field.name !== "string" ||
                typeof field.value !== "string" ||
                field.name.length < 1 ||
                field.name.length > 256 ||
                field.value.length < 1 ||
                field.value.length > 1024
            ) {
                return "Invalid embed field.";
            }
        }
    }

    return null;
}

async function ensureDatabase() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS saved_embeds (
            id BIGSERIAL PRIMARY KEY,
            guild_id TEXT NOT NULL,
            embed_name TEXT NOT NULL DEFAULT 'Untitled Embed',
            embed_data JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_saved_embeds_guild_id
        ON saved_embeds (guild_id)
    `);
}

// Health

app.get("/api/health", async (req, res) => {
    try {
        await pool.query("SELECT 1");

        res.json({
            status: "online",
            database: "connected",
            system: "Rumble System"
        });
    } catch (error) {
        console.error("Health check error:", error);

        res.status(503).json({
            status: "online",
            database: "disconnected",
            system: "Rumble System"
        });
    }
});

// Discord login

app.get("/auth/discord", (req, res) => {
    if (!CLIENT_ID || !REDIRECT_URI || !SESSION_SECRET) {
        return res.status(500).send(
            "Discord OAuth is not configured."
        );
    }

    const state = crypto.randomBytes(32).toString("hex");

    setSessionCookie(res, {
        state,
        expires: Date.now() + 10 * 60 * 1000
    });

    const params = new URLSearchParams({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        response_type: "code",
        scope: "identify guilds",
        state
    });

    res.redirect(
        "https://discord.com/oauth2/authorize?" + params.toString()
    );
});

app.get("/auth/discord/callback", async (req, res) => {
    try {
        const session = readCookie(req);
        const code = req.query.code;
        const state = req.query.state;

        if (!session || !state || session.state !== state) {
            clearSessionCookie(res);
            return res.status(403).send("Invalid OAuth state.");
        }

        if (!code || !CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI) {
            return res.status(400).send(
                "Missing OAuth information."
            );
        }

        const tokenResponse = await discordFetch("/oauth2/token", {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                grant_type: "authorization_code",
                code,
                redirect_uri: REDIRECT_URI
            })
        });

        const tokens = await tokenResponse.json();

        if (!tokenResponse.ok || !tokens.access_token) {
            clearSessionCookie(res);
            return res.status(401).send("Discord login failed.");
        }

        const userResponse = await discordFetch("/users/@me", {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`
            }
        });

        const user = await userResponse.json();

        if (!userResponse.ok) {
            clearSessionCookie(res);
            return res.status(401).send(
                "Could not get Discord user."
            );
        }

        setSessionCookie(res, {
            user: {
                id: user.id,
                username: user.username,
                global_name: user.global_name,
                avatar: user.avatar
            },
            accessToken: encryptToken(tokens.access_token),
            refreshToken: encryptToken(tokens.refresh_token),
            tokenExpiresAt:
                Date.now() + (tokens.expires_in || 3600) * 1000,
            expires: Date.now() + 24 * 60 * 60 * 1000
        });

        res.redirect("/");
    } catch (error) {
        console.error("Discord login error:", error);
        clearSessionCookie(res);
        res.status(500).send(
            "An error occurred during login."
        );
    }
});

// Current user

app.get("/api/me", (req, res) => {
    const session = readCookie(req);

    res.json({
        loggedIn: !!session?.user,
        user: session?.user || null
    });
});

// User servers

app.get("/api/guilds", async (req, res) => {
    try {
        const auth = await getValidSession(req, res);

        if (!auth) {
            return res.status(401).json({
                error: "Please login again."
            });
        }

        if (!BOT_TOKEN) {
            return res.status(500).json({
                error: "Bot token is not configured."
            });
        }

        const response = await discordFetch("/users/@me/guilds", {
            headers: {
                Authorization: `Bearer ${auth.accessToken}`
            }
        });

        if (!response.ok) {
            return res.status(401).json({
                error: "Could not load your servers."
            });
        }

        const userGuilds = await response.json();
        const result = [];

        for (const guild of userGuilds) {
            if (!canManageGuild(guild)) continue;

            const botResponse = await discordFetch(
                `/guilds/${guild.id}`,
                {
                    headers: {
                        Authorization: `Bot ${BOT_TOKEN}`
                    }
                }
            );

            if (botResponse.ok) {
                result.push({
                    id: guild.id,
                    name: guild.name,
                    icon: guild.icon,
                    owner: guild.owner
                });
            }
        }

        res.json({ guilds: result });

    } catch (error) {
        console.error("Guilds API error:", error);

        res.status(500).json({
            error: "Could not load servers."
        });
    }
});

// Get server channels

app.get("/api/guilds/:guildId/channels", async (req, res) => {
    try {
        const { guildId } = req.params;

        const access = await verifyGuild(req, res, guildId);
        if (!access) return;

        const response = await discordFetch(
            `/guilds/${guildId}/channels`,
            {
                headers: {
                    Authorization: `Bot ${BOT_TOKEN}`
                }
            }
        );

        if (!response.ok) {
            return res.status(response.status).json({
                error: "Could not load server channels."
            });
        }

        const channels = await response.json();

        const result = channels
            .filter(channel => [0, 5].includes(channel.type))
            .map(channel => ({
                id: channel.id,
                name: channel.name,
                type: channel.type,
                parent_id: channel.parent_id
            }));

        res.json({ channels: result });

    } catch (error) {
        console.error("Channels API error:", error);

        res.status(500).json({
            error: "Could not load channels."
        });
    }
});

// Get saved embeds

app.get("/api/guilds/:guildId/embeds", async (req, res) => {
    try {
        const { guildId } = req.params;

        const access = await verifyGuild(req, res, guildId);
        if (!access) return;

        await ensureDatabase();

        const result = await pool.query(
            `SELECT id, embed_name, embed_data, created_at, updated_at
             FROM saved_embeds
             WHERE guild_id = $1
             ORDER BY updated_at DESC`,
            [guildId]
        );

        res.json({ embeds: result.rows });

    } catch (error) {
        console.error("Get embeds error:", error);

        res.status(500).json({
            error: "Could not load saved embeds."
        });
    }
});

// Save a new embed

app.post("/api/guilds/:guildId/embeds", async (req, res) => {
    try {
        const { guildId } = req.params;

        const access = await verifyGuild(req, res, guildId);
        if (!access) return;

        const { name, embed } = req.body;

        const validationError = validateEmbed(embed);

        if (validationError) {
            return res.status(400).json({
                error: validationError
            });
        }

        const embedName =
            typeof name === "string" && name.trim()
                ? name.trim().slice(0, 100)
                : "Untitled Embed";

        await ensureDatabase();

        const result = await pool.query(
            `INSERT INTO saved_embeds
                (guild_id, embed_name, embed_data)
             VALUES ($1, $2, $3)
             RETURNING id, embed_name, embed_data, created_at, updated_at`,
            [guildId, embedName, JSON.stringify(embed)]
        );

        res.status(201).json({
            success: true,
            embed: result.rows[0]
        });

    } catch (error) {
        console.error("Save embed error:", error);

        res.status(500).json({
            error: "Could not save embed."
        });
    }
});

// Update an embed

app.put("/api/guilds/:guildId/embeds/:embedId", async (req, res) => {
    try {
        const { guildId, embedId } = req.params;

        const access = await verifyGuild(req, res, guildId);
        if (!access) return;

        const { name, embed } = req.body;

        const validationError = validateEmbed(embed);

        if (validationError) {
            return res.status(400).json({
                error: validationError
            });
        }

        const embedName =
            typeof name === "string" && name.trim()
                ? name.trim().slice(0, 100)
                : "Untitled Embed";

        await ensureDatabase();

        const result = await pool.query(
            `UPDATE saved_embeds
             SET embed_name = $1,
                 embed_data = $2,
                 updated_at = NOW()
             WHERE id = $3 AND guild_id = $4
             RETURNING id, embed_name, embed_data, created_at, updated_at`,
            [
                embedName,
                JSON.stringify(embed),
                embedId,
                guildId
            ]
        );

        if (!result.rowCount) {
            return res.status(404).json({
                error: "Embed not found."
            });
        }

        res.json({
            success: true,
            embed: result.rows[0]
        });

    } catch (error) {
        console.error("Update embed error:", error);

        res.status(500).json({
            error: "Could not update embed."
        });
    }
});

// Delete an embed

app.delete("/api/guilds/:guildId/embeds/:embedId", async (req, res) => {
    try {
        const { guildId, embedId } = req.params;

        const access = await verifyGuild(req, res, guildId);
        if (!access) return;

        await ensureDatabase();

        const result = await pool.query(
            `DELETE FROM saved_embeds
             WHERE id = $1 AND guild_id = $2`,
            [embedId, guildId]
        );

        if (!result.rowCount) {
            return res.status(404).json({
                error: "Embed not found."
            });
        }

        res.json({ success: true });

    } catch (error) {
        console.error("Delete embed error:", error);

        res.status(500).json({
            error: "Could not delete embed."
        });
    }
});

// Send an embed to Discord

app.post(
    "/api/guilds/:guildId/embeds/:embedId/send",
    async (req, res) => {
        try {
            const { guildId, embedId } = req.params;
            const { channelId } = req.body;

            const access = await verifyGuild(req, res, guildId);
            if (!access) return;

            if (!channelId) {
                return res.status(400).json({
                    error: "Channel ID is required."
                });
            }

            await ensureDatabase();

            const saved = await pool.query(
                `SELECT embed_data
                 FROM saved_embeds
                 WHERE id = $1 AND guild_id = $2`,
                [embedId, guildId]
            );

            if (!saved.rowCount) {
                return res.status(404).json({
                    error: "Embed not found."
                });
            }

            const channelResponse = await discordFetch(
                `/guilds/${guildId}/channels`,
                {
                    headers: {
