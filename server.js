const express = require("express");
const crypto = require("crypto");
const path = require("path");
const app = express();

app.set("trust proxy", 1);
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));;
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const SESSION_SECRET = process.env.SESSION_SECRET;

const COOKIE_NAME = "rumble_session";

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

    const tag = cipher.getAuthTag();

    return [
        iv.toString("base64url"),
        tag.toString("base64url"),
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
        const cookies = (req.headers.cookie || "").split(";").reduce((obj, item) => {
            const index = item.indexOf("=");
            if (index > -1) {
                obj[item.slice(0, index).trim()] =
                    item.slice(index + 1).trim();
            }
            return obj;
        }, {});

        const value = cookies[COOKIE_NAME];
        if (!value) return null;

        const [data, signature] = value.split(".");
        if (!data || !signature) return null;

        const expected = sign(data);

        const a = Buffer.from(signature);
        const b = Buffer.from(expected);

        if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
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
    res.setHeader("Set-Cookie",
        `${COOKIE_NAME}=${createCookie(payload)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`
    );
}

function clearSessionCookie(res) {
    res.setHeader("Set-Cookie",
        `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
    );
}

app.get("/api/health", (req, res) => {
    res.json({
        status: "online",
        system: "Rumble System"
    });
});

app.get("/auth/discord", (req, res) => {
    if (!CLIENT_ID || !REDIRECT_URI || !SESSION_SECRET) {
        return res.status(500).send("Discord OAuth is not configured.");
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

    res.redirect("https://discord.com/oauth2/authorize?" + params.toString());
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
            return res.status(400).send("Missing OAuth information.");
        }

        const tokenResponse = await fetch(
            "https://discord.com/api/oauth2/token",
            {
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
            }
        );

        const tokens = await tokenResponse.json();

        if (!tokenResponse.ok || !tokens.access_token) {
            clearSessionCookie(res);
            return res.status(401).send("Discord login failed.");
        }

        const userResponse = await fetch(
            "https://discord.com/api/users/@me",
            {
                headers: {
                    Authorization: `Bearer ${tokens.access_token}`
                }
            }
        );

        const user = await userResponse.json();

        if (!userResponse.ok) {
            clearSessionCookie(res);
            return res.status(401).send("Could not get Discord user.");
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
tokenExpiresAt: Date.now() + (tokens.expires_in || 3600) * 1000,
            expires: Date.now() + 24 * 60 * 60 * 1000
        });

        res.redirect("/");
    } catch (error) {
        console.error("Discord login error:", error);
        clearSessionCookie(res);
        res.status(500).send("An error occurred during login.");
    }
});

app.get("/api/me", (req, res) => {
    const session = readCookie(req);

    res.json({
        loggedIn: !!session?.user,
        user: session?.user || null
    });
});
app.get("/api/guilds", async (req, res) => {
    try {
        const session = readCookie(req);

        if (!session?.user || !session.accessToken) {
            return res.status(401).json({
                error: "Please login again."
            });
        }

        if (!process.env.DISCORD_BOT_TOKEN) {
            return res.status(500).json({
                error: "Bot token is not configured."
            });
        }

        let accessToken = decryptToken(session.accessToken);

        if (session.tokenExpiresAt <= Date.now() + 60000) {
            const refreshToken = decryptToken(session.refreshToken);

            const refreshResponse = await fetch(
                "https://discord.com/api/oauth2/token",
                {
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
                }
            );

            const refreshed = await refreshResponse.json();

            if (!refreshResponse.ok) {
                return res.status(401).json({
                    error: "Please login again."
                });
            }

            accessToken = refreshed.access_token;

            session.accessToken = encryptToken(refreshed.access_token);
            session.refreshToken = encryptToken(refreshed.refresh_token);
            session.tokenExpiresAt =
                Date.now() + refreshed.expires_in * 1000;

            setSessionCookie(res, session);
        }

        const userResponse = await fetch(
            "https://discord.com/api/users/@me/guilds",
            {
                headers: {
                    Authorization: `Bearer ${accessToken}`
                }
            }
        );

        if (!userResponse.ok) {
            return res.status(401).json({
                error: "Could not load your servers."
            });
        }

        const userGuilds = await userResponse.json();
        const botToken = process.env.DISCORD_BOT_TOKEN;
        const result = [];

        for (const guild of userGuilds) {
            const permissions = BigInt(guild.permissions || "0");
            const canManage =
    guild.owner ||
    (permissions & 0x20n) === 0x20n ||
    (permissions & 0x8n) === 0x8n;0x20n;

            if (!canManage) continue;

            const botResponse = await fetch(
                `https://discord.com/api/guilds/${guild.id}`,
                {
                    headers: {
                        Authorization: `Bot ${botToken}`
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
app.post("/api/logout", (req, res) => {
    clearSessionCookie(res);
    res.json({ success: true });
});

module.exports = app;
