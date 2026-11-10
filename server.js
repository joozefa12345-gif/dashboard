const express = require("express");
const session = require("express-session");
const path = require("path");

const app = express();

app.set("trust proxy", 1);
app.use(express.json());

app.use(session({
    secret: process.env.SESSION_SECRET || "change-this-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: "auto",
        sameSite: "lax",
        maxAge: 24 * 60 * 60 * 1000
    }
}));

const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;

app.use(express.static(__dirname));

app.get("/api/health", (req, res) => {
    res.json({ status: "online", system: "Rumble System" });
});

app.get("/auth/discord", (req, res) => {
    if (!CLIENT_ID || !REDIRECT_URI) {
        return res.status(500).send("Discord OAuth is not configured.");
    }

    const params = new URLSearchParams({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        response_type: "code",
        scope: "identify"
    });

    res.redirect(
        "https://discord.com/oauth2/authorize?" + params.toString()
    );
});

app.get("/auth/discord/callback", async (req, res) => {
    try {
        const code = req.query.code;

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
            return res.status(401).send("Could not get Discord user.");
        }

        req.session.user = {
            id: user.id,
            username: user.username,
            global_name: user.global_name,
            avatar: user.avatar
        };

        res.redirect("/");
    } catch (error) {
        console.error("Discord login error:", error);
        res.status(500).send("An error occurred during login.");
    }
});

app.get("/api/me", (req, res) => {
    res.json({
        loggedIn: !!req.session.user,
        user: req.session.user || null
    });
});

app.post("/api/logout", (req, res) => {
    req.session.destroy(() => {
        res.json({ success: true });
    });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Rumble System API running on port ${PORT}`);
});
