
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const crypto = require("crypto");
const db = require("./database");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.SESSION_SECRET ||
    process.env.SESSION_SECRET.length < 32) {
  throw new Error("Set a SESSION_SECRET of at least 32 characters in .env");
}

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));

app.use(session({
  name: "secure.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
    maxAge: 15 * 60 * 1000
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "Too many attempts. Try again later." }
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

const findUser = db.prepare(
  "SELECT id, username, email, password FROM users WHERE email = ?"
);

const createUser = db.prepare(
  "INSERT INTO users (username, email, password) VALUES (?, ?, ?)"
);

const findEmail = db.prepare(
  "SELECT id FROM users WHERE email = ?"
);

const DUMMY_HASH = bcrypt.hashSync(
  crypto.randomBytes(32).toString("hex"),
  12
);

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Please log in first." });
  }
  next();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function safeEqual(a, b) {
  const first = Buffer.from(a);
  const second = Buffer.from(b);

  return first.length === second.length &&
    crypto.timingSafeEqual(first, second);
}

function requireCsrf(req, res, next) {
  const token = req.get("X-CSRF-Token") || "";
  const expected = req.session.csrfToken || "";

  if (!token || !expected || !safeEqual(token, expected)) {
    return res.status(403).json({ error: "Invalid security token." });
  }

  next();
}

app.get("/api/csrf", (req, res) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }

  res.json({ csrfToken: req.session.csrfToken });
});

app.post("/api/register", registerLimiter, requireCsrf, async (req, res) => {
  try {
    let { username, email, password } = req.body;

    if (
      typeof username !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({ error: "Invalid input." });
    }

    username = username.trim();
    email = email.trim().toLowerCase();

    if (
      username.length < 3 ||
      username.length > 30 ||
      !/^[a-zA-Z0-9_ ]+$/.test(username)
    ) {
      return res.status(400).json({
        error: "Username must be 3–30 characters using letters, numbers, spaces or underscores."
      });
    }

    if (!validEmail(email) || email.length > 254) {
      return res.status(400).json({ error: "Enter a valid email address." });
    }

    if (password.length < 12 || password.length > 72) {
      return res.status(400).json({
        error: "Password must be 12–72 characters long."
      });
    }

    if (findEmail.get(email)) {
      return res.status(409).json({
        error: "Unable to create account with these details."
      });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = createUser.run(username, email, hash);

    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({ error: "Session creation failed." });
      }

      req.session.user = {
        id: result.lastInsertRowid,
        username,
        email
      };

      req.session.csrfToken = crypto.randomBytes(32).toString("hex");

      req.session.save((saveErr) => {
        if (saveErr) {
          return res.status(500).json({ error: "Session saving failed." });
        }

        res.status(201).json({
          message: "Account created successfully.",
          redirect: "/dashboard.html"
        });
      });
    });
  } catch (err) {
    if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({
        error: "Unable to create account with these details."
      });
    }

    console.error("Registration error:", err.message);
    res.status(500).json({ error: "Something went wrong." });
  }
});

app.post("/api/login", loginLimiter, requireCsrf, async (req, res) => {
  try {
    let { email, password } = req.body;

    if (typeof email !== "string" || typeof password !== "string") {
      return res.status(400).json({ error: "Invalid email or password." });
    }

    email = email.trim().toLowerCase();

    if (email.length > 254 || password.length > 72) {
      return res.status(400).json({ error: "Invalid email or password." });
    }

    const user = findUser.get(email);
    const passwordMatches = await bcrypt.compare(
      password,
      user ? user.password : DUMMY_HASH
    );

    if (!user || !passwordMatches) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({ error: "Session creation failed." });
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        email: user.email
      };

      req.session.csrfToken = crypto.randomBytes(32).toString("hex");

      req.session.save((saveErr) => {
        if (saveErr) {
          return res.status(500).json({ error: "Session saving failed." });
        }

        res.json({
          message: "Login successful.",
          redirect: "/dashboard.html"
        });
      });
    });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: "Something went wrong." });
  }
});

app.get("/api/me", requireLogin, (req, res) => {
  res.json({ user: req.session.user });
});

app.post("/api/logout", requireCsrf, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: "Logout failed." });
    }

    res.clearCookie("secure.sid", { httpOnly: true, sameSite: "lax" });
    res.json({ message: "Logged out successfully." });
  });
});

// Serve only known public pages and the stylesheet/script.
const publicFiles = new Set([
  "index.html",
  "register.html",
  "dashboard.html",
  "style.css",
  "script.js"
]);

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/:file", (req, res, next) => {
  if (!publicFiles.has(req.params.file)) {
    return next();
  }

  res.sendFile(path.join(__dirname, "public", req.params.file));
});

// Do not rely on hiding dashboard.html; protect its contents via /api/me.
app.listen(PORT, () => {
  console.log(`Secure Login System running at http://localhost:${PORT}`);
});
