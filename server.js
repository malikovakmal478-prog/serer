import "dotenv/config";

import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import pg from "pg";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";

/* =========================================================
   NOVAIX
   Full Stack Server
   ========================================================= */

const { Pool } = pg;

const app = express();

const PORT = Number(process.env.PORT || 10000);

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "development-secret-change-me";

const ADMIN_EMAIL =
  String(process.env.ADMIN_EMAIL || "")
    .trim()
    .toLowerCase();

const CLIENT_URL =
  process.env.CLIENT_URL || "*";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* =========================================================
   DATABASE
   ========================================================= */

if (!process.env.DATABASE_URL) {
  console.warn(
    "WARNING: DATABASE_URL is not configured."
  );
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,

  ssl: process.env.DATABASE_URL
    ? {
        rejectUnauthorized: false
      }
    : false,

  max: 10,

  idleTimeoutMillis: 30000,

  connectionTimeoutMillis: 10000
});

async function query(text, params = []) {
  const result = await pool.query(text, params);
  return result;
}

async function initializeDatabase() {
  if (!process.env.DATABASE_URL) {
    console.warn(
      "Database initialization skipped because DATABASE_URL is missing."
    );
    return;
  }

  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(30) NOT NULL DEFAULT 'user',
      avatar TEXT,
      bio TEXT DEFAULT '',
      status VARCHAR(30) NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_login TIMESTAMPTZ
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      ip VARCHAR(100),
      user_agent TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(200) NOT NULL,
      message TEXT NOT NULL,
      type VARCHAR(30) DEFAULT 'info',
      read BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS activity_logs (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action VARCHAR(100) NOT NULL,
      details TEXT DEFAULT '',
      ip VARCHAR(100),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS settings (
      key VARCHAR(100) PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);

  await query(`
    CREATE INDEX IF NOT EXISTS users_email_idx
    ON users(email);
  `);

  await query(`
    CREATE INDEX IF NOT EXISTS sessions_user_idx
    ON sessions(user_id);
  `);

  await query(`
    CREATE INDEX IF NOT EXISTS notifications_user_idx
    ON notifications(user_id);
  `);

  await query(`
    CREATE INDEX IF NOT EXISTS activity_user_idx
    ON activity_logs(user_id);
  `);

  console.log("Database initialized.");
}

/* =========================================================
   APP SECURITY
   ========================================================= */

app.set("trust proxy", 1);

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: false
  })
);

app.use(
  cors({
    origin:
      CLIENT_URL === "*"
        ? true
        : CLIENT_URL.split(",")
            .map((x) => x.trim()),
    credentials: true
  })
);

app.use(
  express.json({
    limit: "1mb"
  })
);

app.use(
  express.urlencoded({
    extended: false,
    limit: "1mb"
  })
);

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,

  message: {
    success: false,
    message: "Too many requests. Try again later."
  }
});

app.use("/api", globalLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,

  message: {
    success: false,
    message: "Too many authentication attempts."
  }
});

app.use("/api/auth", authLimiter);

/* =========================================================
   HELPERS
   ========================================================= */

function id() {
  return crypto.randomUUID();
}

function cleanEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

function cleanName(name) {
  return String(name || "")
    .trim()
    .replace(/\s+/g, " ")
    .slice(0, 100);
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    avatar: user.avatar || null,
    bio: user.bio || "",
    status: user.status,
    createdAt: user.created_at,
    lastLogin: user.last_login
  };
}

function signToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function getToken(req) {
  const header = req.headers.authorization;

  if (!header) return null;

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.slice(7);
}

async function createLog(
  userId,
  action,
  details,
  req
) {
  try {
    await query(
      `
      INSERT INTO activity_logs
      (id, user_id, action, details, ip)
      VALUES ($1, $2, $3, $4, $5)
      `,
      [
        id(),
        userId || null,
        action,
        details || "",
        req.ip || ""
      ]
    );
  } catch (error) {
    console.error("Activity log error:", error);
  }
}

async function notify(
  userId,
  title,
  message,
  type = "info"
) {
  try {
    await query(
      `
      INSERT INTO notifications
      (id, user_id, title, message, type)
      VALUES ($1, $2, $3, $4, $5)
      `,
      [
        id(),
        userId,
        title,
        message,
        type
      ]
    );
  } catch (error) {
    console.error("Notification error:", error);
  }
}

/* =========================================================
   AUTH MIDDLEWARE
   ========================================================= */

async function auth(req, res, next) {
  try {
    const token = getToken(req);

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Authentication required."
      });
    }

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    const result = await query(
      `
      SELECT *
      FROM users
      WHERE id = $1
      LIMIT 1
      `,
      [decoded.sub]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        success: false,
        message: "User no longer exists."
      });
    }

    const user = result.rows[0];

    if (user.status !== "active") {
      return res.status(403).json({
        success: false,
        message: "Your account is disabled."
      });
    }

    req.user = user;

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token."
    });
  }
}

function adminOnly(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: "Authentication required."
    });
  }

  if (req.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Administrator access required."
    });
  }

  next();
}

/* =========================================================
   SYSTEM
   ========================================================= */

app.get("/health", async (req, res) => {
  let database = "unknown";

  try {
    await query("SELECT 1");
    database = "connected";
  } catch {
    database = "disconnected";
  }

  res.json({
    success: true,
    name: "NOVAIX",
    status: "online",
    database,
    time: new Date().toISOString(),
    uptime: process.uptime()
  });
});

app.get("/api", (req, res) => {
  res.json({
    success: true,
    name: "NOVAIX API",
    version: "1.0.0",
    endpoints: {
      auth: [
        "POST /api/auth/register",
        "POST /api/auth/login"
      ],
      user: [
        "GET /api/me",
        "PATCH /api/me",
        "GET /api/me/notifications",
        "PATCH /api/me/notifications/:id"
      ],
      admin: [
        "GET /api/admin/stats",
        "GET /api/admin/users",
        "PATCH /api/admin/users/:id/status",
        "PATCH /api/admin/users/:id/role",
        "GET /api/admin/logs"
      ]
    }
  });
});

/* =========================================================
   REGISTER
   ========================================================= */

app.post(
  "/api/auth/register",
  async (req, res) => {
    try {
      const name = cleanName(req.body.name);
      const email = cleanEmail(req.body.email);
      const password = String(
        req.body.password || ""
      );

      if (!name || !email || !password) {
        return res.status(400).json({
          success: false,
          message:
            "Name, email and password are required."
        });
      }

      if (name.length < 2) {
        return res.status(400).json({
          success: false,
          message: "Name is too short."
        });
      }

      if (!validEmail(email)) {
        return res.status(400).json({
          success: false,
          message: "Invalid email address."
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          success: false,
          message:
            "Password must contain at least 8 characters."
        });
      }

      const existing = await query(
        `
        SELECT id
        FROM users
        WHERE email = $1
        LIMIT 1
        `,
        [email]
      );

      if (existing.rows.length) {
        return res.status(409).json({
          success: false,
          message:
            "An account with this email already exists."
        });
      }

      const passwordHash =
        await bcrypt.hash(password, 12);

      const role =
        ADMIN_EMAIL &&
        email === ADMIN_EMAIL
          ? "admin"
          : "user";

      const userId = id();

      const result = await query(
        `
        INSERT INTO users
        (
          id,
          name,
          email,
          password_hash,
          role
        )
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        `,
        [
          userId,
          name,
          email,
          passwordHash,
          role
        ]
      );

      const user = result.rows[0];

      const token = signToken(user);

      await createLog(
        user.id,
        "REGISTER",
        "New account created",
        req
      );

      await notify(
        user.id,
        "Welcome to NOVAIX",
        "Your account has been successfully created.",
        "success"
      );

      return res.status(201).json({
        success: true,
        message: "Account created successfully.",
        token,
        user: publicUser(user)
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        success: false,
        message: "Unable to create account."
      });
    }
  }
);

/* =========================================================
   LOGIN
   ========================================================= */

app.post(
  "/api/auth/login",
  async (req, res) => {
    try {
      const email = cleanEmail(req.body.email);
      const password = String(
        req.body.password || ""
      );

      if (!email || !password) {
        return res.status(400).json({
          success: false,
          message:
            "Email and password are required."
        });
      }

      const result = await query(
        `
        SELECT *
        FROM users
        WHERE email = $1
        LIMIT 1
        `,
        [email]
      );

      if (!result.rows.length) {
        return res.status(401).json({
          success: false,
          message: "Invalid email or password."
        });
      }

      const user = result.rows[0];

      const valid =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!valid) {
        await createLog(
          null,
          "LOGIN_FAILED",
          `Failed login for ${email}`,
          req
        );

        return res.status(401).json({
          success: false,
          message: "Invalid email or password."
        });
      }

      if (user.status !== "active") {
        return res.status(403).json({
          success: false,
          message:
            "This account is currently disabled."
        });
      }

      await query(
        `
        UPDATE users
        SET last_login = NOW(),
            updated_at = NOW()
        WHERE id = $1
        `,
        [user.id]
      );

      await query(
        `
        INSERT INTO sessions
        (
          id,
          user_id,
          ip,
          user_agent
        )
        VALUES ($1, $2, $3, $4)
        `,
        [
          id(),
          user.id,
          req.ip || "",
          req.headers["user-agent"] || ""
        ]
      );

      await createLog(
        user.id,
        "LOGIN",
        "Successful login",
        req
      );

      const updatedUser = {
        ...user,
        last_login: new Date()
      };

      const token =
        signToken(updatedUser);

      return res.json({
        success: true,
        message: "Login successful.",
        token,
        user: publicUser(updatedUser)
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        success: false,
        message: "Login failed."
      });
    }
  }
);

/* =========================================================
   ME
   ========================================================= */

app.get(
  "/api/me",
  auth,
  async (req, res) => {
    res.json({
      success: true,
      user: publicUser(req.user)
    });
  }
);

/* =========================================================
   UPDATE PROFILE
   ========================================================= */

app.patch(
  "/api/me",
  auth,
  async (req, res) => {
    try {
      const name = cleanName(req.body.name);

      const bio = String(
        req.body.bio || ""
      )
        .trim()
        .slice(0, 500);

      if (!name || name.length < 2) {
        return res.status(400).json({
          success: false,
          message: "Please enter a valid name."
        });
      }

      const result = await query(
        `
        UPDATE users
        SET
          name = $1,
          bio = $2,
          updated_at = NOW()
        WHERE id = $3
        RETURNING *
        `,
        [
          name,
          bio,
          req.user.id
        ]
      );

      const user = result.rows[0];

      await createLog(
        user.id,
        "PROFILE_UPDATE",
        "Profile updated",
        req
      );

      res.json({
        success: true,
        message: "Profile updated.",
        user: publicUser(user)
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Could not update profile."
      });
    }
  }
);

/* =========================================================
   NOTIFICATIONS
   ========================================================= */

app.get(
  "/api/me/notifications",
  auth,
  async (req, res) => {
    try {
      const result = await query(
        `
        SELECT
          id,
          title,
          message,
          type,
          read,
          created_at
        FROM notifications
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT 50
        `,
        [req.user.id]
      );

      res.json({
        success: true,
        notifications: result.rows
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Could not load notifications."
      });
    }
  }
);

app.patch(
  "/api/me/notifications/:id",
  auth,
  async (req, res) => {
    try {
      const result = await query(
        `
        UPDATE notifications
        SET read = TRUE
        WHERE id = $1
          AND user_id = $2
        RETURNING *
        `,
        [
          req.params.id,
          req.user.id
        ]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          message: "Notification not found."
        });
      }

      res.json({
        success: true,
        notification:
          result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Could not update notification."
      });
    }
  }
);

/* =========================================================
   ADMIN STATS
   ========================================================= */

app.get(
  "/api/admin/stats",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const users = await query(
        `SELECT COUNT(*)::int AS count FROM users`
      );

      const active = await query(
        `
        SELECT COUNT(*)::int AS count
        FROM users
        WHERE status = 'active'
        `
      );

      const admins = await query(
        `
        SELECT COUNT(*)::int AS count
        FROM users
        WHERE role = 'admin'
        `
      );

      const today = await query(
        `
        SELECT COUNT(*)::int AS count
        FROM users
        WHERE created_at >= CURRENT_DATE
        `
      );

      const sessions = await query(
        `
        SELECT COUNT(*)::int AS count
        FROM sessions
        WHERE last_seen >= NOW() - INTERVAL '30 minutes'
        `
      );

      res.json({
        success: true,
        stats: {
          totalUsers: users.rows[0].count,
          activeUsers: active.rows[0].count,
          admins: admins.rows[0].count,
          newToday: today.rows[0].count,
          onlineSessions:
            sessions.rows[0].count
        }
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Could not load statistics."
      });
    }
  }
);

/* =========================================================
   ADMIN USERS
   ========================================================= */

app.get(
  "/api/admin/users",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const result = await query(
        `
        SELECT
          id,
          name,
          email,
          role,
          status,
          bio,
          created_at,
          last_login
        FROM users
        ORDER BY created_at DESC
        LIMIT 500
        `
      );

      res.json({
        success: true,
        users: result.rows
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Could not load users."
      });
    }
  }
);

/* =========================================================
   ADMIN CHANGE ROLE
   ========================================================= */

app.patch(
  "/api/admin/users/:id/role",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const role =
        req.body.role === "admin"
          ? "admin"
          : "user";

      if (req.params.id === req.user.id) {
        return res.status(400).json({
          success: false,
          message:
            "You cannot change your own role."
        });
      }

      const result = await query(
        `
        UPDATE users
        SET
          role = $1,
          updated_at = NOW()
        WHERE id = $2
        RETURNING id, name, email, role, status
        `,
        [
          role,
          req.params.id
        ]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          message: "User not found."
        });
      }

      await createLog(
        req.user.id,
        "ADMIN_ROLE_CHANGE",
        `Changed ${req.params.id} role to ${role}`,
        req
      );

      res.json({
        success: true,
        message: "Role updated.",
        user: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Could not change role."
      });
    }
  }
);

/* =========================================================
   ADMIN CHANGE STATUS
   ========================================================= */

app.patch(
  "/api/admin/users/:id/status",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const status =
        req.body.status === "disabled"
          ? "disabled"
          : "active";

      if (req.params.id === req.user.id) {
        return res.status(400).json({
          success: false,
          message:
            "You cannot disable yourself."
        });
      }

      const result = await query(
        `
        UPDATE users
        SET
          status = $1,
          updated_at = NOW()
        WHERE id = $2
        RETURNING id, name, email, role, status
        `,
        [
          status,
          req.params.id
        ]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          message: "User not found."
        });
      }

      await createLog(
        req.user.id,
        "ADMIN_STATUS_CHANGE",
        `Changed ${req.params.id} status to ${status}`,
        req
      );

      res.json({
        success: true,
        message: "Account status updated.",
        user: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Could not change account status."
      });
    }
  }
);

/* =========================================================
   ADMIN LOGS
   ========================================================= */

app.get(
  "/api/admin/logs",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const result = await query(
        `
        SELECT
          l.id,
          l.action,
          l.details,
          l.ip,
          l.created_at,
          u.name,
          u.email
        FROM activity_logs l
        LEFT JOIN users u
          ON u.id = l.user_id
        ORDER BY l.created_at DESC
        LIMIT 200
        `
      );

      res.json({
        success: true,
        logs: result.rows
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Could not load logs."
      });
    }
  }
);

/* =========================================================
   SEARCH USERS - ADMIN
   ========================================================= */

app.get(
  "/api/admin/search",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const q = String(
        req.query.q || ""
      )
        .trim()
        .slice(0, 100);

      if (!q) {
        return res.json({
          success: true,
          users: []
        });
      }

      const result = await query(
        `
        SELECT
          id,
          name,
          email,
          role,
          status,
          created_at
        FROM users
        WHERE
          name ILIKE $1
          OR email ILIKE $1
        ORDER BY created_at DESC
        LIMIT 50
        `,
        [`%${q}%`]
      );

      res.json({
        success: true,
        users: result.rows
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Search failed."
      });
    }
  }
);

/* =========================================================
   PUBLIC CONFIG
   ========================================================= */

app.get(
  "/api/config",
  (req, res) => {
    res.json({
      success: true,
      name: "NOVAIX",
      version: "1.0.0",
      registration: true,
      features: {
        authentication: true,
        dashboard: true,
        notifications: true,
        admin: true,
        statistics: true,
        activityLogs: true
      }
    });
  }
);

/* =========================================================
   FRONTEND
   ========================================================= */

app.use(
  express.static(
    path.join(__dirname, "public"),
    {
      maxAge: "1h"
    }
  )
);

app.get(
  "*splat",
  (req, res) => {
    if (req.path.startsWith("/api")) {
      return res.status(404).json({
        success: false,
        message: "API route not found."
      });
    }

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);

/* =========================================================
   ERROR HANDLER
   ========================================================= */

app.use(
  (error, req, res, next) => {
    console.error(error);

    if (res.headersSent) {
      return next(error);
    }

    res.status(500).json({
      success: false,
      message: "Internal server error."
    });
  }
);

/* =========================================================
   START
   ========================================================= */

async function start() {
  try {
    await initializeDatabase();

    app.listen(PORT, () => {
      console.log("");
      console.log(
        "======================================"
      );
      console.log(
        "          NOVAIX SERVER"
      );
      console.log(
        "======================================"
      );
      console.log(
        `Server: http://localhost:${PORT}`
      );
      console.log(
        `Environment: ${
          process.env.NODE_ENV || "development"
        }`
      );
      console.log(
        "======================================"
      );
      console.log("");
    });
  } catch (error) {
    console.error(
      "Server startup error:",
      error
    );

    process.exit(1);
  }
}

start();

/* Graceful shutdown */

async function shutdown(signal) {
  console.log(
    `${signal} received. Shutting down...`
  );

  try {
    await pool.end();
  } catch {}

  process.exit(0);
}

process.on(
  "SIGTERM",
  () => shutdown("SIGTERM")
);

process.on(
  "SIGINT",
  () => shutdown("SIGINT")
);
