"use strict";

const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

const PORT = Number(process.env.PORT) || 10000;
const NODE_ENV = process.env.NODE_ENV || "production";
const DATABASE_URL = process.env.DATABASE_URL || "";
const JWT_SECRET =
  process.env.JWT_SECRET || "novaix-development-secret-change-this";

let pool = null;

if (DATABASE_URL) {
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
      rejectUnauthorized: false
    },
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
  });

  pool.on("error", (error) => {
    console.error("PostgreSQL pool error:", error.message);
  });

  console.log("PostgreSQL: configured");
} else {
  console.warn("WARNING: DATABASE_URL is not configured.");
}

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

/* =========================================================
   DATABASE
========================================================= */

async function initDatabase() {
  if (!pool) {
    console.warn(
      "Database initialization skipped because DATABASE_URL is missing."
    );
    return;
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(30) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      full_name VARCHAR(120) DEFAULT '',
      bio TEXT DEFAULT '',
      avatar TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS repositories (
      id SERIAL PRIMARY KEY,
      owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name VARCHAR(100) NOT NULL,
      description TEXT DEFAULT '',
      visibility VARCHAR(20) NOT NULL DEFAULT 'public',
      stars INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(owner_id, name)
    );

    CREATE TABLE IF NOT EXISTS repo_files (
      id SERIAL PRIMARY KEY,
      repo_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
      file_path TEXT NOT NULL,
      content TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(repo_id, file_path)
    );

    CREATE TABLE IF NOT EXISTS commits (
      id SERIAL PRIMARY KEY,
      repo_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
      author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      message TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS issues (
      id SERIAL PRIMARY KEY,
      repo_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
      author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(200) NOT NULL,
      body TEXT DEFAULT '',
      status VARCHAR(20) NOT NULL DEFAULT 'open',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS stars (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      repo_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, repo_id)
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_repositories_owner
      ON repositories(owner_id);

    CREATE INDEX IF NOT EXISTS idx_repo_files_repo
      ON repo_files(repo_id);

    CREATE INDEX IF NOT EXISTS idx_commits_repo
      ON commits(repo_id);

    CREATE INDEX IF NOT EXISTS idx_issues_repo
      ON issues(repo_id);

    CREATE INDEX IF NOT EXISTS idx_stars_repo
      ON stars(repo_id);

    CREATE INDEX IF NOT EXISTS idx_stars_user
      ON stars(user_id);
  `);

  console.log("Database initialized.");
}

/* =========================================================
   HELPERS
========================================================= */

function requireDatabase(req, res, next) {
  if (!pool) {
    return res.status(503).json({
      error: "Database is not configured."
    });
  }

  next();
}

function makeToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      email: user.email
    },
    JWT_SECRET,
    {
      expiresIn: "30d"
    }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Authentication required."
    });
  }

  const token = header.slice(7).trim();

  if (!token) {
    return res.status(401).json({
      error: "Authentication token is missing."
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired token."
    });
  }
}

function optionalAuth(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return next();
  }

  const token = header.slice(7).trim();

  if (!token) {
    return next();
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
  } catch (error) {
    req.user = null;
  }

  next();
}

function normalizeUsername(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function normalizeEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function normalizeRepoName(value) {
  return String(value || "")
    .trim()
    .replace(/\s+/g, "-");
}

function normalizeFilePath(value) {
  let filePath = String(value || "")
    .trim()
    .replace(/\\/g, "/")
    .replace(/^\/+/, "");

  const parts = filePath.split("/");

  if (
    !filePath ||
    filePath.length > 500 ||
    parts.some((part) => !part || part === "." || part === "..")
  ) {
    return null;
  }

  return filePath;
}

function publicUser(row) {
  return {
    id: row.id,
    username: row.username,
    full_name: row.full_name || "",
    bio: row.bio || "",
    avatar: row.avatar || "",
    created_at: row.created_at
  };
}

function publicRepo(row) {
  return {
    id: row.id,
    name: row.name,
    description: row.description || "",
    visibility: row.visibility,
    stars: Number(row.stars || 0),
    created_at: row.created_at,
    owner: {
      id: row.owner_id,
      username: row.owner_username
    }
  };
}

async function findRepository(repoId) {
  const result = await pool.query(
    `
    SELECT
      r.*,
      u.username AS owner_username
    FROM repositories r
    JOIN users u ON u.id = r.owner_id
    WHERE r.id = $1
    `,
    [repoId]
  );

  return result.rows[0] || null;
}

async function canAccessRepository(repo, userId) {
  if (!repo) return false;

  if (repo.visibility === "public") {
    return true;
  }

  return Boolean(userId && Number(repo.owner_id) === Number(userId));
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", async (req, res) => {
  let database = false;

  if (pool) {
    try {
      await pool.query("SELECT 1");
      database = true;
    } catch (error) {
      database = false;
    }
  }

  res.json({
    ok: true,
    service: "NOVAIX",
    environment: NODE_ENV,
    database
  });
});

/*
  Everything below this point that uses PostgreSQL requires DB.
*/
app.use("/api", (req, res, next) => {
  if (req.path === "/health") {
    return next();
  }

  return requireDatabase(req, res, next);
});

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/register", async (req, res) => {
  try {
    const fullName = String(req.body.fullName || "").trim();
    const username = normalizeUsername(req.body.username);
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!username || !email || !password) {
      return res.status(400).json({
        error: "Username, email and password are required."
      });
    }

    if (!/^[a-z0-9_]{3,30}$/.test(username)) {
      return res.status(400).json({
        error:
          "Username must be 3-30 characters and contain only letters, numbers or underscore."
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        error: "Please enter a valid email."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must contain at least 6 characters."
      });
    }

    const existing = await pool.query(
      `
      SELECT id
      FROM users
      WHERE username = $1 OR email = $2
      LIMIT 1
      `,
      [username, email]
    );

    if (existing.rows.length) {
      return res.status(409).json({
        error: "Username or email already exists."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `
      INSERT INTO users (
        username,
        email,
        password_hash,
        full_name
      )
      VALUES ($1, $2, $3, $4)
      RETURNING
        id,
        username,
        email,
        full_name,
        bio,
        avatar,
        created_at
      `,
      [username, email, passwordHash, fullName]
    );

    const user = result.rows[0];
    const token = makeToken(user);

    await pool.query(
      `
      INSERT INTO sessions (user_id, token)
      VALUES ($1, $2)
      `,
      [user.id, token]
    );

    return res.status(201).json({
      ok: true,
      token,
      user: publicUser(user)
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    if (error.code === "23505") {
      return res.status(409).json({
        error: "Username or email already exists."
      });
    }

    return res.status(500).json({
      error: "Registration failed."
    });
  }
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", async (req, res) => {
  try {
    const login = String(req.body.login || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!login || !password) {
      return res.status(400).json({
        error: "Login and password are required."
      });
    }

    const result = await pool.query(
      `
      SELECT
        id,
        username,
        email,
        password_hash,
        full_name,
        bio,
        avatar,
        created_at
      FROM users
      WHERE username = $1 OR email = $1
      LIMIT 1
      `,
      [login]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error: "Invalid login or password."
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid login or password."
      });
    }

    const token = makeToken(user);

    await pool.query(
      `
      INSERT INTO sessions (user_id, token)
      VALUES ($1, $2)
      `,
      [user.id, token]
    );

    return res.json({
      ok: true,
      token,
      user: publicUser(user)
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      error: "Login failed."
    });
  }
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/logout", auth, async (req, res) => {
  try {
    const header = req.headers.authorization || "";
    const token = header.slice(7).trim();

    if (token) {
      await pool.query(
        `
        DELETE FROM sessions
        WHERE token = $1
        `,
        [token]
      );
    }

    res.json({
      ok: true
    });
  } catch (error) {
    console.error("LOGOUT ERROR:", error);

    res.status(500).json({
      error: "Logout failed."
    });
  }
});

/* =========================================================
   ME
========================================================= */

app.get("/api/me", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        id,
        username,
        email,
        full_name,
        bio,
        avatar,
        created_at
      FROM users
      WHERE id = $1
      `,
      [req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "User not found."
      });
    }

    res.json({
      user: publicUser(result.rows[0])
    });
  } catch (error) {
    console.error("ME ERROR:", error);

    res.status(500).json({
      error: "Unable to load account."
    });
  }
});

/* =========================================================
   USER PROFILE
========================================================= */

app.get("/api/users/:username", async (req, res) => {
  try {
    const username = normalizeUsername(req.params.username);

    const result = await pool.query(
      `
      SELECT
        id,
        username,
        full_name,
        bio,
        avatar,
        created_at
      FROM users
      WHERE username = $1
      `,
      [username]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "User not found."
      });
    }

    res.json({
      user: publicUser(result.rows[0])
    });
  } catch (error) {
    console.error("USER PROFILE ERROR:", error);

    res.status(500).json({
      error: "Unable to load profile."
    });
  }
});

/* =========================================================
   CREATE REPOSITORY
========================================================= */

app.post("/api/repos", auth, async (req, res) => {
  try {
    const name = normalizeRepoName(req.body.name);
    const description = String(req.body.description || "").trim();
    const visibility =
      req.body.visibility === "private" ? "private" : "public";

    if (!name) {
      return res.status(400).json({
        error: "Repository name is required."
      });
    }

    if (!/^[a-zA-Z0-9._-]{1,100}$/.test(name)) {
      return res.status(400).json({
        error:
          "Repository name may contain letters, numbers, dots, hyphens and underscores."
      });
    }

    const result = await pool.query(
      `
      INSERT INTO repositories (
        owner_id,
        name,
        description,
        visibility
      )
      VALUES ($1, $2, $3, $4)
      RETURNING *
      `,
      [req.user.id, name, description, visibility]
    );

    res.status(201).json({
      ok: true,
      repository: result.rows[0]
    });
  } catch (error) {
    console.error("CREATE REPO ERROR:", error);

    if (error.code === "23505") {
      return res.status(409).json({
        error: "You already have a repository with this name."
      });
    }

    res.status(500).json({
      error: "Unable to create repository."
    });
  }
});

/* =========================================================
   LIST REPOSITORIES
========================================================= */

app.get("/api/repos", optionalAuth, async (req, res) => {
  try {
    const ownerId = req.user ? Number(req.user.id) : null;

    const result = await pool.query(
      `
      SELECT
        r.id,
        r.name,
        r.description,
        r.visibility,
        r.stars,
        r.created_at,
        r.owner_id,
        u.username AS owner_username
      FROM repositories r
      JOIN users u ON u.id = r.owner_id
      WHERE
        r.visibility = 'public'
        OR ($1::integer IS NOT NULL AND r.owner_id = $1)
      ORDER BY r.created_at DESC
      LIMIT 100
      `,
      [ownerId]
    );

    res.json({
      repositories: result.rows.map(publicRepo)
    });
  } catch (error) {
    console.error("LIST REPOS ERROR:", error);

    res.status(500).json({
      error: "Unable to load repositories."
    });
  }
});

/* =========================================================
   REPOSITORY DETAIL
========================================================= */

app.get(
  "/api/repos/:username/:repo",
  optionalAuth,
  async (req, res) => {
    try {
      const username = normalizeUsername(req.params.username);
      const repoName = String(req.params.repo || "").trim();

      const repoResult = await pool.query(
        `
        SELECT
          r.*,
          u.username AS owner_username
        FROM repositories r
        JOIN users u ON u.id = r.owner_id
        WHERE u.username = $1
          AND r.name = $2
        LIMIT 1
        `,
        [username, repoName]
      );

      if (!repoResult.rows.length) {
        return res.status(404).json({
          error: "Repository not found."
        });
      }

      const repo = repoResult.rows[0];

      if (!(await canAccessRepository(repo, req.user?.id))) {
        return res.status(403).json({
          error: "This repository is private."
        });
      }

      const files = await pool.query(
        `
        SELECT
          id,
          file_path,
          content,
          created_at,
          updated_at
        FROM repo_files
        WHERE repo_id = $1
        ORDER BY file_path ASC
        `,
        [repo.id]
      );

      const commits = await pool.query(
        `
        SELECT
          c.id,
          c.message,
          c.created_at,
          u.username AS author_username
        FROM commits c
        JOIN users u ON u.id = c.author_id
        WHERE c.repo_id = $1
        ORDER BY c.created_at DESC
        LIMIT 50
        `,
        [repo.id]
      );

      const issues = await pool.query(
        `
        SELECT
          i.id,
          i.title,
          i.body,
          i.status,
          i.created_at,
          i.updated_at,
          u.username AS author_username
        FROM issues i
        JOIN users u ON u.id = i.author_id
        WHERE i.repo_id = $1
        ORDER BY i.created_at DESC
        LIMIT 100
        `,
        [repo.id]
      );

      let starred = false;

      if (req.user) {
        const starResult = await pool.query(
          `
          SELECT id
          FROM stars
          WHERE user_id = $1
            AND repo_id = $2
          `,
          [req.user.id, repo.id]
        );

        starred = starResult.rows.length > 0;
      }

      res.json({
        repository: {
          id: repo.id,
          name: repo.name,
          description: repo.description || "",
          visibility: repo.visibility,
          stars: Number(repo.stars || 0),
          created_at: repo.created_at,
          owner: {
            id: repo.owner_id,
            username: repo.owner_username
          },
          starred
        },
        files: files.rows,
        commits: commits.rows,
        issues: issues.rows
      });
    } catch (error) {
      console.error("REPOSITORY ERROR:", error);

      res.status(500).json({
        error: "Unable to load repository."
      });
    }
  }
);

/* =========================================================
   SAVE FILE
========================================================= */

app.post("/api/repos/:repoId/files", auth, async (req, res) => {
  const repoId = Number(req.params.repoId);
  const filePath = normalizeFilePath(req.body.filePath);
  const content = String(req.body.content ?? "");
  const message =
    String(req.body.message || "Update file").trim() || "Update file";

  if (!Number.isInteger(repoId) || repoId <= 0) {
    return res.status(400).json({
      error: "Invalid repository ID."
    });
  }

  if (!filePath) {
    return res.status(400).json({
      error: "Invalid file path."
    });
  }

  if (content.length > 2_000_000) {
    return res.status(413).json({
      error: "File is too large."
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const repoResult = await client.query(
      `
      SELECT *
      FROM repositories
      WHERE id = $1
      FOR UPDATE
      `,
      [repoId]
    );

    if (!repoResult.rows.length) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        error: "Repository not found."
      });
    }

    const repo = repoResult.rows[0];

    if (Number(repo.owner_id) !== Number(req.user.id)) {
      await client.query("ROLLBACK");

      return res.status(403).json({
        error: "Only the repository owner can edit files."
      });
    }

    const result = await client.query(
      `
      INSERT INTO repo_files (
        repo_id,
        file_path,
        content
      )
      VALUES ($1, $2, $3)
      ON CONFLICT (repo_id, file_path)
      DO UPDATE SET
        content = EXCLUDED.content,
        updated_at = NOW()
      RETURNING *
      `,
      [repoId, filePath, content]
    );

    await client.query(
      `
      INSERT INTO commits (
        repo_id,
        author_id,
        message
      )
      VALUES ($1, $2, $3)
      `,
      [repoId, req.user.id, message]
    );

    await client.query("COMMIT");

    res.json({
      ok: true,
      file: result.rows[0]
    });
  } catch (error) {
    await client.query("ROLLBACK");

    console.error("SAVE FILE ERROR:", error);

    res.status(500).json({
      error: "Unable to save file."
    });
  } finally {
    client.release();
  }
});

/* =========================================================
   GET FILE
========================================================= */

app.get(
  /^\/api\/repos\/(\d+)\/files\/(.+)$/,
  optionalAuth,
  async (req, res) => {
    try {
      const repoId = Number(req.params[0]);

      let filePath;

      try {
        filePath = decodeURIComponent(req.params[1]);
      } catch (error) {
        return res.status(400).json({
          error: "Invalid file path."
        });
      }

      filePath = normalizeFilePath(filePath);

      if (!Number.isInteger(repoId) || repoId <= 0 || !filePath) {
        return res.status(400).json({
          error: "Invalid file request."
        });
      }

      const repo = await findRepository(repoId);

      if (!repo) {
        return res.status(404).json({
          error: "Repository not found."
        });
      }

      if (!(await canAccessRepository(repo, req.user?.id))) {
        return res.status(403).json({
          error: "This repository is private."
        });
      }

      const result = await pool.query(
        `
        SELECT *
        FROM repo_files
        WHERE repo_id = $1
          AND file_path = $2
        LIMIT 1
        `,
        [repoId, filePath]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          error: "File not found."
        });
      }

      res.json({
        file: result.rows[0]
      });
    } catch (error) {
      console.error("GET FILE ERROR:", error);

      res.status(500).json({
        error: "Unable to read file."
      });
    }
  }
);

/* =========================================================
   STAR REPOSITORY
========================================================= */

app.post("/api/repos/:repoId/star", auth, async (req, res) => {
  const repoId = Number(req.params.repoId);

  if (!Number.isInteger(repoId) || repoId <= 0) {
    return res.status(400).json({
      error: "Invalid repository ID."
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const repoResult = await client.query(
      `
      SELECT id, stars
      FROM repositories
      WHERE id = $1
      FOR UPDATE
      `,
      [repoId]
    );

    if (!repoResult.rows.length) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        error: "Repository not found."
      });
    }

    const existing = await client.query(
      `
      SELECT id
      FROM stars
      WHERE user_id = $1
        AND repo_id = $2
      `,
      [req.user.id, repoId]
    );

    let starred;

    if (existing.rows.length) {
      await client.query(
        `
        DELETE FROM stars
        WHERE user_id = $1
          AND repo_id = $2
        `,
        [req.user.id, repoId]
      );

      await client.query(
        `
        UPDATE repositories
        SET stars = GREATEST(stars - 1, 0)
        WHERE id = $1
        `,
        [repoId]
      );

      starred = false;
    } else {
      await client.query(
        `
        INSERT INTO stars (user_id, repo_id)
        VALUES ($1, $2)
        ON CONFLICT (user_id, repo_id) DO NOTHING
        `,
        [req.user.id, repoId]
      );

      await client.query(
        `
        UPDATE repositories
        SET stars = stars + 1
        WHERE id = $1
        `,
        [repoId]
      );

      starred = true;
    }

    const updated = await client.query(
      `
      SELECT stars
      FROM repositories
      WHERE id = $1
      `,
      [repoId]
    );

    await client.query("COMMIT");

    res.json({
      ok: true,
      starred,
      stars: Number(updated.rows[0].stars)
    });
  } catch (error) {
    await client.query("ROLLBACK");

    console.error("STAR ERROR:", error);

    res.status(500).json({
      error: "Unable to update star."
    });
  } finally {
    client.release();
  }
});

/* =========================================================
   CREATE ISSUE
========================================================= */

app.post("/api/repos/:repoId/issues", auth, async (req, res) => {
  try {
    const repoId = Number(req.params.repoId);
    const title = String(req.body.title || "").trim();
    const body = String(req.body.body || "").trim();

    if (!Number.isInteger(repoId) || repoId <= 0) {
      return res.status(400).json({
        error: "Invalid repository ID."
      });
    }

    if (!title) {
      return res.status(400).json({
        error: "Issue title is required."
      });
    }

    if (title.length > 200) {
      return res.status(400).json({
        error: "Issue title is too long."
      });
    }

    const repo = await findRepository(repoId);

    if (!repo) {
      return res.status(404).json({
        error: "Repository not found."
      });
    }

    if (!(await canAccessRepository(repo, req.user.id))) {
      return res.status(403).json({
        error: "You cannot access this repository."
      });
    }

    const result = await pool.query(
      `
      INSERT INTO issues (
        repo_id,
        author_id,
        title,
        body
      )
      VALUES ($1, $2, $3, $4)
      RETURNING *
      `,
      [repoId, req.user.id, title, body]
    );

    res.status(201).json({
      ok: true,
      issue: result.rows[0]
    });
  } catch (error) {
    console.error("CREATE ISSUE ERROR:", error);

    res.status(500).json({
      error: "Unable to create issue."
    });
  }
});

/* =========================================================
   UPDATE ISSUE
========================================================= */

app.patch("/api/issues/:id", auth, async (req, res) => {
  try {
    const issueId = Number(req.params.id);
    const status = String(req.body.status || "").toLowerCase();

    if (!Number.isInteger(issueId) || issueId <= 0) {
      return res.status(400).json({
        error: "Invalid issue ID."
      });
    }

    if (!["open", "closed"].includes(status)) {
      return res.status(400).json({
        error: "Status must be open or closed."
      });
    }

    const issueResult = await pool.query(
      `
      SELECT
        i.*,
        r.owner_id
      FROM issues i
      JOIN repositories r ON r.id = i.repo_id
      WHERE i.id = $1
      `,
      [issueId]
    );

    if (!issueResult.rows.length) {
      return res.status(404).json({
        error: "Issue not found."
      });
    }

    const issue = issueResult.rows[0];

    const allowed =
      Number(issue.author_id) === Number(req.user.id) ||
      Number(issue.owner_id) === Number(req.user.id);

    if (!allowed) {
      return res.status(403).json({
        error: "You cannot change this issue."
      });
    }

    const result = await pool.query(
      `
      UPDATE issues
      SET
        status = $1,
        updated_at = NOW()
      WHERE id = $2
      RETURNING *
      `,
      [status, issueId]
    );

    res.json({
      ok: true,
      issue: result.rows[0]
    });
  } catch (error) {
    console.error("UPDATE ISSUE ERROR:", error);

    res.status(500).json({
      error: "Unable to update issue."
    });
  }
});

/* =========================================================
   SEARCH
========================================================= */

app.get("/api/search", async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();

    if (!q) {
      return res.json({
        users: [],
        repositories: []
      });
    }

    const search = "%" + q + "%";

    const users = await pool.query(
      `
      SELECT
        id,
        username,
        full_name,
        bio,
        avatar,
        created_at
      FROM users
      WHERE
        username ILIKE $1
        OR full_name ILIKE $1
      ORDER BY username
      LIMIT 20
      `,
      [search]
    );

    const repositories = await pool.query(
      `
      SELECT
        r.id,
        r.name,
        r.description,
        r.visibility,
        r.stars,
        r.created_at,
        r.owner_id,
        u.username AS owner_username
      FROM repositories r
      JOIN users u ON u.id = r.owner_id
      WHERE
        r.visibility = 'public'
        AND (
          r.name ILIKE $1
          OR r.description ILIKE $1
        )
      ORDER BY r.stars DESC, r.created_at DESC
      LIMIT 50
      `,
      [search]
    );

    res.json({
      users: users.rows.map(publicUser),
      repositories: repositories.rows.map(publicRepo)
    });
  } catch (error) {
    console.error("SEARCH ERROR:", error);

    res.status(500).json({
      error: "Search failed."
    });
  }
});

/* =========================================================
   FRONTEND
========================================================= */

const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
  >
  <title>NOVAIX</title>

  <style>
    * {
      box-sizing: border-box;
    }

    :root {
      --bg: #080b12;
      --panel: #101522;
      --panel2: #151b2b;
      --border: #273044;
      --text: #f5f7fb;
      --muted: #929bb0;
      --accent: #7c5cff;
      --accent2: #5eead4;
      --danger: #ef4444;
      --success: #22c55e;
    }

    body {
      margin: 0;
      background:
        radial-gradient(
          circle at top left,
          rgba(124, 92, 255, .16),
          transparent 30%
        ),
        var(--bg);
      color: var(--text);
      font-family:
        Inter,
        ui-sans-serif,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
      min-height: 100vh;
    }

    a {
      color: inherit;
      text-decoration: none;
    }

    button,
    input,
    textarea,
    select {
      font: inherit;
    }

    button {
      cursor: pointer;
    }

    .nav {
      position: sticky;
      top: 0;
      z-index: 10;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 20px;
      padding: 16px 6%;
      border-bottom: 1px solid rgba(255,255,255,.08);
      background: rgba(8,11,18,.88);
      backdrop-filter: blur(16px);
    }

    .brand {
      font-size: 21px;
      font-weight: 900;
      letter-spacing: -.5px;
    }

    .brand span {
      color: var(--accent);
    }

    .nav-links {
      display: flex;
      gap: 18px;
      align-items: center;
      color: var(--muted);
    }

    .nav-links a:hover {
      color: var(--text);
    }

    .container {
      width: min(1100px, 92%);
      margin: 0 auto;
      padding: 50px 0 80px;
    }

    .hero {
      min-height: 70vh;
      display: grid;
      place-items: center;
      text-align: center;
    }

    .hero h1 {
      margin: 0;
      font-size: clamp(48px, 10vw, 92px);
      line-height: .95;
      letter-spacing: -5px;
    }

    .gradient {
      background: linear-gradient(
        90deg,
        #ffffff,
        #a78bfa,
        #5eead4
      );
      -webkit-background-clip: text;
      background-clip: text;
      color: transparent;
    }

    .hero p {
      max-width: 650px;
      margin: 24px auto;
      color: var(--muted);
      font-size: 18px;
      line-height: 1.7;
    }

    .actions {
      display: flex;
      justify-content: center;
      gap: 12px;
      flex-wrap: wrap;
    }

    .btn {
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px 18px;
      background: var(--panel2);
      color: var(--text);
      transition: .2s;
    }

    .btn:hover {
      transform: translateY(-1px);
      border-color: var(--accent);
    }

    .btn.primary {
      background: var(--accent);
      border-color: var(--accent);
      color: white;
    }

    .card {
      background: rgba(16,21,34,.88);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 26px;
      box-shadow: 0 20px 80px rgba(0,0,0,.2);
    }

    .form-card {
      width: min(500px, 100%);
      margin: 30px auto;
    }

    .form-card h1 {
      margin-top: 0;
    }

    .muted {
      color: var(--muted);
    }

    label {
      display: block;
      margin: 16px 0 8px;
      color: #dbe1ee;
      font-size: 14px;
    }

    input,
    textarea,
    select {
      width: 100%;
      border: 1px solid var(--border);
      border-radius: 11px;
      outline: none;
      background: #0b101b;
      color: var(--text);
      padding: 12px 14px;
    }

    textarea {
      min-height: 130px;
      resize: vertical;
    }

    input:focus,
    textarea:focus,
    select:focus {
      border-color: var(--accent);
    }

    .error {
      margin: 15px 0;
      padding: 12px;
      border-radius: 10px;
      background: rgba(239,68,68,.12);
      border: 1px solid rgba(239,68,68,.3);
      color: #fca5a5;
    }

    .success {
      margin: 15px 0;
      padding: 12px;
      border-radius: 10px;
      background: rgba(34,197,94,.12);
      border: 1px solid rgba(34,197,94,.3);
      color: #86efac;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 18px;
    }

    .repo {
      display: block;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 20px;
    }

    .repo:hover {
      border-color: var(--accent);
    }

    .repo-title {
      font-weight: 800;
      font-size: 19px;
    }

    .badge {
      display: inline-block;
      margin-left: 8px;
      padding: 3px 8px;
      border-radius: 999px;
      background: #20283b;
      color: var(--muted);
      font-size: 11px;
    }

    .meta {
      display: flex;
      gap: 15px;
      flex-wrap: wrap;
      color: var(--muted);
      font-size: 13px;
      margin-top: 14px;
    }

    .section-title {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 15px;
      margin-bottom: 20px;
    }

    .file {
      padding: 13px 15px;
      border-bottom: 1px solid var(--border);
      font-family: monospace;
      color: #c4b5fd;
    }

    .issue {
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 15px;
      margin-top: 10px;
    }

    footer {
      text-align: center;
      color: var(--muted);
      padding: 30px;
      border-top: 1px solid rgba(255,255,255,.06);
    }

    @media (max-width: 700px) {
      .grid {
        grid-template-columns: 1fr;
      }

      .nav-links {
        gap: 10px;
        font-size: 13px;
      }

      .hero h1 {
        letter-spacing: -3px;
      }
    }
  </style>
</head>

<body>

  <nav class="nav">
    <a class="brand" href="/">N<span>OVAIX</span></a>

    <div class="nav-links">
      <a href="/">Home</a>
      <a href="/repos">Repositories</a>
      <a href="/login" id="navLogin">Login</a>
      <a href="/register" id="navRegister">Get Started</a>
      <a href="/dashboard" id="navDashboard" style="display:none">Dashboard</a>
      <a href="#" id="navLogout" style="display:none">Logout</a>
    </div>
  </nav>

  <main id="app"></main>

  <footer>
    © ${new Date().getFullYear()} NOVAIX · Built for the next generation.
  </footer>

<script>
(function () {
  "use strict";

  var app = document.getElementById("app");

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function getToken() {
    return localStorage.getItem("novaix_token") || "";
  }

  function getUser() {
    try {
      return JSON.parse(
        localStorage.getItem("novaix_user") || "null"
      );
    } catch (e) {
      return null;
    }
  }

  function saveAuth(data) {
    localStorage.setItem("novaix_token", data.token);
    localStorage.setItem(
      "novaix_user",
      JSON.stringify(data.user)
    );
    updateNav();
  }

  function clearAuth() {
    localStorage.removeItem("novaix_token");
    localStorage.removeItem("novaix_user");
    updateNav();
  }

  function updateNav() {
    var logged = !!getToken();

    document.getElementById("navLogin").style.display =
      logged ? "none" : "inline";

    document.getElementById("navRegister").style.display =
      logged ? "none" : "inline";

    document.getElementById("navDashboard").style.display =
      logged ? "inline" : "none";

    document.getElementById("navLogout").style.display =
      logged ? "inline" : "none";
  }

  async function api(url, options) {
    options = options || {};
    options.headers = options.headers || {};

    if (!options.headers["Content-Type"] && options.body) {
      options.headers["Content-Type"] = "application/json";
    }

    var token = getToken();

    if (token) {
      options.headers.Authorization = "Bearer " + token;
    }

    var response;

    try {
      response = await fetch(url, options);
    } catch (error) {
      throw new Error(
        "Serverga ulanishda xatolik. Internet yoki Render serverini tekshiring."
      );
    }

    var text = await response.text();
    var data;

    try {
      data = text ? JSON.parse(text) : {};
    } catch (error) {
      throw new Error(
        "Server JSON javob qaytarmadi. HTTP " + response.status
      );
    }

    if (!response.ok) {
      throw new Error(
        data.error || ("Server xatosi: HTTP " + response.status)
      );
    }

    return data;
  }

  function layout(title, content) {
    return (
      '<div class="container">' +
        '<div class="section-title">' +
          '<div>' +
            '<h1>' + escapeHtml(title) + '</h1>' +
          '</div>' +
        '</div>' +
        content +
      '</div>'
    );
  }

  function showError(message) {
    return '<div class="error">' + escapeHtml(message) + '</div>';
  }

  function home() {
    app.innerHTML =
      '<div class="container hero">' +
        '<div>' +
          '<h1>Build with <span class="gradient">NOVAIX</span></h1>' +
          '<p>' +
            'A modern developer platform for repositories, code, issues and collaboration.' +
          '</p>' +
          '<div class="actions">' +
            '<a class="btn primary" href="/register">Get Started</a>' +
            '<a class="btn" href="/repos">Explore Repositories</a>' +
          '</div>' +
        '</div>' +
      '</div>';
  }

  function loginPage() {
    app.innerHTML = layout(
      "Welcome back",
      '<div class="card form-card">' +
        '<p class="muted">Sign in to your NOVAIX account.</p>' +
        '<div id="loginError"></div>' +

        '<form id="loginForm">' +
          '<label>USERNAME OR EMAIL</label>' +
          '<input id="login" required autocomplete="username">' +

          '<label>PASSWORD</label>' +
          '<input id="password" type="password" required autocomplete="current-password">' +

          '<br><br>' +
          '<button class="btn primary" type="submit">Sign In →</button>' +
        '</form>' +

        '<p class="muted">' +
          'No account? <a href="/register">Create one</a>' +
        '</p>' +
      '</div>'
    );

    document
      .getElementById("loginForm")
      .addEventListener("submit", async function (event) {
        event.preventDefault();

        var errorBox = document.getElementById("loginError");
        errorBox.innerHTML = "";

        try {
          var data = await api("/api/login", {
            method: "POST",
            body: JSON.stringify({
              login: document.getElementById("login").value,
              password: document.getElementById("password").value
            })
          });

          saveAuth(data);
          location.href = "/dashboard";
        } catch (error) {
          errorBox.innerHTML = showError(error.message);
        }
      });
  }

  function registerPage() {
    app.innerHTML = layout(
      "Create your account",
      '<div class="card form-card">' +
        '<p class="muted">Start your NOVAIX experience.</p>' +
        '<div id="registerError"></div>' +

        '<form id="registerForm">' +
          '<label>FULL NAME</label>' +
          '<input id="fullName" required autocomplete="name">' +

          '<label>USERNAME</label>' +
          '<input id="username" required autocomplete="username">' +

          '<label>EMAIL</label>' +
          '<input id="email" type="email" required autocomplete="email">' +

          '<label>PASSWORD</label>' +
          '<input id="password" type="password" minlength="6" required autocomplete="new-password">' +

          '<br><br>' +
          '<button class="btn primary" type="submit">Create Account →</button>' +
        '</form>' +

        '<p class="muted">' +
          'Already have an account? <a href="/login">Sign in</a>' +
        '</p>' +
      '</div>'
    );

    document
      .getElementById("registerForm")
      .addEventListener("submit", async function (event) {
        event.preventDefault();

        var errorBox = document.getElementById("registerError");
        errorBox.innerHTML = "";

        var button = event.target.querySelector("button");
        button.disabled = true;
        button.textContent = "Creating...";

        try {
          var data = await api("/api/register", {
            method: "POST",
            body: JSON.stringify({
              fullName: document.getElementById("fullName").value,
              username: document.getElementById("username").value,
              email: document.getElementById("email").value,
              password: document.getElementById("password").value
            })
          });

          saveAuth(data);
          location.href = "/dashboard";
        } catch (error) {
          errorBox.innerHTML = showError(error.message);
          button.disabled = false;
          button.textContent = "Create Account →";
        }
      });
  }

  async function dashboard() {
    if (!getToken()) {
      location.href = "/login";
      return;
    }

    app.innerHTML = layout(
      "Dashboard",
      '<div id="dashboardContent"><p class="muted">Loading...</p></div>'
    );

    try {
      var me = await api("/api/me");
      var data = await api("/api/repos");

      var user = me.user;
      var repos = data.repositories.filter(function (repo) {
        return Number(repo.owner.id) === Number(user.id);
      });

      var content =
        '<div class="card">' +
          '<h2>Welcome, ' +
            escapeHtml(user.full_name || user.username) +
          '</h2>' +
          '<p class="muted">@' +
            escapeHtml(user.username) +
          '</p>' +
          '<button class="btn primary" id="createRepoBtn">+ Create Repository</button>' +
        '</div>' +

        '<br>' +

        '<div class="section-title">' +
          '<h2>Your repositories</h2>' +
        '</div>';

      if (!repos.length) {
        content +=
          '<div class="card">' +
            '<p class="muted">You have no repositories yet.</p>' +
          '</div>';
      } else {
        content += '<div class="grid">';

        repos.forEach(function (repo) {
          content += repoCard(repo);
        });

        content += '</div>';
      }

      document.getElementById("dashboardContent").innerHTML = content;

      document
        .getElementById("createRepoBtn")
        .addEventListener("click", createRepo);
    } catch (error) {
      document.getElementById("dashboardContent").innerHTML =
        showError(error.message);
    }
  }

  function repoCard(repo) {
    return (
      '<a class="repo" href="/repo/' +
        encodeURIComponent(repo.owner.username) +
        '/' +
        encodeURIComponent(repo.name) +
      '">' +

        '<div class="repo-title">' +
          escapeHtml(repo.name) +
          '<span class="badge">' +
            escapeHtml(repo.visibility) +
          '</span>' +
        '</div>' +

        '<p class="muted">' +
          escapeHtml(repo.description || "No description") +
        '</p>' +

        '<div class="meta">' +
          '<span>★ ' + Number(repo.stars || 0) + '</span>' +
          '<span>@' + escapeHtml(repo.owner.username) + '</span>' +
        '</div>' +

      '</a>'
    );
  }

  async function createRepo() {
    var name = prompt("Repository name:");

    if (!name) {
      return;
    }

    var description = prompt("Description:") || "";

    try {
      var data = await api("/api/repos", {
        method: "POST",
        body: JSON.stringify({
          name: name,
          description: description,
          visibility: "public"
        })
      });

      location.href =
        "/repo/" +
        encodeURIComponent(getUser().username) +
        "/" +
        encodeURIComponent(data.repository.name);
    } catch (error) {
      alert(error.message);
    }
  }

  async function repositories() {
    app.innerHTML = layout(
      "Repositories",
      '<div id="repoList"><p class="muted">Loading...</p></div>'
    );

    try {
      var data = await api("/api/repos");

      if (!data.repositories.length) {
        document.getElementById("repoList").innerHTML =
          '<div class="card">' +
            '<p class="muted">No repositories found.</p>' +
          '</div>';
        return;
      }

      var content = '<div class="grid">';

      data.repositories.forEach(function (repo) {
        content += repoCard(repo);
      });

      content += '</div>';

      document.getElementById("repoList").innerHTML = content;
    } catch (error) {
      document.getElementById("repoList").innerHTML =
        showError(error.message);
    }
  }

  async function repository(username, repoName) {
    app.innerHTML = layout(
      "Repository",
      '<div id="repoContent"><p class="muted">Loading...</p></div>'
    );

    try {
      var data = await api(
        "/api/repos/" +
        encodeURIComponent(username) +
        "/" +
        encodeURIComponent(repoName)
      );

      var repo = data.repository;

      var content =
        '<div class="card">' +
          '<div class="section-title">' +
            '<div>' +
              '<h1>' +
                escapeHtml(repo.name) +
              '</h1>' +
              '<p class="muted">' +
                escapeHtml(repo.description || "No description") +
              '</p>' +
            '</div>' +

            '<button class="btn" id="starBtn">' +
              (repo.starred ? "★ Unstar" : "☆ Star") +
              ' · ' +
              Number(repo.stars || 0) +
            '</button>' +
          '</div>' +

          '<div class="meta">' +
            '<span>@' + escapeHtml(repo.owner.username) + '</span>' +
            '<span>' + escapeHtml(repo.visibility) + '</span>' +
          '</div>' +
        '</div>' +

        '<br>' +

        '<div class="card">' +
          '<h2>Files</h2>';

      if (!data.files.length) {
        content +=
          '<p class="muted">No files yet.</p>';
      } else {
        data.files.forEach(function (file) {
          content +=
            '<div class="file">' +
              escapeHtml(file.file_path) +
            '</div>';
        });
      }

      content +=
        '</div>' +

        '<br>' +

        '<div class="card">' +
          '<h2>Issues</h2>' +

          '<form id="issueForm">' +
            '<label>Title</label>' +
            '<input id="issueTitle" required>' +

            '<label>Description</label>' +
            '<textarea id="issueBody"></textarea>' +

            '<br>' +
            '<button class="btn primary" type="submit">Create Issue</button>' +
          '</form>' +

          '<div id="issues">';

      if (!data.issues.length) {
        content +=
          '<p class="muted">No issues yet.</p>';
      } else {
        data.issues.forEach(function (issue) {
          content +=
            '<div class="issue">' +
              '<strong>' +
                escapeHtml(issue.title) +
              '</strong>' +

              '<p class="muted">' +
                escapeHtml(issue.body || "") +
              '</p>' +

              '<div class="meta">' +
                '<span>' +
                  escapeHtml(issue.status) +
                '</span>' +
                '<span>@' +
                  escapeHtml(issue.author_username) +
                '</span>' +
              '</div>' +
            '</div>';
        });
      }

      content +=
          '</div>' +
        '</div>';

      document.getElementById("repoContent").innerHTML = content;

      document
        .getElementById("starBtn")
        .addEventListener("click", async function () {
          if (!getToken()) {
            location.href = "/login";
            return;
          }

          try {
            var star = await api(
              "/api/repos/" + repo.id + "/star",
              {
                method: "POST"
              }
            );

            document.getElementById("starBtn").textContent =
              (star.starred ? "★ Unstar" : "☆ Star") +
              " · " +
              star.stars;
          } catch (error) {
            alert(error.message);
          }
        });

      document
        .getElementById("issueForm")
        .addEventListener("submit", async function (event) {
          event.preventDefault();

          if (!getToken()) {
            location.href = "/login";
            return;
          }

          try {
            await api(
              "/api/repos/" + repo.id + "/issues",
              {
                method: "POST",
                body: JSON.stringify({
                  title: document.getElementById("issueTitle").value,
                  body: document.getElementById("issueBody").value
                })
              }
            );

            alert("Issue created.");
            repository(username, repoName);
          } catch (error) {
            alert(error.message);
          }
        });
    } catch (error) {
      document.getElementById("repoContent").innerHTML =
        showError(error.message);
    }
  }

  async function logout() {
    try {
      if (getToken()) {
        await api("/api/logout", {
          method: "POST"
        });
      }
    } catch (error) {
      console.error(error);
    }

    clearAuth();
    location.href = "/";
  }

  function router() {
    var path = location.pathname;

    if (path === "/" || path === "") {
      home();
      return;
    }

    if (path === "/login") {
      loginPage();
      return;
    }

    if (path === "/register") {
      registerPage();
      return;
    }

    if (path === "/dashboard") {
      dashboard();
      return;
    }

    if (path === "/repos") {
      repositories();
      return;
    }

    var repoMatch = path.match(
      /^\\/repo\\/([^/]+)\\/([^/]+)$/
    );

    if (repoMatch) {
      repository(
        decodeURIComponent(repoMatch[1]),
        decodeURIComponent(repoMatch[2])
      );
      return;
    }

    home();
  }

  document
    .getElementById("navLogout")
    .addEventListener("click", function (event) {
      event.preventDefault();
      logout();
    });

  document.addEventListener("click", function (event) {
    var link = event.target.closest("a");

    if (!link) {
      return;
    }

    var href = link.getAttribute("href");

    if (
      !href ||
      href.startsWith("http") ||
      href.startsWith("#") ||
      href.startsWith("mailto:")
    ) {
      return;
    }

    if (!href.startsWith("/")) {
      return;
    }

    event.preventDefault();

    history.pushState({}, "", href);
    router();
  });

  window.addEventListener("popstate", router);

  updateNav();
  router();
})();
</script>

</body>
</html>
`;

/* =========================================================
   FRONTEND FALLBACK
========================================================= */

app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({
      error: "API endpoint not found."
    });
  }

  res.status(200).type("html").send(html);
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use((error, req, res, next) => {
  console.error("UNHANDLED ERROR:", error);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    error: "Internal server error."
  });
});

/* =========================================================
   START
========================================================= */

async function start() {
  try {
    await initDatabase();

    const server = app.listen(PORT, "0.0.0.0", () => {
      console.log("");
      console.log("=================================");
      console.log("        NOVAIX SERVER");
      console.log("=================================");
      console.log("Port:", PORT);
      console.log("Environment:", NODE_ENV);
      console.log("Database:", pool ? "CONFIGURED" : "MISSING");
      console.log("=================================");
      console.log("");
    });

    function shutdown(signal) {
      console.log(signal + " received. Shutting down...");

      server.close(async () => {
        if (pool) {
          try {
            await pool.end();
          } catch (error) {
            console.error("Database shutdown error:", error.message);
          }
        }

        process.exit(0);
      });
    }

    process.on("SIGTERM", function () {
      shutdown("SIGTERM");
    });

    process.on("SIGINT", function () {
      shutdown("SIGINT");
    });
  } catch (error) {
    console.error("STARTUP ERROR:", error);

    /*
      Serverni butunlay yiqitmaslik uchun:
      DATABASE_URL noto'g'ri bo'lsa ham health/server javob berishi mumkin.
    */

    app.listen(PORT, "0.0.0.0", () => {
      console.log("");
      console.log("=================================");
      console.log("        NOVAIX SERVER");
      console.log("=================================");
      console.log("Port:", PORT);
      console.log("Environment:", NODE_ENV);
      console.log("Database: ERROR");
      console.log("=================================");
      console.log("");
    });
  }
}

start();
