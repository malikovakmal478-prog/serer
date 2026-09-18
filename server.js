/*
  NOVAIX — ONE FILE SERVER
  Node.js 20+
  Render ready

  Required:
    DATABASE_URL

  Optional:
    JWT_SECRET
*/

const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

const PORT = Number(process.env.PORT) || 10000;

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "novaix-development-secret-change-this";

const DATABASE_URL = process.env.DATABASE_URL;

/* =========================================================
   EXPRESS
========================================================= */

app.disable("x-powered-by");

app.use(
  express.json({
    limit: "20mb"
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "20mb"
  })
);

/* =========================================================
   DATABASE
========================================================= */

let pool = null;

if (DATABASE_URL) {
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
      rejectUnauthorized: false
    }
  });

  pool.on("error", (error) => {
    console.error("PostgreSQL pool error:", error.message);
  });

  console.log("PostgreSQL: configured");
} else {
  console.warn(
    "WARNING: DATABASE_URL is not configured."
  );
}

/* =========================================================
   DATABASE HELPERS
========================================================= */

function requireDatabase(req, res, next) {
  if (!pool) {
    return res.status(503).json({
      error:
        "Database is not configured. Add DATABASE_URL in Render."
    });
  }

  next();
}

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
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      bio TEXT DEFAULT '',
      avatar TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS repositories (
      id SERIAL PRIMARY KEY,
      owner_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,
      name VARCHAR(100) NOT NULL,
      description TEXT DEFAULT '',
      visibility VARCHAR(20) DEFAULT 'public',
      default_branch VARCHAR(100) DEFAULT 'main',
      stars INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(owner_id, name)
    );

    CREATE TABLE IF NOT EXISTS repo_files (
      id SERIAL PRIMARY KEY,
      repo_id INTEGER NOT NULL
        REFERENCES repositories(id)
        ON DELETE CASCADE,
      file_path TEXT NOT NULL,
      content TEXT DEFAULT '',
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(repo_id, file_path)
    );

    CREATE TABLE IF NOT EXISTS commits (
      id SERIAL PRIMARY KEY,
      repo_id INTEGER NOT NULL
        REFERENCES repositories(id)
        ON DELETE CASCADE,
      author_id INTEGER
        REFERENCES users(id)
        ON DELETE SET NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS issues (
      id SERIAL PRIMARY KEY,
      repo_id INTEGER NOT NULL
        REFERENCES repositories(id)
        ON DELETE CASCADE,
      author_id INTEGER
        REFERENCES users(id)
        ON DELETE SET NULL,
      title TEXT NOT NULL,
      body TEXT DEFAULT '',
      state VARCHAR(20) DEFAULT 'open',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS stars (
      id SERIAL PRIMARY KEY,
      repo_id INTEGER NOT NULL
        REFERENCES repositories(id)
        ON DELETE CASCADE,
      user_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(repo_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,
      token TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
  `);

  console.log("Database initialized.");
}

/* =========================================================
   AUTH
========================================================= */

function createToken(user) {
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
  const header =
    req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Authentication required."
    });
  }

  const token = header.substring(7).trim();

  if (!token) {
    return res.status(401).json({
      error: "Authentication required."
    });
  }

  try {
    req.user = jwt.verify(
      token,
      JWT_SECRET
    );

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired session."
    });
  }
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
      console.error(
        "Health database error:",
        error.message
      );
    }
  }

  res.json({
    ok: true,
    server: "NOVAIX",
    database,
    environment:
      process.env.NODE_ENV || "production",
    time: new Date().toISOString()
  });
});

/* =========================================================
   REGISTER
========================================================= */

app.post(
  "/api/register",
  requireDatabase,
  async (req, res) => {
    try {
      let username = String(
        req.body.username || ""
      ).trim();

      let email = String(
        req.body.email || ""
      )
        .trim()
        .toLowerCase();

      const password = String(
        req.body.password || ""
      );

      if (
        !/^[a-zA-Z0-9_]{3,30}$/.test(
          username
        )
      ) {
        return res.status(400).json({
          error:
            "Username must contain 3-30 letters, numbers or underscore."
        });
      }

      if (
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
          email
        )
      ) {
        return res.status(400).json({
          error: "Invalid email."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          error:
            "Password must contain at least 6 characters."
        });
      }

      const existing =
        await pool.query(
          `
          SELECT id
          FROM users
          WHERE username = $1
             OR email = $2
          `,
          [username, email]
        );

      if (existing.rows.length > 0) {
        return res.status(409).json({
          error:
            "Username or email already exists."
        });
      }

      const hash =
        await bcrypt.hash(
          password,
          12
        );

      const result =
        await pool.query(
          `
          INSERT INTO users
          (
            username,
            email,
            password_hash
          )
          VALUES ($1, $2, $3)
          RETURNING
            id,
            username,
            email,
            bio,
            avatar,
            created_at
          `,
          [
            username,
            email,
            hash
          ]
        );

      const user =
        result.rows[0];

      const token =
        createToken(user);

      await pool.query(
        `
        INSERT INTO sessions
        (
          user_id,
          token
        )
        VALUES ($1, $2)
        `,
        [
          user.id,
          token
        ]
      );

      return res.status(201).json({
        ok: true,
        token,
        user
      });
    } catch (error) {
      console.error(
        "Registration error:",
        error
      );

      return res.status(500).json({
        error:
          "Registration failed."
      });
    }
  }
);

/* =========================================================
   LOGIN
========================================================= */

app.post(
  "/api/login",
  requireDatabase,
  async (req, res) => {
    try {
      const email = String(
        req.body.email || ""
      )
        .trim()
        .toLowerCase();

      const password = String(
        req.body.password || ""
      );

      if (!email || !password) {
        return res.status(400).json({
          error:
            "Email and password are required."
        });
      }

      const result =
        await pool.query(
          `
          SELECT *
          FROM users
          WHERE email = $1
          LIMIT 1
          `,
          [email]
        );

      if (result.rows.length === 0) {
        return res.status(401).json({
          error:
            "Invalid email or password."
        });
      }

      const user =
        result.rows[0];

      const valid =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!valid) {
        return res.status(401).json({
          error:
            "Invalid email or password."
        });
      }

      const token =
        createToken(user);

      await pool.query(
        `
        INSERT INTO sessions
        (
          user_id,
          token
        )
        VALUES ($1, $2)
        `,
        [
          user.id,
          token
        ]
      );

      delete user.password_hash;

      return res.json({
        ok: true,
        token,
        user
      });
    } catch (error) {
      console.error(
        "Login error:",
        error
      );

      return res.status(500).json({
        error: "Login failed."
      });
    }
  }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/api/logout",
  auth,
  requireDatabase,
  async (req, res) => {
    try {
      const header =
        req.headers.authorization || "";

      const token =
        header.startsWith("Bearer ")
          ? header.substring(7)
          : "";

      if (token) {
        await pool.query(
          `
          DELETE FROM sessions
          WHERE token = $1
          `,
          [token]
        );
      }

      return res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        "Logout error:",
        error.message
      );

      return res.json({
        ok: true
      });
    }
  }
);

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  "/api/me",
  auth,
  requireDatabase,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            id,
            username,
            email,
            bio,
            avatar,
            created_at
          FROM users
          WHERE id = $1
          `,
          [req.user.id]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "User not found."
        });
      }

      return res.json(
        result.rows[0]
      );
    } catch (error) {
      console.error(
        "Me error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to load profile."
      });
    }
  }
);

/* =========================================================
   USER PROFILE
========================================================= */

app.get(
  "/api/users/:username",
  requireDatabase,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            id,
            username,
            email,
            bio,
            avatar,
            created_at
          FROM users
          WHERE username = $1
          `,
          [req.params.username]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error:
            "User not found."
        });
      }

      const user =
        result.rows[0];

      const repos =
        await pool.query(
          `
          SELECT
            id,
            name,
            description,
            visibility,
            default_branch,
            stars,
            created_at
          FROM repositories
          WHERE owner_id = $1
          ORDER BY created_at DESC
          `,
          [user.id]
        );

      return res.json({
        user,
        repositories:
          repos.rows
      });
    } catch (error) {
      console.error(
        "Profile error:",
        error
      );

      return res.status(500).json({
        error:
          "Profile loading failed."
      });
    }
  }
);

/* =========================================================
   CREATE REPOSITORY
========================================================= */

app.post(
  "/api/repos",
  auth,
  requireDatabase,
  async (req, res) => {
    try {
      const name =
        String(
          req.body.name || ""
        ).trim();

      const description =
        String(
          req.body.description || ""
        ).trim();

      const visibility =
        req.body.visibility ===
        "private"
          ? "private"
          : "public";

      if (
        !/^[a-zA-Z0-9._-]{1,100}$/.test(
          name
        )
      ) {
        return res.status(400).json({
          error:
            "Invalid repository name."
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO repositories
          (
            owner_id,
            name,
            description,
            visibility
          )
          VALUES ($1, $2, $3, $4)
          RETURNING *
          `,
          [
            req.user.id,
            name,
            description,
            visibility
          ]
        );

      const repo =
        result.rows[0];

      await pool.query(
        `
        INSERT INTO repo_files
        (
          repo_id,
          file_path,
          content
        )
        VALUES ($1, $2, $3)
        `,
        [
          repo.id,
          "README.md",
          "# " +
            name +
            "\n\n" +
            description
        ]
      );

      await pool.query(
        `
        INSERT INTO commits
        (
          repo_id,
          author_id,
          message
        )
        VALUES ($1, $2, $3)
        `,
        [
          repo.id,
          req.user.id,
          "Initial commit"
        ]
      );

      return res.status(201).json(
        repo
      );
    } catch (error) {
      console.error(
        "Repository creation error:",
        error
      );

      if (
        error &&
        error.code === "23505"
      ) {
        return res.status(409).json({
          error:
            "Repository already exists."
        });
      }

      return res.status(500).json({
        error:
          "Repository creation failed."
      });
    }
  }
);

/* =========================================================
   LIST PUBLIC REPOSITORIES
========================================================= */

app.get(
  "/api/repos",
  requireDatabase,
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            r.id,
            r.name,
            r.description,
            r.visibility,
            r.default_branch,
            r.stars,
            r.created_at,
            u.username AS owner
          FROM repositories r
          JOIN users u
            ON u.id = r.owner_id
          WHERE r.visibility = 'public'
          ORDER BY r.created_at DESC
        `);

      return res.json(
        result.rows
      );
    } catch (error) {
      console.error(
        "Repositories error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to load repositories."
      });
    }
  }
);

/* =========================================================
   REPOSITORY DETAILS
========================================================= */

app.get(
  "/api/repos/:username/:repo",
  requireDatabase,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            r.*,
            u.username AS owner
          FROM repositories r
          JOIN users u
            ON u.id = r.owner_id
          WHERE
            u.username = $1
            AND r.name = $2
          `,
          [
            req.params.username,
            req.params.repo
          ]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error:
            "Repository not found."
        });
      }

      const repo =
        result.rows[0];

      if (
        repo.visibility ===
        "private"
      ) {
        const header =
          req.headers.authorization ||
          "";

        if (
          !header.startsWith(
            "Bearer "
          )
        ) {
          return res.status(403).json({
            error:
              "Private repository."
          });
        }

        try {
          const token =
            header.substring(7);

          const viewer =
            jwt.verify(
              token,
              JWT_SECRET
            );

          if (
            viewer.id !==
            repo.owner_id
          ) {
            return res.status(403).json({
              error:
                "Private repository."
            });
          }
        } catch {
          return res.status(403).json({
            error:
              "Private repository."
          });
        }
      }

      const files =
        await pool.query(
          `
          SELECT
            id,
            file_path,
            content,
            updated_at
          FROM repo_files
          WHERE repo_id = $1
          ORDER BY file_path
          `,
          [repo.id]
        );

      const commits =
        await pool.query(
          `
          SELECT
            c.id,
            c.message,
            c.created_at,
            u.username
          FROM commits c
          LEFT JOIN users u
            ON u.id = c.author_id
          WHERE c.repo_id = $1
          ORDER BY c.created_at DESC
          LIMIT 50
          `,
          [repo.id]
        );

      const issues =
        await pool.query(
          `
          SELECT
            i.id,
            i.title,
            i.body,
            i.state,
            i.created_at,
            u.username
          FROM issues i
          LEFT JOIN users u
            ON u.id = i.author_id
          WHERE i.repo_id = $1
          ORDER BY i.created_at DESC
          `,
          [repo.id]
        );

      return res.json({
        repository: repo,
        files:
          files.rows,
        commits:
          commits.rows,
        issues:
          issues.rows
      });
    } catch (error) {
      console.error(
        "Repository details error:",
        error
      );

      return res.status(500).json({
        error:
          "Repository loading failed."
      });
    }
  }
);

/* =========================================================
   SAVE FILE
========================================================= */

app.post(
  "/api/repos/:repoId/files",
  auth,
  requireDatabase,
  async (req, res) => {
    try {
      const repoId =
        Number(req.params.repoId);

      if (
        !Number.isInteger(repoId) ||
        repoId <= 0
      ) {
        return res.status(400).json({
          error:
            "Invalid repository ID."
        });
      }

      const filePath =
        String(
          req.body.path || ""
        ).trim();

      const content =
        String(
          req.body.content || ""
        );

      if (!filePath) {
        return res.status(400).json({
          error:
            "File path required."
        });
      }

      const repoResult =
        await pool.query(
          `
          SELECT *
          FROM repositories
          WHERE id = $1
          `,
          [repoId]
        );

      if (
        repoResult.rows.length ===
        0
      ) {
        return res.status(404).json({
          error:
            "Repository not found."
        });
      }

      const repo =
        repoResult.rows[0];

      if (
        repo.owner_id !==
        req.user.id
      ) {
        return res.status(403).json({
          error:
            "Only repository owner can modify files."
        });
      }

      await pool.query(
        `
        INSERT INTO repo_files
        (
          repo_id,
          file_path,
          content
        )
        VALUES ($1, $2, $3)
        ON CONFLICT
        (
          repo_id,
          file_path
        )
        DO UPDATE SET
          content = EXCLUDED.content,
          updated_at =
            CURRENT_TIMESTAMP
        `,
        [
          repoId,
          filePath,
          content
        ]
      );

      await pool.query(
        `
        INSERT INTO commits
        (
          repo_id,
          author_id,
          message
        )
        VALUES ($1, $2, $3)
        `,
        [
          repoId,
          req.user.id,
          "Update " +
            filePath
        ]
      );

      return res.json({
        ok: true,
        path: filePath
      });
    } catch (error) {
      console.error(
        "File save error:",
        error
      );

      return res.status(500).json({
        error:
          "File save failed."
      });
    }
  }
);

/* =========================================================
   GET FILE
========================================================= */

app.get(
  "/api/repos/:repoId/files/*file",
  requireDatabase,
  async (req, res) => {
    try {
      const repoId =
        Number(req.params.repoId);

      let filePath =
        req.params.file;

      if (Array.isArray(filePath)) {
        filePath =
          filePath.join("/");
      }

      filePath =
        String(
          filePath || ""
        );

      const result =
        await pool.query(
          `
          SELECT *
          FROM repo_files
          WHERE repo_id = $1
            AND file_path = $2
          `,
          [
            repoId,
            filePath
          ]
        );

      if (
        result.rows.length ===
        0
      ) {
        return res.status(404).json({
          error:
            "File not found."
        });
      }

      return res.json(
        result.rows[0]
      );
    } catch (error) {
      console.error(
        "File read error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to read file."
      });
    }
  }
);

/* =========================================================
   STAR REPOSITORY
========================================================= */

app.post(
  "/api/repos/:repoId/star",
  auth,
  requireDatabase,
  async (req, res) => {
    try {
      const repoId =
        Number(req.params.repoId);

      const exists =
        await pool.query(
          `
          SELECT id
          FROM stars
          WHERE repo_id = $1
            AND user_id = $2
          `,
          [
            repoId,
            req.user.id
          ]
        );

      if (
        exists.rows.length >
        0
      ) {
        await pool.query(
          `
          DELETE FROM stars
          WHERE repo_id = $1
            AND user_id = $2
          `,
          [
            repoId,
            req.user.id
          ]
        );

        await pool.query(
          `
          UPDATE repositories
          SET stars =
            GREATEST(stars - 1, 0)
          WHERE id = $1
          `,
          [repoId]
        );

        return res.json({
          starred: false
        });
      }

      await pool.query(
        `
        INSERT INTO stars
        (
          repo_id,
          user_id
        )
        VALUES ($1, $2)
        `,
        [
          repoId,
          req.user.id
        ]
      );

      await pool.query(
        `
        UPDATE repositories
        SET stars = stars + 1
        WHERE id = $1
        `,
        [repoId]
      );

      return res.json({
        starred: true
      });
    } catch (error) {
      console.error(
        "Star error:",
        error
      );

      return res.status(500).json({
        error:
          "Star operation failed."
      });
    }
  }
);

/* =========================================================
   CREATE ISSUE
========================================================= */

app.post(
  "/api/repos/:repoId/issues",
  auth,
  requireDatabase,
  async (req, res) => {
    try {
      const repoId =
        Number(req.params.repoId);

      const title =
        String(
          req.body.title || ""
        ).trim();

      const body =
        String(
          req.body.body || ""
        ).trim();

      if (!title) {
        return res.status(400).json({
          error:
            "Issue title required."
        });
      }

      const repo =
        await pool.query(
          `
          SELECT id
          FROM repositories
          WHERE id = $1
          `,
          [repoId]
        );

      if (
        repo.rows.length ===
        0
      ) {
        return res.status(404).json({
          error:
            "Repository not found."
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO issues
          (
            repo_id,
            author_id,
            title,
            body
          )
          VALUES ($1, $2, $3, $4)
          RETURNING *
          `,
          [
            repoId,
            req.user.id,
            title,
            body
          ]
        );

      return res.status(201).json(
        result.rows[0]
      );
    } catch (error) {
      console.error(
        "Issue creation error:",
        error
      );

      return res.status(500).json({
        error:
          "Issue creation failed."
      });
    }
  }
);

/* =========================================================
   UPDATE ISSUE
========================================================= */

app.patch(
  "/api/issues/:id",
  auth,
  requireDatabase,
  async (req, res) => {
    try {
      const id =
        Number(req.params.id);

      const state =
        req.body.state ===
        "closed"
          ? "closed"
          : "open";

      const result =
        await pool.query(
          `
          UPDATE issues
          SET state = $1
          WHERE id = $2
          RETURNING *
          `,
          [
            state,
            id
          ]
        );

      if (
        result.rows.length ===
        0
      ) {
        return res.status(404).json({
          error:
            "Issue not found."
        });
      }

      return res.json(
        result.rows[0]
      );
    } catch (error) {
      console.error(
        "Issue update error:",
        error
      );

      return res.status(500).json({
        error:
          "Issue update failed."
      });
    }
  }
);

/* =========================================================
   SEARCH
========================================================= */

app.get(
  "/api/search",
  requireDatabase,
  async (req, res) => {
    try {
      const q =
        String(
          req.query.q || ""
        ).trim();

      if (!q) {
        return res.json({
          users: [],
          repositories: []
        });
      }

      const users =
        await pool.query(
          `
          SELECT
            id,
            username,
            bio,
            avatar
          FROM users
          WHERE username ILIKE $1
          ORDER BY username
          LIMIT 20
          `,
          ["%" + q + "%"]
        );

      const repositories =
        await pool.query(
          `
          SELECT
            r.id,
            r.name,
            r.description,
            r.stars,
            u.username AS owner
          FROM repositories r
          JOIN users u
            ON u.id = r.owner_id
          WHERE
            r.visibility = 'public'
            AND (
              r.name ILIKE $1
              OR r.description ILIKE $1
            )
          ORDER BY r.stars DESC
          LIMIT 30
          `,
          ["%" + q + "%"]
        );

      return res.json({
        users:
          users.rows,
        repositories:
          repositories.rows
      });
    } catch (error) {
      console.error(
        "Search error:",
        error
      );

      return res.status(500).json({
        error:
          "Search failed."
      });
    }
  }
);

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
  content="width=device-width,initial-scale=1"
>
<title>NOVAIX</title>

<style>

*{
  box-sizing:border-box;
}

html,
body{
  margin:0;
  min-height:100%;
  background:#050506;
  color:#f6f6f7;
  font-family:
    Inter,
    system-ui,
    -apple-system,
    BlinkMacSystemFont,
    "Segoe UI",
    sans-serif;
}

body{
  overflow-x:hidden;
}

a{
  color:inherit;
  text-decoration:none;
}

button,
input,
textarea{
  font:inherit;
}

button{
  cursor:pointer;
}

.nav{
  height:76px;
  border-bottom:1px solid #1d1d24;
  display:flex;
  align-items:center;
  justify-content:space-between;
  padding:0 7%;
  background:rgba(5,5,6,.86);
  backdrop-filter:blur(20px);
  position:sticky;
  top:0;
  z-index:20;
}

.logo{
  display:flex;
  align-items:center;
  gap:12px;
  font-weight:900;
  font-size:21px;
}

.logoIcon{
  width:38px;
  height:38px;
  border-radius:12px;
  display:grid;
  place-items:center;
  background:
    linear-gradient(
      135deg,
      #fff,
      #a99cff
    );
  color:#111;
  font-weight:900;
  box-shadow:
    0 0 30px
    rgba(154,136,255,.25);
}

.navLinks{
  display:flex;
  align-items:center;
  gap:28px;
  color:#a9a9b4;
}

.navLinks a:hover{
  color:white;
}

.btn{
  border:0;
  border-radius:13px;
  padding:13px 20px;
  font-weight:800;
}

.btnPrimary{
  background:
    linear-gradient(
      135deg,
      #fff,
      #b5a7ff
    );
  color:#111;
}

.btnDark{
  background:#111116;
  border:1px solid #292932;
  color:white;
}

.hero{
  max-width:1200px;
  margin:0 auto;
  padding:100px 24px;
  text-align:center;
}

.badge{
  display:inline-flex;
  padding:8px 13px;
  border:1px solid #292938;
  background:#101017;
  border-radius:999px;
  color:#bdb7ff;
  font-size:13px;
  font-weight:700;
}

.hero h1{
  font-size:
    clamp(52px,8vw,100px);
  line-height:.95;
  letter-spacing:-5px;
  margin:28px 0;
}

.gradient{
  background:
    linear-gradient(
      135deg,
      #fff,
      #b8adff,
      #7e72ff
    );
  -webkit-background-clip:text;
  background-clip:text;
  color:transparent;
}

.hero p{
  max-width:720px;
  margin:0 auto;
  color:#92929d;
  font-size:19px;
  line-height:1.7;
}

.actions{
  display:flex;
  justify-content:center;
  gap:12px;
  margin-top:32px;
}

.container{
  width:min(1180px,92%);
  margin:auto;
}

.panel{
  background:
    linear-gradient(
      180deg,
      #101016,
      #09090c
    );
  border:1px solid #24242d;
  border-radius:22px;
  padding:24px;
  box-shadow:
    0 30px 80px
    rgba(0,0,0,.35);
}

.grid{
  display:grid;
  grid-template-columns:
    repeat(
      auto-fit,
      minmax(260px,1fr)
    );
  gap:18px;
}

.card{
  background:#0d0d12;
  border:1px solid #22222b;
  border-radius:18px;
  padding:22px;
}

.card h3{
  margin-top:0;
}

.muted{
  color:#8d8d99;
}

.input{
  width:100%;
  padding:15px 16px;
  border-radius:13px;
  border:1px solid #292933;
  background:#08080b;
  color:white;
  outline:none;
  margin:7px 0 16px;
}

.input:focus{
  border-color:#9d91ff;
  box-shadow:
    0 0 0 3px
    rgba(157,145,255,.12);
}

label{
  font-size:12px;
  font-weight:800;
  color:#a9a9b5;
  text-transform:uppercase;
}

.form{
  width:min(460px,100%);
  margin:60px auto;
}

.alert{
  padding:13px 15px;
  border-radius:12px;
  margin-bottom:18px;
  background:#281518;
  border:1px solid #603035;
  color:#ffb4bc;
}

.success{
  background:#122117;
  border-color:#285b39;
  color:#a5efb8;
}

.repo{
  transition:.2s;
}

.repo:hover{
  transform:translateY(-3px);
  border-color:#514b78;
}

.repoName{
  font-size:19px;
  font-weight:850;
  color:#b9adff;
}

.stats{
  display:flex;
  gap:20px;
  margin-top:15px;
  color:#888894;
  font-size:13px;
}

.code{
  background:#07070a;
  border:1px solid #24242c;
  border-radius:15px;
  padding:20px;
  overflow:auto;
  color:#d6d2ff;
  white-space:pre-wrap;
  font-family:
    ui-monospace,
    SFMono-Regular,
    Consolas,
    monospace;
}

.footer{
  border-top:1px solid #1b1b21;
  margin-top:100px;
  padding:30px 7%;
  color:#666672;
  display:flex;
  justify-content:space-between;
}

.hidden{
  display:none!important;
}

@media(max-width:700px){

  .nav{
    padding:0 20px;
  }

  .navLinks a:not(.btn){
    display:none;
  }

  .hero{
    padding:70px 20px;
  }

  .hero h1{
    letter-spacing:-3px;
  }

  .actions{
    flex-direction:column;
  }

  .footer{
    flex-direction:column;
    gap:10px;
  }

}

</style>
</head>

<body>

<header class="nav">

<a href="/" class="logo">
  <span class="logoIcon">N</span>
  NOVAIX
</a>

<nav class="navLinks">
  <a href="/">Home</a>
  <a href="/repositories">Repositories</a>
  <a href="/login" id="loginLink">Login</a>
  <a
    href="/register"
    class="btn btnPrimary"
    id="startLink"
  >
    Get Started
  </a>
</nav>

</header>

<main id="app"></main>

<footer class="footer">
  <span>© ${new Date().getFullYear()} NOVAIX</span>
  <span>Built for the next generation.</span>
</footer>

<script>

const API = "/api";

/* =========================================================
   FRONTEND HELPERS
========================================================= */

function token(){
  return localStorage.getItem(
    "novaix_token"
  );
}

function user(){
  try{
    return JSON.parse(
      localStorage.getItem(
        "novaix_user"
      )
    );
  }catch(error){
    return null;
  }
}

function headers(){

  const h = {
    "Content-Type":
      "application/json"
  };

  if(token()){
    h.Authorization =
      "Bearer " + token();
  }

  return h;
}

async function api(
  url,
  options
){

  options =
    options || {};

  const response =
    await fetch(
      API + url,
      {
        ...options,
        headers:{
          ...headers(),
          ...(options.headers || {})
        }
      }
    );

  const data =
    await response
      .json()
      .catch(function(){
        return {};
      });

  if(!response.ok){
    throw new Error(
      data.error ||
      "Request failed"
    );
  }

  return data;
}

function escapeHtml(value){

  return String(
    value == null
      ? ""
      : value
  )
    .replaceAll(
      "&",
      "&amp;"
    )
    .replaceAll(
      "<",
      "&lt;"
    )
    .replaceAll(
      ">",
      "&gt;"
    )
    .replaceAll(
      '"',
      "&quot;"
    )
    .replaceAll(
      "'",
      "&#039;"
    );
}

function layout(content){

  document.getElementById(
    "app"
  ).innerHTML = content;

  updateNavigation();
}

function updateNavigation(){

  const logged =
    !!token();

  const login =
    document.getElementById(
      "loginLink"
    );

  const start =
    document.getElementById(
      "startLink"
    );

  if(login){

    login.textContent =
      logged
        ? "Dashboard"
        : "Login";

    login.href =
      logged
        ? "/dashboard"
        : "/login";
  }

  if(start){

    if(logged){
      start.textContent =
        "Dashboard";
      start.href =
        "/dashboard";
    }else{
      start.textContent =
        "Get Started";
      start.href =
        "/register";
    }
  }
}

/* =========================================================
   HOME
========================================================= */

function home(){

  layout(
    '<section class="hero">' +

      '<div class="badge">' +
        'Developer platform for the next generation' +
      '</div>' +

      '<h1>' +
        'Build. ' +
        '<span class="gradient">Ship.</span> ' +
        'Scale.' +
      '</h1>' +

      '<p>' +
        'NOVAIX is a modern developer platform for repositories, ' +
        'collaboration, issues, commits and open source projects.' +
      '</p>' +

      '<div class="actions">' +

        '<a ' +
          'class="btn btnPrimary" ' +
          'href="/register">' +
          'Create your account →' +
        '</a>' +

        '<a ' +
          'class="btn btnDark" ' +
          'href="/repositories">' +
          'Explore repositories' +
        '</a>' +

      '</div>' +

    '</section>' +

    '<section class="container">' +

      '<div class="grid">' +

        '<div class="card">' +
          '<h3>Repositories</h3>' +
          '<p class="muted">' +
            'Create and manage your projects with a clean developer workflow.' +
          '</p>' +
        '</div>' +

        '<div class="card">' +
          '<h3>Collaboration</h3>' +
          '<p class="muted">' +
            'Stars, issues, profiles and commits in one place.' +
          '</p>' +
        '</div>' +

        '<div class="card">' +
          '<h3>Built for scale</h3>' +
          '<p class="muted">' +
            'PostgreSQL-backed architecture ready for Render deployment.' +
          '</p>' +
        '</div>' +

      '</div>' +

    '</section>'
  );
}

/* =========================================================
   LOGIN
========================================================= */

function loginPage(){

  layout(
    '<section class="container">' +

      '<div class="panel form">' +

        '<div class="logo">' +
          '<span class="logoIcon">N</span>' +
          'NOVAIX' +
        '</div>' +

        '<h1>Welcome back</h1>' +

        '<p class="muted">' +
          'Sign in to continue to NOVAIX.' +
        '</p>' +

        '<div id="error"></div>' +

        '<form id="loginForm">' +

          '<label>Email</label>' +

          '<input ' +
            'class="input" ' +
            'id="email" ' +
            'type="email" ' +
            'required ' +
            'placeholder="you@example.com">' +

          '<label>Password</label>' +

          '<input ' +
            'class="input" ' +
            'id="password" ' +
            'type="password" ' +
            'required ' +
            'placeholder="••••••••">' +

          '<button ' +
            'class="btn btnPrimary" ' +
            'style="width:100%">' +
            'Sign In →' +
          '</button>' +

        '</form>' +

        '<p class="muted">' +
          "Don't have an account? " +
          '<a ' +
            'href="/register" ' +
            'style="color:#b9adff">' +
            'Create one' +
          '</a>' +
        '</p>' +

      '</div>' +

    '</section>'
  );

  const form =
    document.getElementById(
      "loginForm"
    );

  if(!form) return;

  form.addEventListener(
    "submit",
    async function(e){

      e.preventDefault();

      const error =
        document.getElementById(
          "error"
        );

      try{

        const data =
          await api(
            "/login",
            {
              method:"POST",
              body:JSON.stringify({
                email:
                  document.getElementById(
                    "email"
                  ).value,
                password:
                  document.getElementById(
                    "password"
                  ).value
              })
            }
          );

        localStorage.setItem(
          "novaix_token",
          data.token
        );

        localStorage.setItem(
          "novaix_user",
          JSON.stringify(
            data.user
          )
        );

        location.href =
          "/dashboard";

      }catch(err){

        error.innerHTML =
          '<div class="alert">' +
          escapeHtml(
            err.message
          ) +
          '</div>';
      }
    }
  );
}

/* =========================================================
   REGISTER
========================================================= */

function registerPage(){

  layout(
    '<section class="container">' +

      '<div class="panel form">' +

        '<div class="logo">' +
          '<span class="logoIcon">N</span>' +
          'NOVAIX' +
        '</div>' +

        '<h1>Create account</h1>' +

        '<p class="muted">' +
          'Start building with NOVAIX.' +
        '</p>' +

        '<div id="error"></div>' +

        '<form id="registerForm">' +

          '<label>Username</label>' +

          '<input ' +
            'class="input" ' +
            'id="username" ' +
            'required ' +
            'placeholder="yourname">' +

          '<label>Email</label>' +

          '<input ' +
            'class="input" ' +
            'id="email" ' +
            'type="email" ' +
            'required ' +
            'placeholder="you@example.com">' +

          '<label>Password</label>' +

          '<input ' +
            'class="input" ' +
            'id="password" ' +
            'type="password" ' +
            'minlength="6" ' +
            'required ' +
            'placeholder="At least 6 characters">' +

          '<button ' +
            'class="btn btnPrimary" ' +
            'style="width:100%">' +
            'Create Account →' +
          '</button>' +

        '</form>' +

        '<p class="muted">' +
          'Already have an account? ' +
          '<a ' +
            'href="/login" ' +
            'style="color:#b9adff">' +
            'Sign in' +
          '</a>' +
        '</p>' +

      '</div>' +

    '</section>'
  );

  const form =
    document.getElementById(
      "registerForm"
    );

  if(!form) return;

  form.addEventListener(
    "submit",
    async function(e){

      e.preventDefault();

      const error =
        document.getElementById(
          "error"
        );

      try{

        const data =
          await api(
            "/register",
            {
              method:"POST",
              body:JSON.stringify({
                username:
                  document.getElementById(
                    "username"
                  ).value,
                email:
                  document.getElementById(
                    "email"
                  ).value,
                password:
                  document.getElementById(
                    "password"
                  ).value
              })
            }
          );

        localStorage.setItem(
          "novaix_token",
          data.token
        );

        localStorage.setItem(
          "novaix_user",
          JSON.stringify(
            data.user
          )
        );

        location.href =
          "/dashboard";

      }catch(err){

        error.innerHTML =
          '<div class="alert">' +
          escapeHtml(
            err.message
          ) +
          '</div>';
      }
    }
  );
}

/* =========================================================
   DASHBOARD
========================================================= */

async function dashboard(){

  if(!token()){
    location.href =
      "/login";
    return;
  }

  const u = user();

  let repos = [];

  try{

    const all =
      await api(
        "/repos"
      );

    repos =
      all.filter(
        function(r){
          return (
            u &&
            r.owner ===
              u.username
          );
        }
      );

  }catch(error){
    console.error(error);
  }

  let repoHtml = "";

  if(repos.length){

    repoHtml =
      repos.map(
        function(repo){

          return (
            '<a ' +
              'class="card repo" ' +
              'href="/repo/' +
              encodeURIComponent(
                repo.owner
              ) +
              '/' +
              encodeURIComponent(
                repo.name
              ) +
              '">' +

              '<div class="repoName">' +
                escapeHtml(
                  repo.name
                ) +
              '</div>' +

              '<p class="muted">' +
                escapeHtml(
                  repo.description ||
                  "No description"
                ) +
              '</p>' +

              '<div class="stats">' +
                '<span>★ ' +
                  repo.stars +
                '</span>' +
                '<span>' +
                  escapeHtml(
                    repo.visibility
                  ) +
                '</span>' +
              '</div>' +

            '</a>'
          );
        }
      ).join("");

  }else{

    repoHtml =
      '<div class="card">' +
        '<h3>No repositories yet</h3>' +
        '<p class="muted">' +
          'Create your first repository.' +
        '</p>' +
      '</div>';
  }

  layout(
    '<section ' +
      'class="container" ' +
      'style="padding:60px 0">' +

      '<div class="panel">' +

        '<h1>Welcome, ' +
          escapeHtml(
            u &&
            u.username
              ? u.username
              : "Developer"
          ) +
        '</h1>' +

        '<p class="muted">' +
          'Your NOVAIX developer workspace.' +
        '</p>' +

        '<div ' +
          'class="actions" ' +
          'style="justify-content:flex-start">' +

          '<button ' +
            'class="btn btnPrimary" ' +
            'onclick="createRepo()">' +
            '+ New Repository' +
          '</button>' +

          '<button ' +
            'class="btn btnDark" ' +
            'onclick="logout()">' +
            'Logout' +
          '</button>' +

        '</div>' +

      '</div>' +

      '<h2 style="margin-top:45px">' +
        'Your repositories' +
      '</h2>' +

      '<div class="grid">' +
        repoHtml +
      '</div>' +

    '</section>'
  );
}

/* =========================================================
   CREATE REPOSITORY
========================================================= */

async function createRepo(){

  const name =
    prompt(
      "Repository name:"
    );

  if(!name) return;

  const description =
    prompt(
      "Description:"
    ) || "";

  try{

    await api(
      "/repos",
      {
        method:"POST",
        body:JSON.stringify({
          name:name,
          description:
            description,
          visibility:
            "public"
        })
      }
    );

    alert(
      "Repository created!"
    );

    await dashboard();

  }catch(error){

    alert(
      error.message
    );
  }
}

/* =========================================================
   REPOSITORIES
========================================================= */

async function repositories(){

  try{

    const repos =
      await api(
        "/repos"
      );

    let repoHtml = "";

    if(repos.length){

      repoHtml =
        repos.map(
          function(repo){

            return (
              '<a ' +
                'class="card repo" ' +
                'href="/repo/' +
                encodeURIComponent(
                  repo.owner
                ) +
                '/' +
                encodeURIComponent(
                  repo.name
                ) +
                '">' +

                '<div class="repoName">' +
                  escapeHtml(
                    repo.owner
                  ) +
                  '/' +
                  escapeHtml(
                    repo.name
                  ) +
                '</div>' +

                '<p class="muted">' +
                  escapeHtml(
                    repo.description ||
                    "No description"
                  ) +
                '</p>' +

                '<div class="stats">' +
                  '<span>★ ' +
                    repo.stars +
                  '</span>' +

                  '<span>' +
                    escapeHtml(
                      repo.default_branch
                    ) +
                  '</span>' +
                '</div>' +

              '</a>'
            );
          }
        ).join("");

    }else{

      repoHtml =
        '<div class="card">' +
          'No repositories found.' +
        '</div>';
    }

    const dashboardButton =
      token()
        ? (
          '<a ' +
            'class="btn btnPrimary" ' +
            'href="/dashboard">' +
            'Dashboard' +
          '</a>'
        )
        : "";

    layout(
      '<section ' +
        'class="container" ' +
        'style="padding:60px 0">' +

        '<div ' +
          'style="' +
            'display:flex;' +
            'justify-content:space-between;' +
            'align-items:center;' +
            'gap:20px;' +
            'flex-wrap:wrap">' +

          '<div>' +
            '<h1>Explore repositories</h1>' +
            '<p class="muted">' +
              'Discover public projects on NOVAIX.' +
            '</p>' +
          '</div>' +

          dashboardButton +

        '</div>' +

        '<div ' +
          'class="grid" ' +
          'style="margin-top:30px">' +
          repoHtml +
        '</div>' +

      '</section>'
    );

  }catch(error){

    layout(
      '<section ' +
        'class="container" ' +
        'style="padding:80px 0">' +

        '<div class="alert">' +
          escapeHtml(
            error.message
          ) +
        '</div>' +

      '</section>'
    );
  }
}

/* =========================================================
   REPOSITORY PAGE
========================================================= */

async function repository(
  username,
  repo
){

  try{

    const data =
      await api(
        "/repos/" +
        encodeURIComponent(
          username
        ) +
        "/" +
        encodeURIComponent(
          repo
        )
      );

    const r =
      data.repository;

    let filesHtml = "";

    if(data.files.length){

      filesHtml =
        data.files.map(
          function(file){

            return (
              '<div class="card">' +

                '<h3>' +
                  escapeHtml(
                    file.file_path
                  ) +
                '</h3>' +

                '<div class="code">' +
                  escapeHtml(
                    file.content
                  ) +
                '</div>' +

              '</div>'
            );
          }
        ).join("");

    }else{

      filesHtml =
        '<div class="card">' +
          'No files.' +
        '</div>';
    }

    let commitsHtml = "";

    if(data.commits.length){

      commitsHtml =
        data.commits.map(
          function(c){

            return (
              '<div class="card">' +

                '<b>' +
                  escapeHtml(
                    c.message
                  ) +
                '</b>' +

                '<p class="muted">' +
                  escapeHtml(
                    c.username ||
                    "Unknown"
                  ) +
                '</p>' +

                '<small class="muted">' +
                  escapeHtml(
                    new Date(
                      c.created_at
                    ).toLocaleString()
                  ) +
                '</small>' +

              '</div>'
            );
          }
        ).join("");

    }else{

      commitsHtml =
        '<div class="card">' +
          'No commits yet.' +
        '</div>';
    }

    let issuesHtml = "";

    if(data.issues.length){

      issuesHtml =
        data.issues.map(
          function(i){

            return (
              '<div class="card">' +

                '<h3>' +
                  escapeHtml(
                    i.title
                  ) +
                '</h3>' +

                '<p class="muted">' +
                  escapeHtml(
                    i.body || ""
                  ) +
                '</p>' +

                '<span class="badge">' +
                  escapeHtml(
                    i.state
                  ) +
                '</span>' +

              '</div>'
            );
          }
        ).join("");

    }else{

      issuesHtml =
        '<div class="card">' +
          'No issues yet.' +
        '</div>';
    }

    let starHtml = "";

    if(token()){

      starHtml =
        '<button ' +
          'class="btn btnPrimary" ' +
          'onclick="starRepo(' +
            Number(r.id) +
          ')">' +
          '★ Star' +
        '</button>';

    }else{

      starHtml =
        '<a ' +
          'class="btn btnPrimary" ' +
          'href="/login">' +
          'Login to Star' +
        '</a>';
    }

    let issueFormHtml = "";

    if(token()){

      issueFormHtml =
        '<div ' +
          'class="panel" ' +
          'style="margin-top:40px">' +

          '<h2>Create issue</h2>' +

          '<input ' +
            'id="issueTitle" ' +
            'class="input" ' +
            'placeholder="Issue title">' +

          '<textarea ' +
            'id="issueBody" ' +
            'class="input" ' +
            'rows="6" ' +
            'placeholder="Describe the issue...">' +
          '</textarea>' +

          '<button ' +
            'class="btn btnPrimary" ' +
            'onclick="createIssue(' +
              Number(r.id) +
            ')">' +
            'Open Issue' +
          '</button>' +

        '</div>';
    }

    layout(
      '<section ' +
        'class="container" ' +
        'style="padding:60px 0">' +

        '<div class="panel">' +

          '<div class="muted">' +
            escapeHtml(
              r.owner
            ) +
          '</div>' +

          '<h1>' +
            escapeHtml(
              r.name
            ) +
          '</h1>' +

          '<p class="muted">' +
            escapeHtml(
              r.description ||
              "No description"
            ) +
          '</p>' +

          '<div class="stats">' +
            '<span>★ ' +
              r.stars +
            '</span>' +

            '<span>' +
              escapeHtml(
                r.visibility
              ) +
            '</span>' +

            '<span>' +
              escapeHtml(
                r.default_branch
              ) +
            '</span>' +
          '</div>' +

          '<div ' +
            'class="actions" ' +
            'style="justify-content:flex-start">' +
            starHtml +
          '</div>' +

        '</div>' +

        '<h2 style="margin-top:40px">' +
          'Files' +
        '</h2>' +

        '<div class="grid">' +
          filesHtml +
        '</div>' +

        '<h2 style="margin-top:45px">' +
          'Commits' +
        '</h2>' +

        '<div class="grid">' +
          commitsHtml +
        '</div>' +

        '<h2 style="margin-top:45px">' +
          'Issues' +
        '</h2>' +

        '<div class="grid">' +
          issuesHtml +
        '</div>' +

        issueFormHtml +

      '</section>'
    );

  }catch(error){

    layout(
      '<section ' +
        'class="container" ' +
        'style="padding:80px 0">' +

        '<div class="alert">' +
          escapeHtml(
            error.message
          ) +
        '</div>' +

      '</section>'
    );
  }
}

/* =========================================================
   STAR
========================================================= */

async function starRepo(id){

  try{

    await api(
      "/repos/" +
      id +
      "/star",
      {
        method:"POST"
      }
    );

    alert(
      "Star updated!"
    );

    location.reload();

  }catch(error){

    alert(
      error.message
    );
  }
}

/* =========================================================
   CREATE ISSUE
========================================================= */

async function createIssue(id){

  const titleElement =
    document.getElementById(
      "issueTitle"
    );

  const bodyElement =
    document.getElementById(
      "issueBody"
    );

  if(!titleElement){
    return;
  }

  const title =
    titleElement.value.trim();

  const body =
    bodyElement
      ? bodyElement.value
      : "";

  if(!title){

    alert(
      "Issue title required."
    );

    return;
  }

  try{

    await api(
      "/repos/" +
      id +
      "/issues",
      {
        method:"POST",
        body:JSON.stringify({
          title:title,
          body:body
        })
      }
    );

    alert(
      "Issue created!"
    );

    location.reload();

  }catch(error){

    alert(
      error.message
    );
  }
}

/* =========================================================
   LOGOUT
========================================================= */

async function logout(){

  try{

    await api(
      "/logout",
      {
        method:"POST"
      }
    );

  }catch(error){

    console.error(
      error
    );
  }

  localStorage.removeItem(
    "novaix_token"
  );

  localStorage.removeItem(
    "novaix_user"
  );

  location.href = "/";
}

/* =========================================================
   ROUTER
========================================================= */

function router(){

  const p =
    location.pathname;

  if(p === "/"){
    home();
    return;
  }

  if(p === "/login"){
    loginPage();
    return;
  }

  if(p === "/register"){
    registerPage();
    return;
  }

  if(p === "/dashboard"){
    dashboard();
    return;
  }

  if(p === "/repositories"){
    repositories();
    return;
  }

  if(
    p.startsWith(
      "/repo/"
    )
  ){

    const parts =
      p.substring(
        "/repo/".length
      )
      .split("/")
      .map(
        function(value){
          return decodeURIComponent(
            value
          );
        }
      );

    if(parts.length >= 2){

      repository(
        parts[0],
        parts[1]
      );

      return;
    }
  }

  home();
}

/* =========================================================
   SPA NAVIGATION
========================================================= */

document.addEventListener(
  "click",
  function(e){

    const a =
      e.target.closest(
        "a"
      );

    if(!a) return;

    const href =
      a.getAttribute(
        "href"
      );

    if(
      !href ||
      !href.startsWith("/") ||
      href.startsWith("//")
    ){
      return;
    }

    if(
      a.target === "_blank" ||
      e.ctrlKey ||
      e.metaKey ||
      e.shiftKey ||
      e.altKey
    ){
      return;
    }

    e.preventDefault();

    history.pushState(
      {},
      "",
      href
    );

    router();
  }
);

window.addEventListener(
  "popstate",
  router
);

router();

</script>

</body>
</html>
`;

/* =========================================================
   FRONTEND FALLBACK
========================================================= */

app.get(
  "/{*splat}",
  function(req, res){

    if(
      req.path.startsWith(
        "/api/"
      )
    ){
      return res.status(404).json({
        error:
          "API endpoint not found"
      });
    }

    return res
      .type("html")
      .send(html);
  }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  function(error, req, res, next){

    console.error(
      "Unhandled server error:",
      error
    );

    if(res.headersSent){
      return next(error);
    }

    return res.status(500).json({
      error:
        "Internal server error."
    });
  }
);

/* =========================================================
   START
========================================================= */

async function start(){

  try{

    await initDatabase();

  }catch(error){

    console.error(
      "Database initialization failed:",
      error.message
    );

    console.error(
      "Server will continue running."
    );
  }

  app.listen(
    PORT,
    "0.0.0.0",
    function(){

      console.log("");
      console.log(
        "================================="
      );
      console.log(
        "        NOVAIX SERVER"
      );
      console.log(
        "================================="
      );
      console.log(
        "Port:",
        PORT
      );
      console.log(
        "Environment:",
        process.env.NODE_ENV ||
        "production"
      );
      console.log(
        "Database:",
        DATABASE_URL
          ? "CONFIGURED"
          : "MISSING"
      );
      console.log(
        "================================="
      );
      console.log("");
    }
  );
}

start();
