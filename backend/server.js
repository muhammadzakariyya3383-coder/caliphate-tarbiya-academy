const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";

app.use(cors());
app.use(express.json({ limit: "10mb" }));

/* =========================
   DATABASE
========================= */

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is missing.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

async function query(text, params = []) {
  return pool.query(text, params);
}

/* =========================
   DATABASE INITIALIZATION
========================= */

async function initializeDatabase() {
  console.log("Initializing database...");

  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      full_name VARCHAR(200) NOT NULL,
      email VARCHAR(200),
      phone VARCHAR(50),
      role VARCHAR(30) NOT NULL DEFAULT 'teacher',
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      is_hod BOOLEAN NOT NULL DEFAULT FALSE,
      is_exam_officer BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS classes (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) UNIQUE NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS subjects (
      id SERIAL PRIMARY KEY,
      name VARCHAR(150) UNIQUE NOT NULL,
      code VARCHAR(50),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS teacher_subjects (
      teacher_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      subject_id INTEGER REFERENCES subjects(id) ON DELETE CASCADE,
      PRIMARY KEY (teacher_id, subject_id)
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS teacher_classes (
      teacher_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      class_id INTEGER REFERENCES classes(id) ON DELETE CASCADE,
      PRIMARY KEY (teacher_id, class_id)
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS hod_subjects (
      teacher_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      subject_id INTEGER REFERENCES subjects(id) ON DELETE CASCADE,
      PRIMARY KEY (teacher_id, subject_id)
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS documents (
      id SERIAL PRIMARY KEY,
      teacher_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      document_type VARCHAR(50) NOT NULL,
      title VARCHAR(255) NOT NULL,
      subject_id INTEGER REFERENCES subjects(id) ON DELETE SET NULL,
      class_id INTEGER REFERENCES classes(id) ON DELETE SET NULL,
      session VARCHAR(50),
      term VARCHAR(50),
      week VARCHAR(50),
      topic VARCHAR(255),
      content TEXT,
      status VARCHAR(30) DEFAULT 'draft',
      submitted_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS assessments (
      id SERIAL PRIMARY KEY,
      teacher_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      assessment_type VARCHAR(50) NOT NULL,
      title VARCHAR(255) NOT NULL,
      subject_id INTEGER REFERENCES subjects(id) ON DELETE SET NULL,
      class_id INTEGER REFERENCES classes(id) ON DELETE SET NULL,
      session VARCHAR(50),
      term VARCHAR(50),
      duration VARCHAR(50),
      total_marks INTEGER DEFAULT 0,
      objective_questions TEXT,
      theory_questions TEXT,
      marking_scheme TEXT,
      status VARCHAR(30) DEFAULT 'draft',
      submitted_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS approvals (
      id SERIAL PRIMARY KEY,
      document_id INTEGER REFERENCES documents(id) ON DELETE CASCADE,
      assessment_id INTEGER REFERENCES assessments(id) ON DELETE CASCADE,
      approver_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      approval_level VARCHAR(50),
      decision VARCHAR(30),
      comment TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS approved_archive (
      id SERIAL PRIMARY KEY,
      document_id INTEGER,
      assessment_id INTEGER,
      document_type VARCHAR(50),
      title VARCHAR(255),
      teacher_id INTEGER,
      subject_id INTEGER,
      class_id INTEGER,
      session VARCHAR(50),
      term VARCHAR(50),
      week VARCHAR(50),
      topic VARCHAR(255),
      content TEXT,
      approved_by INTEGER,
      approved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      action VARCHAR(255),
      details TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS school_settings (
      id INTEGER PRIMARY KEY DEFAULT 1,
      school_name VARCHAR(255) DEFAULT 'Caliphate Tarbiya Academy',
      address TEXT,
      phone VARCHAR(100),
      email VARCHAR(200),
      logo_url TEXT,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await query(`
    INSERT INTO school_settings (id)
    VALUES (1)
    ON CONFLICT (id) DO NOTHING;
  `);

  console.log("Database tables initialized successfully.");
}

/* =========================
   ADMIN SEED
========================= */

async function seedAdmin() {
  const username = process.env.ADMIN_USERNAME || "admin";
  const password = process.env.ADMIN_PASSWORD;

  if (!password) {
    console.error("ADMIN_PASSWORD is missing in Railway Variables.");
    return;
  }

  const existing = await query(
    "SELECT id, role, is_active FROM users WHERE username = $1",
    [username]
  );

  if (existing.rows.length === 0) {
    const hash = await bcrypt.hash(password, 12);

    await query(
      `INSERT INTO users
       (username, password_hash, full_name, role, is_active)
       VALUES ($1, $2, $3, 'admin', TRUE)`,
      [username, hash, "System Administrator"]
    );

    console.log("======================================");
    console.log("ADMIN ACCOUNT CREATED SUCCESSFULLY");
    console.log("Username:", username);
    console.log("======================================");
  } else {
    await query(
      "UPDATE users SET role = 'admin', is_active = TRUE WHERE username = $1",
      [username]
    );

    console.log("Admin account already exists:", username);
  }
}

/* =========================
   AUTHENTICATION
========================= */

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authenticate(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Authentication required."
    });
  }

  const token = header.substring(7);

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired session."
    });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Administrator access required."
    });
  }

  next();
}

/* =========================
   HEALTH
========================= */

app.get("/", (req, res) => {
  res.json({
    success: true,
    system: "Caliphate Tarbiya Academy",
    message: "Backend is running."
  });
});

app.get("/api/health", async (req, res) => {
  try {
    await query("SELECT NOW()");

    res.json({
      success: true,
      database: "connected",
      system: "Caliphate Tarbiya Academy"
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      database: "error"
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password are required."
      });
    }

    const result = await query(
      `SELECT *
       FROM users
       WHERE LOWER(username) = LOWER($1)
       LIMIT 1`,
      [username.trim()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password."
      });
    }

    const user = result.rows[0];

    if (!user.is_active) {
      return res.status(403).json({
        success: false,
        message: "This account has been deactivated."
      });
    }

    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password."
      });
    }

    const token = createToken(user);

    await query(
      `INSERT INTO audit_logs (user_id, action, details)
       VALUES ($1, $2, $3)`,
      [user.id, "LOGIN", "Successful login"]
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        email: user.email,
        phone: user.phone,
        role: user.role,
        is_hod: user.is_hod,
        is_exam_officer: user.is_exam_officer
      }
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Login failed."
    });
  }
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/auth/me", authenticate, async (req, res) => {
  const result = await query(
    `SELECT id, username, full_name, email, phone,
            role, is_active, is_hod, is_exam_officer
     FROM users
     WHERE id = $1`,
    [req.user.id]
  );

  if (!result.rows.length) {
    return res.status(404).json({
      success: false,
      message: "User not found."
    });
  }

  res.json({
    success: true,
    user: result.rows[0]
  });
});

/* =========================
   CHANGE PASSWORD
========================= */

app.post("/api/auth/change-password", authenticate, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;

    if (!current_password || !new_password) {
      return res.status(400).json({
        success: false,
        message: "Current and new passwords are required."
      });
    }

    if (new_password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "New password must contain at least 6 characters."
      });
    }

    const result = await query(
      "SELECT password_hash FROM users WHERE id = $1",
      [req.user.id]
    );

    const valid = await bcrypt.compare(
      current_password,
      result.rows[0].password_hash
    );

    if (!valid) {
      return res.status(400).json({
        success: false,
        message: "Current password is incorrect."
      });
    }

    const hash = await bcrypt.hash(new_password, 12);

    await query(
      `UPDATE users
       SET password_hash = $1, updated_at = CURRENT_TIMESTAMP
       WHERE id = $2`,
      [hash, req.user.id]
    );

    res.json({
      success: true,
      message: "Password changed successfully."
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Unable to change password."
    });
  }
});

/* =========================
   ADMIN — CREATE TEACHER
========================= */

app.post(
  "/api/users/teachers",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const {
        username,
        password,
        full_name,
        email,
        phone,
        is_hod = false,
        is_exam_officer = false
      } = req.body;

      if (!username || !password || !full_name) {
        return res.status(400).json({
          success: false,
          message: "Username, password and full name are required."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message: "Teacher password must contain at least 6 characters."
        });
      }

      const exists = await query(
        "SELECT id FROM users WHERE LOWER(username) = LOWER($1)",
        [username.trim()]
      );

      if (exists.rows.length) {
        return res.status(409).json({
          success: false,
          message: "Username already exists."
        });
      }

      const hash = await bcrypt.hash(password, 12);

      const result = await query(
        `INSERT INTO users
        (username, password_hash, full_name, email, phone,
         role, is_active, is_hod, is_exam_officer)
        VALUES ($1, $2, $3, $4, $5, 'teacher', TRUE, $6, $7)
        RETURNING id, username, full_name, email, phone,
                  role, is_active, is_hod, is_exam_officer`,
        [
          username.trim(),
          hash,
          full_name.trim(),
          email || null,
          phone || null,
          Boolean(is_hod),
          Boolean(is_exam_officer)
        ]
      );

      await query(
        `INSERT INTO audit_logs (user_id, action, details)
         VALUES ($1, $2, $3)`,
        [
          req.user.id,
          "CREATE_TEACHER",
          `Created teacher account: ${username}`
        ]
      );

      res.status(201).json({
        success: true,
        message: "Teacher account created successfully.",
        teacher: result.rows[0]
      });

    } catch (error) {
      console.error("CREATE TEACHER ERROR:", error);

      res.status(500).json({
        success: false,
        message: "Unable to create teacher."
      });
    }
  }
);

/* =========================
   ADMIN — LIST USERS
========================= */

app.get(
  "/api/users",
  authenticate,
  adminOnly,
  async (req, res) => {
    const result = await query(
      `SELECT id, username, full_name, email, phone,
              role, is_active, is_hod, is_exam_officer,
              created_at, updated_at
       FROM users
       ORDER BY full_name ASC`
    );

    res.json({
      success: true,
      users: result.rows
    });
  }
);

/* =========================
   ADMIN — UPDATE TEACHER
========================= */

app.put(
  "/api/users/teachers/:id",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      const {
        full_name,
        email,
        phone,
        is_active,
        is_hod,
        is_exam_officer
      } = req.body;

      const result = await query(
        `UPDATE users
         SET full_name = COALESCE($1, full_name),
             email = COALESCE($2, email),
             phone = COALESCE($3, phone),
             is_active = COALESCE($4, is_active),
             is_hod = COALESCE($5, is_hod),
             is_exam_officer = COALESCE($6, is_exam_officer),
             updated_at = CURRENT_TIMESTAMP
         WHERE id = $7
         AND role = 'teacher'
         RETURNING id, username, full_name, email, phone,
                   role, is_active, is_hod, is_exam_officer`,
        [
          full_name ?? null,
          email ?? null,
          phone ?? null,
          is_active ?? null,
          is_hod ?? null,
          is_exam_officer ?? null,
          id
        ]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          message: "Teacher not found."
        });
      }

      res.json({
        success: true,
        teacher: result.rows[0]
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Unable to update teacher."
      });
    }
  }
);

/* =========================
   ADMIN — RESET TEACHER PASSWORD
========================= */

app.post(
  "/api/users/teachers/:id/reset-password",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const id = Number(req.params.id);
      const { new_password } = req.body;

      if (!new_password || new_password.length < 6) {
        return res.status(400).json({
          success: false,
          message: "Password must contain at least 6 characters."
        });
      }

      const hash = await bcrypt.hash(new_password, 12);

      const result = await query(
        `UPDATE users
         SET password_hash = $1,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = $2
         AND role = 'teacher'
         RETURNING id, username`,
        [hash, id]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          message: "Teacher not found."
        });
      }

      res.json({
        success: true,
        message: "Teacher password reset successfully."
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Unable to reset password."
      });
    }
  }
);

/* =========================
   CLASSES
========================= */

app.get("/api/classes", authenticate, async (req, res) => {
  const result = await query(
    "SELECT * FROM classes ORDER BY name ASC"
  );

  res.json({
    success: true,
    classes: result.rows
  });
});

app.post(
  "/api/classes",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const { name } = req.body;

      if (!name) {
        return res.status(400).json({
          success: false,
          message: "Class name is required."
        });
      }

      const result = await query(
        `INSERT INTO classes (name)
         VALUES ($1)
         ON CONFLICT (name) DO NOTHING
         RETURNING *`,
        [name.trim()]
      );

      res.json({
        success: true,
        class: result.rows[0] || null
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        message: "Unable to create class."
      });
    }
  }
);

/* =========================
   SUBJECTS
========================= */

app.get("/api/subjects", authenticate, async (req, res) => {
  const result = await query(
    "SELECT * FROM subjects ORDER BY name ASC"
  );

  res.json({
    success: true,
    subjects: result.rows
  });
});

app.post(
  "/api/subjects",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const { name, code } = req.body;

      if (!name) {
        return res.status(400).json({
          success: false,
          message: "Subject name is required."
        });
      }

      const result = await query(
        `INSERT INTO subjects (name, code)
         VALUES ($1, $2)
         ON CONFLICT (name) DO NOTHING
         RETURNING *`,
        [name.trim(), code || null]
      );

      res.json({
        success: true,
        subject: result.rows[0] || null
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        message: "Unable to create subject."
      });
    }
  }
);

/* =========================
   TEACHER ASSIGNMENTS
========================= */

app.get(
  "/api/my/assignments",
  authenticate,
  async (req, res) => {
    const subjects = await query(
      `SELECT s.*
       FROM subjects s
       INNER JOIN teacher_subjects ts
       ON ts.subject_id = s.id
       WHERE ts.teacher_id = $1
       ORDER BY s.name`,
      [req.user.id]
    );

    const classes = await query(
      `SELECT c.*
       FROM classes c
       INNER JOIN teacher_classes tc
       ON tc.class_id = c.id
       WHERE tc.teacher_id = $1
       ORDER BY c.name`,
      [req.user.id]
    );

    res.json({
      success: true,
      subjects: subjects.rows,
      classes: classes.rows
    });
  }
);

app.put(
  "/api/users/teachers/:id/assignments",
  authenticate,
  adminOnly,
  async (req, res) => {
    const teacherId = Number(req.params.id);

    const subjectIds = Array.isArray(req.body.subject_ids)
      ? req.body.subject_ids
      : [];

    const classIds = Array.isArray(req.body.class_ids)
      ? req.body.class_ids
      : [];

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      await client.query(
        "DELETE FROM teacher_subjects WHERE teacher_id = $1",
        [teacherId]
      );

      await client.query(
        "DELETE FROM teacher_classes WHERE teacher_id = $1",
        [teacherId]
      );

      for (const subjectId of subjectIds) {
        await client.query(
          `INSERT INTO teacher_subjects
           (teacher_id, subject_id)
           VALUES ($1, $2)
           ON CONFLICT DO NOTHING`,
          [teacherId, Number(subjectId)]
        );
      }

      for (const classId of classIds) {
        await client.query(
          `INSERT INTO teacher_classes
           (teacher_id, class_id)
           VALUES ($1, $2)
           ON CONFLICT DO NOTHING`,
          [teacherId, Number(classId)]
        );
      }

      await client.query("COMMIT");

      res.json({
        success: true,
        message: "Teacher assignments saved."
      });

    } catch (error) {
      await client.query("ROLLBACK");

      console.error(error);

      res.status(500).json({
        success: false,
        message: "Unable to save assignments."
      });
    } finally {
      client.release();
    }
  }
);

/* =========================
   DOCUMENTS
========================= */

app.post(
  "/api/documents",
  authenticate,
  async (req, res) => {
    try {
      const {
        document_type,
        title,
        subject_id,
        class_id,
        session,
        term,
        week,
        topic,
        content
      } = req.body;

      if (!document_type || !title) {
        return res.status(400).json({
          success: false,
          message: "Document type and title are required."
        });
      }

      const result = await query(
        `INSERT INTO documents
        (teacher_id, document_type, title, subject_id,
         class_id, session, term, week, topic, content, status)
        VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'draft')
        RETURNING *`,
        [
          req.user.id,
          document_type,
          title,
          subject_id || null,
          class_id || null,
          session || null,
          term || null,
          week || null,
          topic || null,
          content || ""
        ]
      );

      res.status(201).json({
        success: true,
        document: result.rows[0]
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Unable to save document."
      });
    }
  }
);

app.get(
  "/api/documents",
  authenticate,
  async (req, res) => {
    const result = await query(
      `SELECT d.*,
              u.full_name AS teacher_name,
              s.name AS subject_name,
              c.name AS class_name
       FROM documents d
       LEFT JOIN users u ON u.id = d.teacher_id
       LEFT JOIN subjects s ON s.id = d.subject_id
       LEFT JOIN classes c ON c.id = d.class_id
       WHERE d.teacher_id = $1
       ORDER BY d.updated_at DESC`,
      [req.user.id]
    );

    res.json({
      success: true,
      documents: result.rows
    });
  }
);

app.post(
  "/api/documents/:id/submit",
  authenticate,
  async (req, res) => {
    const id = Number(req.params.id);

    const result = await query(
      `UPDATE documents
       SET status = 'submitted',
           submitted_at = CURRENT_TIMESTAMP,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $1
       AND teacher_id = $2
       RETURNING *`,
      [id, req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        success: false,
        message: "Document not found."
      });
    }

    res.json({
      success: true,
      message: "Document submitted successfully.",
      document: result.rows[0]
    });
  }
);

/* =========================
   HOD DOCUMENTS
========================= */

app.get(
  "/api/hod/documents",
  authenticate,
  async (req, res) => {
    if (!req.user.role === "admin" && !req.user.is_hod) {
      return res.status(403).json({
        success: false,
        message: "HOD access required."
      });
    }

    const result = await query(
      `SELECT d.*,
              u.full_name AS teacher_name,
              s.name AS subject_name,
              c.name AS class_name
       FROM documents d
       LEFT JOIN users u ON u.id = d.teacher_id
       LEFT JOIN subjects s ON s.id = d.subject_id
       LEFT JOIN classes c ON c.id = d.class_id
       WHERE d.status = 'submitted'
       ORDER BY d.submitted_at ASC`
    );

    res.json({
      success: true,
      documents: result.rows
    });
  }
);

app.post(
  "/api/hod/documents/:id/decision",
  authenticate,
  async (req, res) => {
    try {
      if (!req.user.is_hod && req.user.role !== "admin") {
        return res.status(403).json({
          success: false,
          message: "HOD access required."
        });
      }

      const id = Number(req.params.id);
      const { decision, comment } = req.body;

      if (!["approved", "rejected"].includes(decision)) {
        return res.status(400).json({
          success: false,
          message: "Invalid decision."
        });
      }

      const result = await query(
        `UPDATE documents
         SET status = $1,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = $2
         RETURNING *`,
        [decision, id]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          message: "Document not found."
        });
      }

      await query(
        `INSERT INTO approvals
        (document_id, approver_id, approval_level, decision, comment)
        VALUES ($1,$2,'HOD',$3,$4)`,
        [id, req.user.id, decision, comment || null]
      );

      if (decision === "approved") {
        const d = result.rows[0];

        await query(
          `INSERT INTO approved_archive
          (document_id, document_type, title, teacher_id,
           subject_id, class_id, session, term, week, topic,
           content, approved_by)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
          [
            d.id,
            d.document_type,
            d.title,
            d.teacher_id,
            d.subject_id,
            d.class_id,
            d.session,
            d.term,
            d.week,
            d.topic,
            d.content,
            req.user.id
          ]
        );
      }

      res.json({
        success: true,
        message: `Document ${decision}.`
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Unable to process approval."
      });
    }
  }
);

/* =========================
   ASSESSMENTS
========================= */

app.post(
  "/api/assessments",
  authenticate,
  async (req, res) => {
    try {
      const {
        assessment_type,
        title,
        subject_id,
        class_id,
        session,
        term,
        duration,
        total_marks,
        objective_questions,
        theory_questions,
        marking_scheme
      } = req.body;

      const result = await query(
        `INSERT INTO assessments
        (teacher_id, assessment_type, title, subject_id,
         class_id, session, term, duration, total_marks,
         objective_questions, theory_questions, marking_scheme)
        VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        RETURNING *`,
        [
          req.user.id,
          assessment_type,
          title,
          subject_id || null,
          class_id || null,
          session || null,
          term || null,
          duration || null,
          Number(total_marks) || 0,
          objective_questions || "",
          theory_questions || "",
          marking_scheme || ""
        ]
      );

      res.status(201).json({
        success: true,
        assessment: result.rows[0]
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Unable to save assessment."
      });
    }
  }
);

app.get(
  "/api/assessments",
  authenticate,
  async (req, res) => {
    const result = await query(
      `SELECT a.*,
              u.full_name AS teacher_name,
              s.name AS subject_name,
              c.name AS class_name
       FROM assessments a
       LEFT JOIN users u ON u.id = a.teacher_id
       LEFT JOIN subjects s ON s.id = a.subject_id
       LEFT JOIN classes c ON c.id = a.class_id
       WHERE a.teacher_id = $1
       ORDER BY a.updated_at DESC`,
      [req.user.id]
    );

    res.json({
      success: true,
      assessments: result.rows
    });
  }
);

app.post(
  "/api/assessments/:id/submit",
  authenticate,
  async (req, res) => {
    const id = Number(req.params.id);

    const result = await query(
      `UPDATE assessments
       SET status = 'submitted',
           submitted_at = CURRENT_TIMESTAMP,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $1
       AND teacher_id = $2
       RETURNING *`,
      [id, req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        success: false,
        message: "Assessment not found."
      });
    }

    res.json({
      success: true,
      message: "Assessment submitted successfully.",
      assessment: result.rows[0]
    });
  }
);

/* =========================
   EXAM OFFICER
========================= */

app.get(
  "/api/examination-officer/assessments",
  authenticate,
  async (req, res) => {
    if (!req.user.is_exam_officer && req.user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Examination Officer access required."
      });
    }

    const result = await query(
      `SELECT a.*,
              u.full_name AS teacher_name,
              s.name AS subject_name,
              c.name AS class_name
       FROM assessments a
       LEFT JOIN users u ON u.id = a.teacher_id
       LEFT JOIN subjects s ON s.id = a.subject_id
       LEFT JOIN classes c ON c.id = a.class_id
       WHERE a.status IN ('submitted','hod_approved')
       ORDER BY a.submitted_at ASC`
    );

    res.json({
      success: true,
      assessments: result.rows
    });
  }
);

/* =========================
   ARCHIVE
========================= */

app.get(
  "/api/archive",
  authenticate,
  adminOnly,
  async (req, res) => {
    const {
      search,
      teacher_id,
      subject_id,
      class_id,
      session,
      term,
      document_type
    } = req.query;

    let sql = `
      SELECT aa.*,
             u.full_name AS teacher_name,
             s.name AS subject_name,
             c.name AS class_name
      FROM approved_archive aa
      LEFT JOIN users u ON u.id = aa.teacher_id
      LEFT JOIN subjects s ON s.id = aa.subject_id
      LEFT JOIN classes c ON c.id = aa.class_id
      WHERE 1=1
    `;

    const params = [];

    if (search) {
      params.push(`%${search}%`);
      sql += `
        AND (
          aa.title ILIKE $${params.length}
          OR aa.topic ILIKE $${params.length}
          OR aa.content ILIKE $${params.length}
        )
      `;
    }

    if (teacher_id) {
      params.push(Number(teacher_id));
      sql += ` AND aa.teacher_id = $${params.length}`;
    }

    if (subject_id) {
      params.push(Number(subject_id));
      sql += ` AND aa.subject_id = $${params.length}`;
    }

    if (class_id) {
      params.push(Number(class_id));
      sql += ` AND aa.class_id = $${params.length}`;
    }

    if (session) {
      params.push(session);
      sql += ` AND aa.session = $${params.length}`;
    }

    if (term) {
      params.push(term);
      sql += ` AND aa.term = $${params.length}`;
    }

    if (document_type) {
      params.push(document_type);
      sql += ` AND aa.document_type = $${params.length}`;
    }

    sql += " ORDER BY aa.approved_at DESC";

    const result = await query(sql, params);

    res.json({
      success: true,
      archive: result.rows
    });
  }
);

/* =========================
   ARCHIVE STATISTICS
========================= */

app.get(
  "/api/archive/stats",
  authenticate,
  adminOnly,
  async (req, res) => {
    const result = await query(`
      SELECT
        COUNT(*) AS total,
        COUNT(*) FILTER
          (WHERE document_type = 'Scheme of Work') AS schemes,
        COUNT(*) FILTER
          (WHERE document_type = 'Lesson Plan') AS lesson_plans,
        COUNT(*) FILTER
          (WHERE document_type = 'Lesson Note') AS lesson_notes,
        COUNT(*) FILTER
          (WHERE document_type = 'CA') AS cas,
        COUNT(*) FILTER
          (WHERE document_type = 'Examination') AS examinations
      FROM approved_archive
    `);

    res.json({
      success: true,
      stats: result.rows[0]
    });
  }
);

/* =========================
   SCHOOL SETTINGS
========================= */

app.get(
  "/api/school/settings",
  authenticate,
  async (req, res) => {
    const result = await query(
      "SELECT * FROM school_settings WHERE id = 1"
    );

    res.json({
      success: true,
      settings: result.rows[0]
    });
  }
);

app.put(
  "/api/school/settings",
  authenticate,
  adminOnly,
  async (req, res) => {
    const {
      school_name,
      address,
      phone,
      email,
      logo_url
    } = req.body;

    const result = await query(
      `UPDATE school_settings
       SET school_name = COALESCE($1, school_name),
           address = COALESCE($2, address),
           phone = COALESCE($3, phone),
           email = COALESCE($4, email),
           logo_url = COALESCE($5, logo_url),
           updated_at = CURRENT_TIMESTAMP
       WHERE id = 1
       RETURNING *`,
      [
        school_name ?? null,
        address ?? null,
        phone ?? null,
        email ?? null,
        logo_url ?? null
      ]
    );

    res.json({
      success: true,
      settings: result.rows[0]
    });
  }
);

/* =========================
   AUDIT LOG
========================= */

app.get(
  "/api/audit-logs",
  authenticate,
  adminOnly,
  async (req, res) => {
    const result = await query(
      `SELECT a.*,
              u.username,
              u.full_name
       FROM audit_logs a
       LEFT JOIN users u ON u.id = a.user_id
       ORDER BY a.created_at DESC
       LIMIT 500`
    );

    res.json({
      success: true,
      logs: result.rows
    });
  }
);

/* =========================
   404
========================= */

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "API route not found."
  });
});

/* =========================
   ERROR HANDLER
========================= */

app.use((error, req, res, next) => {
  console.error("SERVER ERROR:", error);

  res.status(500).json({
    success: false,
    message: "Internal server error."
  });
});

/* =========================
   START SERVER
========================= */

async function startServer() {
  try {
    console.log("Starting Caliphate Tarbiya Academy backend...");

    await query("SELECT NOW()");

    console.log("PostgreSQL connection successful.");

    await initializeDatabase();

    await seedAdmin();

    app.listen(PORT, "0.0.0.0", () => {
      console.log("======================================");
      console.log("CALIPHATE TARBIYA ACADEMY BACKEND");
      console.log("Server running on port:", PORT);
      console.log("======================================");
    });

  } catch (error) {
    console.error("STARTUP ERROR:");
    console.error(error);
    process.exit(1);
  }
}

startServer();
