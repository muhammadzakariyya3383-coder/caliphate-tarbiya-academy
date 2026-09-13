require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

/* =========================================================
   CONFIGURATION
========================================================= */

const PORT = process.env.PORT || 3000;

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "CHANGE_THIS_SECRET_BEFORE_PRODUCTION";

/* =========================================================
   DATABASE
========================================================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,

  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false
});

pool.on("error", (err) => {
  console.error("Unexpected PostgreSQL error:", err);
});

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(
  cors({
    origin: true,
    credentials: true
  })
);

app.use(express.json({ limit: "10mb" }));

/* =========================================================
   HELPERS
========================================================= */

function sendError(res, status, message) {
  return res.status(status).json({
    ok: false,
    message
  });
}

async function audit(
  userId,
  action,
  entityType = null,
  entityId = null,
  details = null
) {
  try {
    await pool.query(
      `
      INSERT INTO audit_logs
      (
        user_id,
        action,
        entity_type,
        entity_id,
        details
      )
      VALUES ($1,$2,$3,$4,$5)
      `,
      [
        userId || null,
        action,
        entityType,
        entityId,
        details
      ]
    );
  } catch (error) {
    console.error("Audit error:", error.message);
  }
}

/* =========================================================
   AUTHENTICATION MIDDLEWARE
========================================================= */

async function authenticate(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return sendError(res, 401, "Authentication required");
    }

    const token = header.substring(7);

    const decoded = jwt.verify(token, JWT_SECRET);

    const result = await pool.query(
      `
      SELECT
        id,
        username,
        full_name,
        role,
        is_active
      FROM users
      WHERE id = $1
      `,
      [decoded.userId]
    );

    if (result.rows.length === 0) {
      return sendError(res, 401, "User account not found");
    }

    const user = result.rows[0];

    if (!user.is_active) {
      return sendError(res, 403, "This account is inactive");
    }

    req.user = user;

    next();
  } catch (error) {
    return sendError(res, 401, "Invalid or expired session");
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return sendError(
      res,
      403,
      "Administrator permission required"
    );
  }

  next();
}

async function teacherOnly(req, res, next) {
  if (
    req.user.role !== "teacher" &&
    req.user.role !== "admin"
  ) {
    return sendError(res, 403, "Teacher permission required");
  }

  next();
}

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      service: "Caliphate Tarbiya Academy API",
      database: "connected"
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      ok: false,
      service: "Caliphate Tarbiya Academy API",
      database: "error"
    });
  }
});

/* =========================================================
   ROOT
========================================================= */

app.get("/", (req, res) => {
  res.json({
    ok: true,
    message:
      "Caliphate Tarbiya Academy API is running"
  });
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/auth/login", async (req, res) => {
  try {
    const {
      username,
      password
    } = req.body;

    if (!username || !password) {
      return sendError(
        res,
        400,
        "Username and password are required"
      );
    }

    const result = await pool.query(
      `
      SELECT *
      FROM users
      WHERE LOWER(username) = LOWER($1)
      LIMIT 1
      `,
      [username.trim()]
    );

    if (result.rows.length === 0) {
      return sendError(
        res,
        401,
        "Invalid username or password"
      );
    }

    const user = result.rows[0];

    if (!user.is_active) {
      return sendError(
        res,
        403,
        "This account is inactive. Contact the Administrator."
      );
    }

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return sendError(
        res,
        401,
        "Invalid username or password"
      );
    }

    const token = jwt.sign(
      {
        userId: user.id,
        role: user.role
      },
      JWT_SECRET,
      {
        expiresIn: "12h"
      }
    );

    await audit(
      user.id,
      "LOGIN",
      "user",
      user.id,
      {
        username: user.username
      }
    );

    res.json({
      ok: true,
      token,

      user: {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        role: user.role,
        is_active: user.is_active
      }
    });
  } catch (error) {
    console.error("Login error:", error);

    sendError(
      res,
      500,
      "Unable to complete login"
    );
  }
});

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  "/api/auth/me",
  authenticate,
  async (req, res) => {
    res.json({
      ok: true,
      user: req.user
    });
  }
);

/* =========================================================
   CHANGE PASSWORD
========================================================= */

app.post(
  "/api/auth/change-password",
  authenticate,
  async (req, res) => {
    try {
      const {
        currentPassword,
        newPassword
      } = req.body;

      if (!currentPassword || !newPassword) {
        return sendError(
          res,
          400,
          "Current and new passwords are required"
        );
      }

      if (newPassword.length < 8) {
        return sendError(
          res,
          400,
          "New password must contain at least 8 characters"
        );
      }

      const result = await pool.query(
        `
        SELECT password_hash
        FROM users
        WHERE id = $1
        `,
        [req.user.id]
      );

      if (result.rows.length === 0) {
        return sendError(
          res,
          404,
          "User not found"
        );
      }

      const valid = await bcrypt.compare(
        currentPassword,
        result.rows[0].password_hash
      );

      if (!valid) {
        return sendError(
          res,
          400,
          "Current password is incorrect"
        );
      }

      const hash = await bcrypt.hash(
        newPassword,
        12
      );

      await pool.query(
        `
        UPDATE users
        SET password_hash = $1,
            updated_at = NOW()
        WHERE id = $2
        `,
        [hash, req.user.id]
      );

      await audit(
        req.user.id,
        "CHANGE_PASSWORD",
        "user",
        req.user.id
      );

      res.json({
        ok: true,
        message: "Password changed successfully"
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to change password"
      );
    }
  }
);

/* =========================================================
   ADMIN - CREATE TEACHER
========================================================= */

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
        is_hod,
        is_exam_officer
      } = req.body;

      if (!username || !password || !full_name) {
        return sendError(
          res,
          400,
          "Username, password and full name are required"
        );
      }

      if (password.length < 8) {
        return sendError(
          res,
          400,
          "Teacher password must contain at least 8 characters"
        );
      }

      const existing = await pool.query(
        `
        SELECT id
        FROM users
        WHERE LOWER(username) = LOWER($1)
        `,
        [username.trim()]
      );

      if (existing.rows.length > 0) {
        return sendError(
          res,
          409,
          "Username already exists"
        );
      }

      const passwordHash = await bcrypt.hash(
        password,
        12
      );

      const result = await pool.query(
        `
        INSERT INTO users
        (
          username,
          password_hash,
          full_name,
          email,
          phone,
          role,
          is_active,
          is_hod,
          is_exam_officer
        )
        VALUES
        (
          $1,$2,$3,$4,$5,
          'teacher',
          TRUE,
          $6,$7
        )
        RETURNING
          id,
          username,
          full_name,
          email,
          phone,
          role,
          is_active,
          is_hod,
          is_exam_officer
        `,
        [
          username.trim(),
          passwordHash,
          full_name.trim(),
          email || null,
          phone || null,
          Boolean(is_hod),
          Boolean(is_exam_officer)
        ]
      );

      const teacher = result.rows[0];

      await audit(
        req.user.id,
        "CREATE_TEACHER",
        "user",
        teacher.id,
        {
          username: teacher.username
        }
      );

      res.status(201).json({
        ok: true,
        teacher
      });
    } catch (error) {
      console.error(
        "Create teacher error:",
        error
      );

      sendError(
        res,
        500,
        "Unable to create teacher"
      );
    }
  }
);

/* =========================================================
   ADMIN - LIST USERS
========================================================= */

app.get(
  "/api/users",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          id,
          username,
          full_name,
          email,
          phone,
          role,
          is_active,
          is_hod,
          is_exam_officer,
          created_at,
          updated_at
        FROM users
        ORDER BY
          role,
          full_name
        `
      );

      res.json({
        ok: true,
        users: result.rows
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to load users"
      );
    }
  }
);

/* =========================================================
   ADMIN - UPDATE TEACHER
========================================================= */

app.put(
  "/api/users/teachers/:id",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const id = req.params.id;

      const {
        full_name,
        email,
        phone,
        is_active,
        is_hod,
        is_exam_officer
      } = req.body;

      const result = await pool.query(
        `
        UPDATE users
        SET
          full_name = COALESCE($1, full_name),
          email = COALESCE($2, email),
          phone = COALESCE($3, phone),
          is_active = COALESCE($4, is_active),
          is_hod = COALESCE($5, is_hod),
          is_exam_officer = COALESCE($6, is_exam_officer),
          updated_at = NOW()
        WHERE
          id = $7
          AND role = 'teacher'
        RETURNING
          id,
          username,
          full_name,
          email,
          phone,
          role,
          is_active,
          is_hod,
          is_exam_officer
        `,
        [
          full_name ?? null,
          email ?? null,
          phone ?? null,
          typeof is_active === "boolean"
            ? is_active
            : null,
          typeof is_hod === "boolean"
            ? is_hod
            : null,
          typeof is_exam_officer === "boolean"
            ? is_exam_officer
            : null,
          id
        ]
      );

      if (result.rows.length === 0) {
        return sendError(
          res,
          404,
          "Teacher not found"
        );
      }

      await audit(
        req.user.id,
        "UPDATE_TEACHER",
        "user",
        id
      );

      res.json({
        ok: true,
        teacher: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to update teacher"
      );
    }
  }
);

/* =========================================================
   ADMIN - RESET TEACHER PASSWORD
========================================================= */

app.post(
  "/api/users/teachers/:id/reset-password",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const id = req.params.id;

      const {
        newPassword
      } = req.body;

      if (!newPassword) {
        return sendError(
          res,
          400,
          "New password is required"
        );
      }

      if (newPassword.length < 8) {
        return sendError(
          res,
          400,
          "Password must contain at least 8 characters"
        );
      }

      const hash = await bcrypt.hash(
        newPassword,
        12
      );

      const result = await pool.query(
        `
        UPDATE users
        SET
          password_hash = $1,
          updated_at = NOW()
        WHERE
          id = $2
          AND role = 'teacher'
        RETURNING id, username
        `,
        [hash, id]
      );

      if (result.rows.length === 0) {
        return sendError(
          res,
          404,
          "Teacher not found"
        );
      }

      await audit(
        req.user.id,
        "RESET_TEACHER_PASSWORD",
        "user",
        id
      );

      res.json({
        ok: true,
        message:
          "Teacher password reset successfully"
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to reset password"
      );
    }
  }
);

/* =========================================================
   CLASSES
========================================================= */

app.get(
  "/api/classes",
  authenticate,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT *
        FROM classes
        ORDER BY name
        `
      );

      res.json({
        ok: true,
        classes: result.rows
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to load classes"
      );
    }
  }
);

app.post(
  "/api/classes",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const {
        name,
        level
      } = req.body;

      if (!name) {
        return sendError(
          res,
          400,
          "Class name is required"
        );
      }

      const result = await pool.query(
        `
        INSERT INTO classes
        (
          name,
          level
        )
        VALUES
        ($1,$2)
        RETURNING *
        `,
        [
          name.trim(),
          level || null
        ]
      );

      await audit(
        req.user.id,
        "CREATE_CLASS",
        "class",
        result.rows[0].id
      );

      res.status(201).json({
        ok: true,
        class: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to create class"
      );
    }
  }
);

/* =========================================================
   SUBJECTS
========================================================= */

app.get(
  "/api/subjects",
  authenticate,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT *
        FROM subjects
        ORDER BY name
        `
      );

      res.json({
        ok: true,
        subjects: result.rows
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to load subjects"
      );
    }
  }
);

app.post(
  "/api/subjects",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const {
        name,
        code
      } = req.body;

      if (!name) {
        return sendError(
          res,
          400,
          "Subject name is required"
        );
      }

      const result = await pool.query(
        `
        INSERT INTO subjects
        (
          name,
          code
        )
        VALUES
        ($1,$2)
        RETURNING *
        `,
        [
          name.trim(),
          code || null
        ]
      );

      await audit(
        req.user.id,
        "CREATE_SUBJECT",
        "subject",
        result.rows[0].id
      );

      res.status(201).json({
        ok: true,
        subject: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to create subject"
      );
    }
  }
);

/* =========================================================
   TEACHER ASSIGNMENTS
========================================================= */

app.post(
  "/api/users/teachers/:id/assignments",
  authenticate,
  adminOnly,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const teacherId = req.params.id;

      const {
        subjectIds = [],
        classIds = [],
        hodSubjectIds = [],
        isExamOfficer
      } = req.body;

      await client.query("BEGIN");

      await client.query(
        `
        DELETE FROM teacher_subjects
        WHERE teacher_id = $1
        `,
        [teacherId]
      );

      for (const subjectId of subjectIds) {
        await client.query(
          `
          INSERT INTO teacher_subjects
          (
            teacher_id,
            subject_id
          )
          VALUES
          ($1,$2)
          ON CONFLICT DO NOTHING
          `,
          [
            teacherId,
            subjectId
          ]
        );
      }

      await client.query(
        `
        DELETE FROM teacher_classes
        WHERE teacher_id = $1
        `,
        [teacherId]
      );

      for (const classId of classIds) {
        await client.query(
          `
          INSERT INTO teacher_classes
          (
            teacher_id,
            class_id
          )
          VALUES
          ($1,$2)
          ON CONFLICT DO NOTHING
          `,
          [
            teacherId,
            classId
          ]
        );
      }

      await client.query(
        `
        DELETE FROM hod_subjects
        WHERE teacher_id = $1
        `,
        [teacherId]
      );

      for (const subjectId of hodSubjectIds) {
        await client.query(
          `
          INSERT INTO hod_subjects
          (
            teacher_id,
            subject_id
          )
          VALUES
          ($1,$2)
          ON CONFLICT DO NOTHING
          `,
          [
            teacherId,
            subjectId
          ]
        );
      }

      if (typeof isExamOfficer === "boolean") {
        await client.query(
          `
          UPDATE users
          SET
            is_exam_officer = $1,
            updated_at = NOW()
          WHERE id = $2
          `,
          [
            isExamOfficer,
            teacherId
          ]
        );
      }

      await client.query("COMMIT");

      await audit(
        req.user.id,
        "UPDATE_TEACHER_ASSIGNMENTS",
        "user",
        teacherId
      );

      res.json({
        ok: true,
        message:
          "Teacher assignments updated successfully"
      });
    } catch (error) {
      await client.query("ROLLBACK");

      console.error(error);

      sendError(
        res,
        500,
        "Unable to update teacher assignments"
      );
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   TEACHER ASSIGNMENTS - CURRENT USER
========================================================= */

app.get(
  "/api/my/assignments",
  authenticate,
  teacherOnly,
  async (req, res) => {
    try {
      const subjects = await pool.query(
        `
        SELECT
          s.*
        FROM subjects s
        INNER JOIN teacher_subjects ts
          ON ts.subject_id = s.id
        WHERE ts.teacher_id = $1
        ORDER BY s.name
        `,
        [req.user.id]
      );

      const classes = await pool.query(
        `
        SELECT
          c.*
        FROM classes c
        INNER JOIN teacher_classes tc
          ON tc.class_id = c.id
        WHERE tc.teacher_id = $1
        ORDER BY c.name
        `,
        [req.user.id]
      );

      const hodSubjects = await pool.query(
        `
        SELECT
          s.*
        FROM subjects s
        INNER JOIN hod_subjects hs
          ON hs.subject_id = s.id
        WHERE hs.teacher_id = $1
        ORDER BY s.name
        `,
        [req.user.id]
      );

      res.json({
        ok: true,
        subjects: subjects.rows,
        classes: classes.rows,
        hodSubjects: hodSubjects.rows
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to load teacher assignments"
      );
    }
  }
);

/* =========================================================
   DOCUMENTS - CREATE
========================================================= */

app.post(
  "/api/documents",
  authenticate,
  teacherOnly,
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

      const allowedTypes = [
        "Scheme of Work",
        "Lesson Plan",
        "Lesson Note"
      ];

      if (!allowedTypes.includes(document_type)) {
        return sendError(
          res,
          400,
          "Invalid document type"
        );
      }

      if (!title || !content) {
        return sendError(
          res,
          400,
          "Title and content are required"
        );
      }

      const result = await pool.query(
        `
        INSERT INTO documents
        (
          teacher_id,
          document_type,
          title,
          subject_id,
          class_id,
          session,
          term,
          week,
          topic,
          content,
          status
        )
        VALUES
        (
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
          'Draft'
        )
        RETURNING *
        `,
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
          content
        ]
      );

      await audit(
        req.user.id,
        "CREATE_DOCUMENT",
        "document",
        result.rows[0].id
      );

      res.status(201).json({
        ok: true,
        document: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to create document"
      );
    }
  }
);

/* =========================================================
   MY DOCUMENTS
========================================================= */

app.get(
  "/api/documents/my",
  authenticate,
  teacherOnly,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          d.*,
          s.name AS subject_name,
          c.name AS class_name
        FROM documents d
        LEFT JOIN subjects s
          ON s.id = d.subject_id
        LEFT JOIN classes c
          ON c.id = d.class_id
        WHERE d.teacher_id = $1
        ORDER BY d.updated_at DESC
        `,
        [req.user.id]
      );

      res.json({
        ok: true,
        documents: result.rows
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to load documents"
      );
    }
  }
);

/* =========================================================
   SUBMIT DOCUMENT TO HOD
========================================================= */

app.post(
  "/api/documents/:id/submit",
  authenticate,
  teacherOnly,
  async (req, res) => {
    try {
      const id = req.params.id;

      const result = await pool.query(
        `
        UPDATE documents
        SET
          status = 'Submitted',
          submitted_at = NOW(),
          updated_at = NOW()
        WHERE
          id = $1
          AND teacher_id = $2
          AND status IN ('Draft','Rejected')
        RETURNING *
        `,
        [
          id,
          req.user.id
        ]
      );

      if (result.rows.length === 0) {
        return sendError(
          res,
          404,
          "Document cannot be submitted"
        );
      }

      await audit(
        req.user.id,
        "SUBMIT_DOCUMENT",
        "document",
        id
      );

      res.json({
        ok: true,
        document: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to submit document"
      );
    }
  }
);

/* =========================================================
   HOD - DOCUMENTS
========================================================= */

app.get(
  "/api/hod/documents",
  authenticate,
  teacherOnly,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          d.*,
          u.full_name AS teacher_name,
          s.name AS subject_name,
          c.name AS class_name
        FROM documents d
        INNER JOIN hod_subjects hs
          ON hs.subject_id = d.subject_id
         AND hs.teacher_id = $1
        INNER JOIN users u
          ON u.id = d.teacher_id
        LEFT JOIN subjects s
          ON s.id = d.subject_id
        LEFT JOIN classes c
          ON c.id = d.class_id
        WHERE d.status = 'Submitted'
        ORDER BY d.submitted_at DESC
        `,
        [req.user.id]
      );

      res.json({
        ok: true,
        documents: result.rows
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to load HOD documents"
      );
    }
  }
);

/* =========================================================
   HOD - DOCUMENT DECISION
========================================================= */

app.post(
  "/api/documents/:id/hod-decision",
  authenticate,
  teacherOnly,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const id = req.params.id;

      const {
        decision,
        comment
      } = req.body;

      if (
        !["Approved", "Rejected"].includes(
          decision
        )
      ) {
        return sendError(
          res,
          400,
          "Invalid HOD decision"
        );
      }

      const documentResult =
        await client.query(
          `
          SELECT d.*
          FROM documents d
          INNER JOIN hod_subjects hs
            ON hs.subject_id = d.subject_id
           AND hs.teacher_id = $1
          WHERE d.id = $2
          `,
          [
            req.user.id,
            id
          ]
        );

      if (
        documentResult.rows.length === 0
      ) {
        return sendError(
          res,
          404,
          "Document not found or not assigned to you"
        );
      }

      const document =
        documentResult.rows[0];

      await client.query("BEGIN");

      await client.query(
        `
        INSERT INTO approvals
        (
          document_id,
          approver_id,
          approval_level,
          decision,
          comment
        )
        VALUES
        (
          $1,$2,'HOD',$3,$4
        )
        `,
        [
          id,
          req.user.id,
          decision,
          comment || null
        ]
      );

      await client.query(
        `
        UPDATE documents
        SET
          status = $1,
          updated_at = NOW()
        WHERE id = $2
        `,
        [
          decision,
          id
        ]
      );

      if (decision === "Approved") {
        await client.query(
          `
          INSERT INTO approved_archive
          (
            document_id,
            document_type,
            title,
            teacher_id,
            subject_id,
            class_id,
            session,
            term,
            week,
            topic,
            content,
            approved_by,
            approved_at
          )
          VALUES
          (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW()
          )
          `,
          [
            document.id,
            document.document_type,
            document.title,
            document.teacher_id,
            document.subject_id,
            document.class_id,
            document.session,
            document.term,
            document.week,
            document.topic,
            document.content,
            req.user.id
          ]
        );
      }

      await client.query("COMMIT");

      await audit(
        req.user.id,
        `HOD_${decision.toUpperCase()}`,
        "document",
        id
      );

      res.json({
        ok: true,
        message:
          `Document ${decision.toLowerCase()}`
      });
    } catch (error) {
      await client.query("ROLLBACK");

      console.error(error);

      sendError(
        res,
        500,
        "Unable to process HOD decision"
      );
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   ASSESSMENTS
========================================================= */

app.post(
  "/api/assessments",
  authenticate,
  teacherOnly,
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

      if (
        ![
          "CA",
          "Examination"
        ].includes(assessment_type)
      ) {
        return sendError(
          res,
          400,
          "Invalid assessment type"
        );
      }

      if (!title) {
        return sendError(
          res,
          400,
          "Assessment title is required"
        );
      }

      const result = await pool.query(
        `
        INSERT INTO assessments
        (
          teacher_id,
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
          marking_scheme,
          status
        )
        VALUES
        (
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
          'Draft'
        )
        RETURNING *
        `,
        [
          req.user.id,
          assessment_type,
          title,
          subject_id || null,
          class_id || null,
          session || null,
          term || null,
          duration || null,
          total_marks || null,
          JSON.stringify(
            objective_questions || []
          ),
          JSON.stringify(
            theory_questions || []
          ),
          JSON.stringify(
            marking_scheme || []
          )
        ]
      );

      await audit(
        req.user.id,
        "CREATE_ASSESSMENT",
        "assessment",
        result.rows[0].id
      );

      res.status(201).json({
        ok: true,
        assessment: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to create assessment"
      );
    }
  }
);

/* =========================================================
   MY ASSESSMENTS
========================================================= */

app.get(
  "/api/assessments/my",
  authenticate,
  teacherOnly,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          a.*,
          s.name AS subject_name,
          c.name AS class_name
        FROM assessments a
        LEFT JOIN subjects s
          ON s.id = a.subject_id
        LEFT JOIN classes c
          ON c.id = a.class_id
        WHERE a.teacher_id = $1
        ORDER BY a.updated_at DESC
        `,
        [req.user.id]
      );

      res.json({
        ok: true,
        assessments: result.rows
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to load assessments"
      );
    }
  }
);

/* =========================================================
   SUBMIT ASSESSMENT
========================================================= */

app.post(
  "/api/assessments/:id/submit",
  authenticate,
  teacherOnly,
  async (req, res) => {
    try {
      const id = req.params.id;

      const result = await pool.query(
        `
        UPDATE assessments
        SET
          status = 'Submitted',
          submitted_at = NOW(),
          updated_at = NOW()
        WHERE
          id = $1
          AND teacher_id = $2
          AND status IN ('Draft','Rejected','Exam Rejected')
        RETURNING *
        `,
        [
          id,
          req.user.id
        ]
      );

      if (result.rows.length === 0) {
        return sendError(
          res,
          404,
          "Assessment cannot be submitted"
        );
      }

      await audit(
        req.user.id,
        "SUBMIT_ASSESSMENT",
        "assessment",
        id
      );

      res.json({
        ok: true,
        assessment: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to submit assessment"
      );
    }
  }
);

/* =========================================================
   HOD - ASSESSMENTS
========================================================= */

app.get(
  "/api/hod/assessments",
  authenticate,
  teacherOnly,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          a.*,
          u.full_name AS teacher_name,
          s.name AS subject_name,
          c.name AS class_name
        FROM assessments a
        INNER JOIN hod_subjects hs
          ON hs.subject_id = a.subject_id
         AND hs.teacher_id = $1
        INNER JOIN users u
          ON u.id = a.teacher_id
        LEFT JOIN subjects s
          ON s.id = a.subject_id
        LEFT JOIN classes c
          ON c.id = a.class_id
        WHERE a.status = 'Submitted'
        ORDER BY a.submitted_at DESC
        `,
        [req.user.id]
      );

      res.json({
        ok: true,
        assessments: result.rows
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to load HOD assessments"
      );
    }
  }
);

/* =========================================================
   HOD - ASSESSMENT DECISION
========================================================= */

app.post(
  "/api/assessments/:id/hod-decision",
  authenticate,
  teacherOnly,
  async (req, res) => {
    try {
      const id = req.params.id;

      const {
        decision,
        comment
      } = req.body;

      if (
        ![
          "Approved",
          "Rejected"
        ].includes(decision)
      ) {
        return sendError(
          res,
          400,
          "Invalid HOD decision"
        );
      }

      const check = await pool.query(
        `
        SELECT a.*
        FROM assessments a
        INNER JOIN hod_subjects hs
          ON hs.subject_id = a.subject_id
         AND hs.teacher_id = $1
        WHERE a.id = $2
        `,
        [
          req.user.id,
          id
        ]
      );

      if (check.rows.length === 0) {
        return sendError(
          res,
          404,
          "Assessment not found or not assigned to you"
        );
      }

      const assessment = check.rows[0];

      const newStatus =
        decision === "Approved"
          ? "HOD Approved"
          : "Rejected";

      await pool.query(
        `
        INSERT INTO approvals
        (
          assessment_id,
          approver_id,
          approval_level,
          decision,
          comment
        )
        VALUES
        (
          $1,$2,'HOD',$3,$4
        )
        `,
        [
          id,
          req.user.id,
          decision,
          comment || null
        ]
      );

      await pool.query(
        `
        UPDATE assessments
        SET
          status = $1,
          updated_at = NOW()
        WHERE id = $2
        `,
        [
          newStatus,
          id
        ]
      );

      await audit(
        req.user.id,
        `HOD_ASSESSMENT_${decision.toUpperCase()}`,
        "assessment",
        id
      );

      res.json({
        ok: true,
        message:
          `Assessment ${decision.toLowerCase()}`
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to process assessment"
      );
    }
  }
);

/* =========================================================
   EXAMINATION OFFICER
========================================================= */

app.get(
  "/api/exam-officer/assessments",
  authenticate,
  teacherOnly,
  async (req, res) => {
    try {
      const permission = await pool.query(
        `
        SELECT is_exam_officer
        FROM users
        WHERE id = $1
        `,
        [req.user.id]
      );

      if (
        !permission.rows[0] ||
        !permission.rows[0].is_exam_officer
      ) {
        return sendError(
          res,
          403,
          "Examination Officer permission required"
        );
      }

      const result = await pool.query(
        `
        SELECT
          a.*,
          u.full_name AS teacher_name,
          s.name AS subject_name,
          c.name AS class_name
        FROM assessments a
        INNER JOIN users u
          ON u.id = a.teacher_id
        LEFT JOIN subjects s
          ON s.id = a.subject_id
        LEFT JOIN classes c
          ON c.id = a.class_id
        WHERE a.status = 'HOD Approved'
        ORDER BY a.updated_at DESC
        `
      );

      res.json({
        ok: true,
        assessments: result.rows
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to load examination assessments"
      );
    }
  }
);

/* =========================================================
   EXAMINATION OFFICER DECISION
========================================================= */

app.post(
  "/api/assessments/:id/exam-decision",
  authenticate,
  teacherOnly,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const id = req.params.id;

      const {
        decision,
        comment
      } = req.body;

      if (
        ![
          "Approved",
          "Rejected"
        ].includes(decision)
      ) {
        return sendError(
          res,
          400,
          "Invalid examination decision"
        );
      }

      const permission = await client.query(
        `
        SELECT is_exam_officer
        FROM users
        WHERE id = $1
        `,
        [req.user.id]
      );

      if (
        !permission.rows[0] ||
        !permission.rows[0].is_exam_officer
      ) {
        return sendError(
          res,
          403,
          "Examination Officer permission required"
        );
      }

      const result = await client.query(
        `
        SELECT *
        FROM assessments
        WHERE
          id = $1
          AND status = 'HOD Approved'
        `,
        [id]
      );

      if (result.rows.length === 0) {
        return sendError(
          res,
          404,
          "Assessment not available for examination approval"
        );
      }

      const assessment = result.rows[0];

      await client.query("BEGIN");

      await client.query(
        `
        INSERT INTO approvals
        (
          assessment_id,
          approver_id,
          approval_level,
          decision,
          comment
        )
        VALUES
        (
          $1,$2,'EXAMINATION_OFFICER',$3,$4
        )
        `,
        [
          id,
          req.user.id,
          decision,
          comment || null
        ]
      );

      const finalStatus =
        decision === "Approved"
          ? "Final Approved"
          : "Exam Rejected";

      await client.query(
        `
        UPDATE assessments
        SET
          status = $1,
          updated_at = NOW()
        WHERE id = $2
        `,
        [
          finalStatus,
          id
        ]
      );

      if (
        decision === "Approved"
      ) {
        await client.query(
          `
          INSERT INTO approved_archive
          (
            assessment_id,
            document_type,
            title,
            teacher_id,
            subject_id,
            class_id,
            session,
            term,
            content,
            approved_by,
            approved_at
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9,
            $10,
            NOW()
          )
          `,
          [
            assessment.id,
            assessment.assessment_type,
            assessment.title,
            assessment.teacher_id,
            assessment.subject_id,
            assessment.class_id,
            assessment.session,
            assessment.term,
            JSON.stringify({
              duration:
                assessment.duration,
              total_marks:
                assessment.total_marks,
              objective_questions:
                assessment.objective_questions,
              theory_questions:
                assessment.theory_questions,
              marking_scheme:
                assessment.marking_scheme
            }),
            req.user.id
          ]
        );
      }

      await client.query("COMMIT");

      await audit(
        req.user.id,
        `EXAM_OFFICER_${decision.toUpperCase()}`,
        "assessment",
        id
      );

      res.json({
        ok: true,
        message:
          `Assessment ${decision.toLowerCase()}`
      });
    } catch (error) {
      await client.query("ROLLBACK");

      console.error(error);

      sendError(
        res,
        500,
        "Unable to process examination decision"
      );
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   APPROVED ACADEMIC ARCHIVE
========================================================= */

app.get(
  "/api/archive",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const {
        search,
        teacher_id,
        subject_id,
        class_id,
        session,
        term,
        document_type,
        from_date,
        to_date
      } = req.query;

      const conditions = [];
      const values = [];

      function addCondition(
        sql,
        value
      ) {
        values.push(value);
        conditions.push(
          sql.replace(
            "?",
            `$${values.length}`
          )
        );
      }

      if (search) {
        values.push(`%${search}%`);

        conditions.push(
          `(a.title ILIKE $${values.length}
            OR a.content::text ILIKE $${values.length}
            OR u.full_name ILIKE $${values.length})`
        );
      }

      if (teacher_id) {
        addCondition(
          "a.teacher_id = ?",
          teacher_id
        );
      }

      if (subject_id) {
        addCondition(
          "a.subject_id = ?",
          subject_id
        );
      }

      if (class_id) {
        addCondition(
          "a.class_id = ?",
          class_id
        );
      }

      if (session) {
        addCondition(
          "a.session = ?",
          session
        );
      }

      if (term) {
        addCondition(
          "a.term = ?",
          term
        );
      }

      if (document_type) {
        addCondition(
          "a.document_type = ?",
          document_type
        );
      }

      if (from_date) {
        addCondition(
          "a.approved_at >= ?",
          from_date
        );
      }

      if (to_date) {
        addCondition(
          "a.approved_at < (?::date + INTERVAL '1 day')",
          to_date
        );
      }

      const where =
        conditions.length
          ? `WHERE ${conditions.join(" AND ")}`
          : "";

      const result = await pool.query(
        `
        SELECT
          a.*,
          u.full_name AS teacher_name,
          s.name AS subject_name,
          c.name AS class_name
        FROM approved_archive a
        LEFT JOIN users u
          ON u.id = a.teacher_id
        LEFT JOIN subjects s
          ON s.id = a.subject_id
        LEFT JOIN classes c
          ON c.id = a.class_id
        ${where}
        ORDER BY a.approved_at DESC
        `,
        values
      );

      res.json({
        ok: true,
        archive: result.rows
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to load academic archive"
      );
    }
  }
);

/* =========================================================
   ARCHIVE STATISTICS
========================================================= */

app.get(
  "/api/archive/statistics",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          COUNT(*)::int AS total,
          COUNT(*) FILTER
            (
              WHERE document_type = 'Scheme of Work'
            )::int AS schemes,
          COUNT(*) FILTER
            (
              WHERE document_type = 'Lesson Plan'
            )::int AS lesson_plans,
          COUNT(*) FILTER
            (
              WHERE document_type = 'Lesson Note'
            )::int AS lesson_notes,
          COUNT(*) FILTER
            (
              WHERE document_type = 'CA'
            )::int AS ca,
          COUNT(*) FILTER
            (
              WHERE document_type = 'Examination'
            )::int AS examinations
        FROM approved_archive
        `
      );

      res.json({
        ok: true,
        statistics: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to load archive statistics"
      );
    }
  }
);

/* =========================================================
   SCHOOL SETTINGS
========================================================= */

app.get(
  "/api/settings",
  authenticate,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT *
        FROM school_settings
        ORDER BY id
        LIMIT 1
        `
      );

      res.json({
        ok: true,
        settings:
          result.rows[0] || null
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to load school settings"
      );
    }
  }
);

app.put(
  "/api/settings",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const {
        school_name,
        motto,
        address,
        phone,
        email,
        current_session,
        current_term,
        logo_url
      } = req.body;

      const existing = await pool.query(
        `
        SELECT id
        FROM school_settings
        ORDER BY id
        LIMIT 1
        `
      );

      let result;

      if (existing.rows.length === 0) {
        result = await pool.query(
          `
          INSERT INTO school_settings
          (
            school_name,
            motto,
            address,
            phone,
            email,
            current_session,
            current_term,
            logo_url
          )
          VALUES
          ($1,$2,$3,$4,$5,$6,$7,$8)
          RETURNING *
          `,
          [
            school_name || null,
            motto || null,
            address || null,
            phone || null,
            email || null,
            current_session || null,
            current_term || null,
            logo_url || null
          ]
        );
      } else {
        result = await pool.query(
          `
          UPDATE school_settings
          SET
            school_name = $1,
            motto = $2,
            address = $3,
            phone = $4,
            email = $5,
            current_session = $6,
            current_term = $7,
            logo_url = $8,
            updated_at = NOW()
          WHERE id = $9
          RETURNING *
          `,
          [
            school_name || null,
            motto || null,
            address || null,
            phone || null,
            email || null,
            current_session || null,
            current_term || null,
            logo_url || null,
            existing.rows[0].id
          ]
        );
      }

      await audit(
        req.user.id,
        "UPDATE_SCHOOL_SETTINGS",
        "school_settings",
        result.rows[0].id
      );

      res.json({
        ok: true,
        settings: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to update school settings"
      );
    }
  }
);

/* =========================================================
   AUDIT LOG
========================================================= */

app.get(
  "/api/audit-logs",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          a.*,
          u.full_name AS user_name,
          u.username
        FROM audit_logs a
        LEFT JOIN users u
          ON u.id = a.user_id
        ORDER BY a.created_at DESC
        LIMIT 500
        `
      );

      res.json({
        ok: true,
        logs: result.rows
      });
    } catch (error) {
      console.error(error);

      sendError(
        res,
        500,
        "Unable to load audit logs"
      );
    }
  }
);

/* =========================================================
   404
========================================================= */

app.use(
  (req, res) => {
    res.status(404).json({
      ok: false,
      message: "Route not found"
    });
  }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (err, req, res, next) => {
    console.error(
      "Unhandled server error:",
      err
    );

    res.status(500).json({
      ok: false,
      message:
        "Internal server error"
    });
  }
);

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {
  try {
    await pool.query("SELECT 1");

    console.log(
      "PostgreSQL connection successful"
    );

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `Caliphate Tarbiya Academy API running on port ${PORT}`
        );
      }
    );
  } catch (error) {
    console.error(
      "Unable to connect to PostgreSQL:",
      error
    );

    process.exit(1);
  }
}

startServer();
