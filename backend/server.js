require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();

app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Health check
app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      service: "Caliphate Tarbiya Academy API",
      database: "connected"
    });
  } catch (error) {
    console.error("Database error:", error.message);

    res.status(500).json({
      ok: false,
      service: "Caliphate Tarbiya Academy API",
      database: "error"
    });
  }
});

// Basic root route
app.get("/", (req, res) => {
  res.json({
    ok: true,
    message: "Caliphate Tarbiya Academy API is running"
  });
});

// 404
app.use((req, res) => {
  res.status(404).json({
    ok: false,
    message: "Route not found"
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error("Server error:", err);

  res.status(500).json({
    ok: false,
    message: "Internal server error"
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Caliphate Tarbiya Academy API running on port ${PORT}`);
});
