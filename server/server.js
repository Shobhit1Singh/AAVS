import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import path from "path";
import { fileURLToPath } from "url";

import pool from "./db.js";

const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(cors());
app.use(express.json());

/* ================= REGISTER ================= */

app.post("/register", async (req, res) => {
  const { full_name, email, phone, password } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).json({ message: "Missing fields" });
    }

    const hashed = await bcrypt.hash(password, 10);

    await pool.query(
      `INSERT INTO users (full_name, email, phone, password_hash)
       VALUES ($1, $2, $3, $4)`,
      [full_name, email, phone, hashed]
    );

    res.json({ message: "User saved" });

  } catch (err) {
    console.error("REGISTER ERROR:", err.message);
    res.status(500).json({ message: err.message });
  }
});

/* ================= LOGIN ================= */

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  console.log("LOGIN HIT:", email);

  try {
    if (!email || !password) {
      return res.status(400).json({ message: "Missing email or password" });
    }

    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: "User not found" });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(400).json({ message: "Invalid password" });
    }

    res.json({
      message: "Login successful",
      user: {
        id: user.id,
        name: user.full_name,
        email: user.email
      }
    });

  } catch (err) {
    console.error("LOGIN ERROR:", err.message);
    res.status(500).json({ message: "Server error" });
  }
});
app.get("/api/test", (req, res) => {
  res.json({
    message: "Backend running on port 5000"
  });
});
/* ================= SERVE FRONTEND ================= */

app.use(
  express.static(
    path.join(__dirname, "../aavs-frontend/dist")
  )
);

app.use((req, res) => {
  res.sendFile(
    path.join(__dirname, "../aavs-frontend/dist/index.html")
  );
});


/* ================= START SERVER ================= */

app.listen(5000, () => {
  console.log("Server running on http://127.0.0.1:5000");
});