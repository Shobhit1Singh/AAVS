const express = require("express");
const bodyParser = require("body-parser");
const { exec } = require("child_process");

const app = express();
app.use(bodyParser.json());

// global safety net so req.body never ruins your life again
app.use((req, res, next) => {
  if (!req.body) req.body = {};
  next();
});

let users = [
  { id: 1, username: "admin", password: "admin123", role: "admin" },
  { id: 2, username: "user", password: "user123", role: "user" }
];

// -----------------------------
// 1. Sensitive Data Exposure
// -----------------------------
app.get("/api/users", (req, res) => {
  res.json(users);
});

// -----------------------------
// 2. Auth Bypass + No Rate Limit
// -----------------------------
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};

  const user = users.find(
    u => u.username == username && u.password == password
  );

  if (user) {
    res.json({
      message: "Login success",
      token: "fake-jwt-token",
      user
    });
  } else {
    res.status(200).json({ message: "Invalid creds but still 200" });
  }
});

// -----------------------------
// 3. IDOR
// -----------------------------
app.get("/api/user/:id", (req, res) => {
  const user = users.find(u => u.id == req.params.id);
  res.json(user);
});

// -----------------------------
// 4. Mass Assignment
// -----------------------------
app.post("/api/update", (req, res) => {
  const { id, role } = req.body || {};

  const user = users.find(u => u.id == id);
  if (user) {
    user.role = role;
    res.json({ message: "Updated", user });
  } else {
    res.status(404).json({ error: "User not found" });
  }
});

// -----------------------------
// 5. Reflected Input (XSS)
// -----------------------------
app.get("/api/search", (req, res) => {
  const q = req.query.q || "";
  res.send(`Results for: ${q}`);
});

// -----------------------------
// 6. Command Injection
// -----------------------------
app.post("/api/exec", (req, res) => {
  const { cmd } = req.body || {};

  if (!cmd) {
    return res.status(400).send("No command provided");
  }

  exec(cmd, (err, stdout, stderr) => {
    if (err) {
      return res.send(err.message);
    }
    res.send(stdout || stderr);
  });
});

// -----------------------------
// 7. SQL-like Injection Simulation
// -----------------------------
app.post("/api/fake-sql", (req, res) => {
  const { username } = req.body || {};

  if (username && username.includes("' OR '1'='1")) {
    return res.json(users);
  }

  res.json({ message: "No injection" });
});

// -----------------------------
// 8. Error Leak
// -----------------------------
app.get("/api/crash", (req, res) => {
  throw new Error("Simulated server crash with stack trace");
});

// -----------------------------
app.listen(3000, () => {
  console.log("🔥 Vulnerable API running on http://localhost:3000");
});