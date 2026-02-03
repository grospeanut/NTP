import express from "express";
import jwt from "jsonwebtoken";
import mysql from "mysql2/promise";

// -------------------- Hardcoded config (EDIT THESE) --------------------
// Same format as your C# `Data/Db.cs` uses.
const MYSQL_CONNECTION_STRING =
  "Server=188.245.158.246;Port=3306;Database=NTP;User=root;Password=wtEgR59qxb1BcaPp8XZxnC93Bg2vNvpQmOvwhQylm5Iq3HAEz5d4NoZnWI7C7mM0;SslMode=Preferred;";

// JWT secret hardcoded too (EDIT THIS)
const JWT_SECRET = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET_32+";
const JWT_ISSUER = "NaprednoApi";
const JWT_AUDIENCE = "NaprednoClients";

const PORT = 5175;

// -------------------- MySQL connection --------------------
function parseMySqlCs(cs) {
  const parts = Object.create(null);
  for (const chunk of cs.split(";")) {
    const [k, ...rest] = chunk.split("=");
    if (!k || rest.length === 0) continue;
    parts[k.trim().toLowerCase()] = rest.join("=").trim();
  }

  const host = parts.server ?? parts.host ?? "127.0.0.1";
  const port = Number(parts.port ?? 3306);
  const database = parts.database;
  const user = parts.user ?? parts.uid ?? parts.username;
  const password = parts.password ?? "";

  if (!database) throw new Error("Connection string missing Database=...");
  if (!user) throw new Error("Connection string missing User=...");

  return { host, port, database, user, password };
}

const pool = mysql.createPool({
  ...parseMySqlCs(MYSQL_CONNECTION_STRING),
  waitForConnections: true,
  connectionLimit: 10,
  maxIdle: 10,
  idleTimeout: 60_000
});

// -------------------- Auth helpers --------------------
function signToken(user) {
  return jwt.sign(
    {
      sub: String(user.id),
      name: user.username,
      role: user.role,
      city: user.city
    },
    JWT_SECRET,
    {
      algorithm: "HS256",
      expiresIn: "2h",
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE
    }
  );
}

function requireAuth(req, res, next) {
  const hdr = req.headers["authorization"];
  const token = hdr?.startsWith("Bearer ") ? hdr.slice("Bearer ".length) : null;
  if (!token) return res.status(401).json({ error: "Missing bearer token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE
    });
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Not authenticated" });
    if (req.user.role !== role) return res.status(403).json({ error: "Forbidden (missing role)" });
    next();
  };
}

// -------------------- API --------------------
const app = express();
app.use(express.json());

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body ?? {};
  if (!username || !password) return res.status(400).json({ error: "username/password required" });

  const [rows] = await pool.query(
    "SELECT Id, Username, PasswordHash, Email, Role, City FROM Users WHERE Username = ? LIMIT 1",
    [username]
  );

  const u = rows?.[0];
  if (!u) return res.status(401).json({ error: "Invalid credentials" });

  // DEMO: matches your `DbSeeder.cs` where PasswordHash is plain ("admin"/"user")
  if (u.PasswordHash !== password) return res.status(401).json({ error: "Invalid credentials" });

  const token = signToken({ id: u.Id, username: u.Username, role: u.Role, city: u.City });

  return res.json({
    accessToken: token,
    user: { id: u.Id, username: u.Username, email: u.Email, role: u.Role, city: u.City }
  });
});

// Resource #1: any authenticated user
app.get("/api/profile", requireAuth, (req, res) => {
  res.json({
    message: "Authenticated OK",
    username: req.user.name,
    role: req.user.role,
    city: req.user.city
  });
});

// Resource #2: Admin only
app.get("/api/admin/reports", requireAuth, requireRole("Admin"), (_req, res) => {
  res.json({ report: "Top secret admin report" });
});

app.get("/health", (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));
