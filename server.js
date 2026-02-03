import "dotenv/config";
import express from "express";
import jwt from "jsonwebtoken";
import mysql from "mysql2/promise";

// -------------------- Config --------------------
const PORT = Number(process.env.PORT ?? 5175);

const MYSQL_CONNECTION_STRING = process.env.MYSQL_CONNECTION_STRING;
if (!MYSQL_CONNECTION_STRING) {
  throw new Error("Missing MYSQL_CONNECTION_STRING (set it in .env).");
}

const JWT_SECRET = process.env.JWT_SECRET ?? "DEV_ONLY_CHANGE_ME_TO_A_LONG_RANDOM_SECRET_32+";
const JWT_ISSUER = process.env.JWT_ISSUER ?? "NaprednoApi";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE ?? "NaprednoClients";

// -------------------- MySQL connection (parses same style as your C# Db.cs) --------------------
function parseMySqlCs(cs) {
  // Supports: Server=...;Port=...;Database=...;User=...;Password=...;SslMode=...;
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

  if (!database) throw new Error("MYSQL_CONNECTION_STRING missing Database=...");
  if (!user) throw new Error("MYSQL_CONNECTION_STRING missing User=...");

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
  // user: { id, username, role, city }
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
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE
    });

    req.user = decoded; // { sub, name, role, city, iat, exp, ... }
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

// Auth: login -> JWT
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body ?? {};
  if (!username || !password) return res.status(400).json({ error: "username/password required" });

  // Schema matches your EF model / seeder:
  // Users: Id, Username, PasswordHash, Email, Role, City
  const [rows] = await pool.query(
    "SELECT Id, Username, PasswordHash, Email, Role, City FROM Users WHERE Username = ? LIMIT 1",
    [username]
  );

  const dbUser = rows?.[0];
  if (!dbUser) return res.status(401).json({ error: "Invalid credentials" });

  // DEMO: your DbSeeder.cs uses plain text password in PasswordHash ("admin"/"user")
  // For production, replace with bcrypt verify.
  if (dbUser.PasswordHash !== password) return res.status(401).json({ error: "Invalid credentials" });

  const token = signToken({
    id: dbUser.Id,
    username: dbUser.Username,
    role: dbUser.Role,
    city: dbUser.City
  });

  return res.json({
    accessToken: token,
    user: {
      id: dbUser.Id,
      username: dbUser.Username,
      email: dbUser.Email,
      role: dbUser.Role,
      city: dbUser.City
    }
  });
});

// Resource #1: any authenticated user
app.get("/api/profile", requireAuth, (req, res) => {
  return res.json({
    message: "Authenticated OK",
    username: req.user.name,
    role: req.user.role,
    city: req.user.city
  });
});

// Resource #2: only Admin
app.get("/api/admin/reports", requireAuth, requireRole("Admin"), (req, res) => {
  return res.json({ report: "Top secret admin report" });
});

// Health check (optional, no auth)
app.get("/health", (_, res) => res.json({ ok: true }));

// -------------------- Start --------------------
app.listen(PORT, () => {
  console.log(`API running on http://localhost:${PORT}`);
  console.log("Try: POST /api/auth/login then GET /api/profile and GET /api/admin/reports");
});
