import express from "express";
import jwt from "jsonwebtoken";
import mysql from "mysql2/promise";

// NOTE: For simple local/WPF testing you may also need CORS.

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

function toId(x) {
  const n = Number(x);
  return Number.isFinite(n) ? n : null;
}

// -------------------- API --------------------
const app = express();
app.use(express.json());

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "authorization, content-type");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

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

  const userId = u.Id ?? u.id;
  const token = signToken({ id: userId, username: u.Username, role: u.Role, city: u.City });

  return res.json({
    accessToken: token,
    user: { id: userId, username: u.Username, email: u.Email, role: u.Role, city: u.City }
  });
});

// Debug/troubleshoot: verify which DB is connected and if Users table has rows
app.get("/api/admin/dbinfo", requireAuth, requireRole("Admin"), async (_req, res) => {
  const [dbRows] = await pool.query("SELECT DATABASE() AS db");
  const [countRows] = await pool.query("SELECT COUNT(*) AS userCount FROM Users");
  res.json({ database: dbRows?.[0]?.db, userCount: countRows?.[0]?.userCount });
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

// Admin-only: list users (do NOT expose PasswordHash)
app.get("/api/admin/users", requireAuth, requireRole("Admin"), async (_req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT Id, Username, Email, Role, City FROM Users ORDER BY Id"
    );
    return res.json(rows);
  } catch (e) {
    return res.status(500).json({ error: "Failed to load users" });
  }
});

// Admin-only: create user
app.post("/api/admin/users", requireAuth, requireRole("Admin"), async (req, res) => {
  const { username, password, email, role, city } = req.body ?? {};
  if (!username || !password || !email || !role || !city) {
    return res.status(400).json({ error: "username,password,email,role,city required" });
  }

  try {
    const [r] = await pool.query(
      "INSERT INTO Users (Username, PasswordHash, Email, Role, City) VALUES (?,?,?,?,?)",
      [String(username), String(password), String(email), String(role), String(city)]
    );
    return res.status(201).json({ id: r.insertId });
  } catch {
    return res.status(500).json({ error: "Failed to create user" });
  }
});

// Admin-only: update user (password optional)
app.put("/api/admin/users/:id", requireAuth, requireRole("Admin"), async (req, res) => {
  const id = toId(req.params.id);
  if (!id) return res.status(400).json({ error: "Invalid id" });

  const { username, password, email, role, city } = req.body ?? {};
  if (!username || !email || !role || !city) {
    return res.status(400).json({ error: "username,email,role,city required" });
  }

  try {
    if (password && String(password).length > 0) {
      const [r] = await pool.query(
        "UPDATE Users SET Username=?, PasswordHash=?, Email=?, Role=?, City=? WHERE Id=?",
        [String(username), String(password), String(email), String(role), String(city), id]
      );
      if (r.affectedRows === 0) return res.sendStatus(404);
      return res.sendStatus(204);
    }

    const [r] = await pool.query(
      "UPDATE Users SET Username=?, Email=?, Role=?, City=? WHERE Id=?",
      [String(username), String(email), String(role), String(city), id]
    );
    if (r.affectedRows === 0) return res.sendStatus(404);
    return res.sendStatus(204);
  } catch {
    return res.status(500).json({ error: "Failed to update user" });
  }
});

// Admin-only: delete user
app.delete("/api/admin/users/:id", requireAuth, requireRole("Admin"), async (req, res) => {
  const id = toId(req.params.id);
  if (!id) return res.status(400).json({ error: "Invalid id" });

  try {
    const [r] = await pool.query("DELETE FROM Users WHERE Id=?", [id]);
    if (r.affectedRows === 0) return res.sendStatus(404);
    return res.sendStatus(204);
  } catch {
    return res.status(500).json({ error: "Failed to delete user" });
  }
});

// Locations (read for any authenticated user; write for Admin)
app.get("/api/locations", requireAuth, async (_req, res) => {
  const [rows] = await pool.query("SELECT Id, Name, City FROM Locations ORDER BY Id");
  res.json(rows);
});

app.post("/api/locations", requireAuth, requireRole("Admin"), async (req, res) => {
  const { name, city } = req.body ?? {};
  if (!name || !city) return res.status(400).json({ error: "name,city required" });
  try {
    const [r] = await pool.query("INSERT INTO Locations (Name, City) VALUES (?,?)", [String(name), String(city)]);
    res.status(201).json({ id: r.insertId });
  } catch {
    res.status(500).json({ error: "Failed to create location" });
  }
});

app.put("/api/locations/:id", requireAuth, requireRole("Admin"), async (req, res) => {
  const id = toId(req.params.id);
  if (!id) return res.status(400).json({ error: "Invalid id" });
  const { name, city } = req.body ?? {};
  if (!name || !city) return res.status(400).json({ error: "name,city required" });
  try {
    const [r] = await pool.query("UPDATE Locations SET Name=?, City=? WHERE Id=?", [String(name), String(city), id]);
    if (r.affectedRows === 0) return res.sendStatus(404);
    res.sendStatus(204);
  } catch {
    res.status(500).json({ error: "Failed to update location" });
  }
});

app.delete("/api/locations/:id", requireAuth, requireRole("Admin"), async (req, res) => {
  const id = toId(req.params.id);
  if (!id) return res.status(400).json({ error: "Invalid id" });
  try {
    const [r] = await pool.query("DELETE FROM Locations WHERE Id=?", [id]);
    if (r.affectedRows === 0) return res.sendStatus(404);
    res.sendStatus(204);
  } catch {
    res.status(500).json({ error: "Failed to delete location" });
  }
});

// Devices (read for any authenticated user; write for Admin)
app.get("/api/devices", requireAuth, async (_req, res) => {
  const [rows] = await pool.query(
    "SELECT Id, LocationId, Name, Type, CapacityKg, PricePerWash, IsActive FROM Devices ORDER BY Id"
  );
  res.json(rows);
});

app.post("/api/devices", requireAuth, requireRole("Admin"), async (req, res) => {
  const { locationId, name, type, capacityKg, pricePerWash, isActive } = req.body ?? {};
  const locId = toId(locationId);
  if (!locId || !name || !type) return res.status(400).json({ error: "locationId,name,type required" });
  try {
    const [r] = await pool.query(
      "INSERT INTO Devices (LocationId, Name, Type, CapacityKg, PricePerWash, IsActive) VALUES (?,?,?,?,?,?)",
      [
        locId,
        String(name),
        String(type),
        capacityKg ?? null,
        pricePerWash ?? null,
        isActive ?? true
      ]
    );
    res.status(201).json({ id: r.insertId });
  } catch {
    res.status(500).json({ error: "Failed to create device" });
  }
});

app.put("/api/devices/:id", requireAuth, requireRole("Admin"), async (req, res) => {
  const id = toId(req.params.id);
  if (!id) return res.status(400).json({ error: "Invalid id" });
  const { locationId, name, type, capacityKg, pricePerWash, isActive } = req.body ?? {};
  const locId = toId(locationId);
  if (!locId || !name || !type) return res.status(400).json({ error: "locationId,name,type required" });
  try {
    const [r] = await pool.query(
      "UPDATE Devices SET LocationId=?, Name=?, Type=?, CapacityKg=?, PricePerWash=?, IsActive=? WHERE Id=?",
      [locId, String(name), String(type), capacityKg ?? null, pricePerWash ?? null, isActive ?? true, id]
    );
    if (r.affectedRows === 0) return res.sendStatus(404);
    res.sendStatus(204);
  } catch {
    res.status(500).json({ error: "Failed to update device" });
  }
});

app.delete("/api/devices/:id", requireAuth, requireRole("Admin"), async (req, res) => {
  const id = toId(req.params.id);
  if (!id) return res.status(400).json({ error: "Invalid id" });
  try {
    const [r] = await pool.query("DELETE FROM Devices WHERE Id=?", [id]);
    if (r.affectedRows === 0) return res.sendStatus(404);
    res.sendStatus(204);
  } catch {
    res.status(500).json({ error: "Failed to delete device" });
  }
});

// Reservations (read for authenticated user; create for authenticated user; delete for Admin)
app.get("/api/reservations", requireAuth, async (_req, res) => {
  const [rows] = await pool.query(
    "SELECT Id, UserId, DeviceId, StartAtUtc, EndAtUtc, Status FROM Reservations ORDER BY StartAtUtc DESC"
  );
  res.json(rows);
});

app.post("/api/reservations", requireAuth, async (req, res) => {
  const { deviceId, startAtUtc, endAtUtc, status } = req.body ?? {};
  const devId = toId(deviceId);
  const userId = toId(req.user.sub);
  if (!devId || !userId || !startAtUtc || !endAtUtc) {
    return res.status(400).json({ error: "deviceId,startAtUtc,endAtUtc required" });
  }

  try {
    const [r] = await pool.query(
      "INSERT INTO Reservations (UserId, DeviceId, StartAtUtc, EndAtUtc, Status) VALUES (?,?,?,?,?)",
      [userId, devId, startAtUtc, endAtUtc, status ?? "Created"]
    );
    res.status(201).json({ id: r.insertId });
  } catch {
    res.status(500).json({ error: "Failed to create reservation" });
  }
});

app.put("/api/reservations/:id", requireAuth, async (req, res) => {
  const id = toId(req.params.id);
  if (!id) return res.status(400).json({ error: "Invalid id" });
  const { startAtUtc, endAtUtc, status } = req.body ?? {};
  if (!startAtUtc || !endAtUtc || !status) return res.status(400).json({ error: "startAtUtc,endAtUtc,status required" });

  const userId = toId(req.user.sub);
  if (!userId) return res.status(401).json({ error: "Invalid token" });

  try {
    // Allow Admin to edit any reservation; normal user can edit only their own.
    const isAdmin = req.user.role === "Admin";
    const sql = isAdmin
      ? "UPDATE Reservations SET StartAtUtc=?, EndAtUtc=?, Status=? WHERE Id=?"
      : "UPDATE Reservations SET StartAtUtc=?, EndAtUtc=?, Status=? WHERE Id=? AND UserId=?";
    const args = isAdmin
      ? [startAtUtc, endAtUtc, String(status), id]
      : [startAtUtc, endAtUtc, String(status), id, userId];

    const [r] = await pool.query(sql, args);
    if (r.affectedRows === 0) return res.sendStatus(404);
    res.sendStatus(204);
  } catch {
    res.status(500).json({ error: "Failed to update reservation" });
  }
});

app.delete("/api/reservations/:id", requireAuth, requireRole("Admin"), async (req, res) => {
  const id = toId(req.params.id);
  if (!id) return res.status(400).json({ error: "Invalid id" });
  try {
    const [r] = await pool.query("DELETE FROM Reservations WHERE Id=?", [id]);
    if (r.affectedRows === 0) return res.sendStatus(404);
    res.sendStatus(204);
  } catch {
    res.status(500).json({ error: "Failed to delete reservation" });
  }
});

app.get("/health", (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));
