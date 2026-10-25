const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const { DATABASE_URL, JWT_SECRET } = process.env;
if (!DATABASE_URL || !JWT_SECRET) {
  console.error("Missing DATABASE_URL or JWT_SECRET environment variable.");
  process.exit(1);
}
const noSsl = process.env.PGSSL === "off" || /localhost|127\.0\.0\.1/.test(DATABASE_URL);
const pool = new Pool({ connectionString: DATABASE_URL, ssl: noSsl ? false : { rejectUnauthorized: false } });

pool.on("error", (e) => console.error("Database connection error:", e.message));

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "1mb" }));
app.use((q, s, n) => {
  s.set({ "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin" });
  n();
});

const COOKIE = "sid";
const prod = process.env.NODE_ENV === "production";
const DUMMY = bcrypt.hashSync("not-a-real-password", 10);
const wrap = (fn) => (q, s) => fn(q, s).catch((e) => { console.error(e); s.status(500).json({ error: "Server error" }); });

const give = (s, u) =>
  s.cookie(COOKIE, jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: "30d" }), {
    httpOnly: true, sameSite: "lax", secure: prod, maxAge: 30 * 864e5,
  });
const getUid = (q) => {
  const c = (q.headers.cookie || "").split(";").map((x) => x.trim()).find((x) => x.startsWith(COOKIE + "="));
  if (!c) return null;
  try { return jwt.verify(decodeURIComponent(c.slice(COOKIE.length + 1)), JWT_SECRET).id; } catch (e) { return null; }
};
const auth = (q, s, n) => {
  const id = getUid(q);
  if (!id) return s.status(401).json({ error: "Please log in" });
  q.uid = id; n();
};

// Simple in-memory limiter: 10 attempts per 15 minutes per key.
const tries = new Map();
const tooMany = (k) => {
  const now = Date.now(), a = (tries.get(k) || []).filter((t) => now - t < 9e5);
  a.push(now); tries.set(k, a); return a.length > 10;
};
setInterval(() => tries.clear(), 36e5).unref();

const cleanEmail = (e) => String(e || "").trim().toLowerCase();
const okEmail = (e) => e.length <= 254 && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e);
const okPass = (p) => typeof p === "string" && p.length >= 8 && p.length <= 200;

app.get("/health", (q, s) => s.send("ok"));

app.post("/api/signup", wrap(async (q, s) => {
  const email = cleanEmail(q.body.email), pw = q.body.password;
  if (tooMany("s" + q.ip)) return s.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
  if (!okEmail(email)) return s.status(400).json({ error: "Enter a valid email." });
  if (!okPass(pw)) return s.status(400).json({ error: "Password must be at least 8 characters." });
  try {
    const r = await pool.query("insert into users(email,pass_hash) values($1,$2) returning id,email", [email, await bcrypt.hash(pw, 10)]);
    give(s, r.rows[0]); s.json({ user: r.rows[0] });
  } catch (e) {
    if (e.code === "23505") return s.status(409).json({ error: "That email already has an account. Log in instead." });
    throw e;
  }
}));

app.post("/api/login", wrap(async (q, s) => {
  const email = cleanEmail(q.body.email);
  if (tooMany("l" + q.ip + email)) return s.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
  const r = await pool.query("select id,email,pass_hash from users where email=$1", [email]);
  const u = r.rows[0];
  const ok = await bcrypt.compare(String(q.body.password || ""), u ? u.pass_hash : DUMMY);
  if (!u || !ok) return s.status(401).json({ error: "Wrong email or password." });
  give(s, u); s.json({ user: { id: u.id, email: u.email } });
}));

app.post("/api/logout", (q, s) => { s.clearCookie(COOKIE); s.json({ ok: true }); });

app.get("/api/me", auth, wrap(async (q, s) => {
  const r = await pool.query("select id,email from users where id=$1", [q.uid]);
  if (!r.rows[0]) return s.status(401).json({ error: "Please log in" });
  s.json({ user: r.rows[0] });
}));

app.get("/api/data", auth, wrap(async (q, s) => {
  const r = await pool.query("select data from dashboards where user_id=$1", [q.uid]);
  s.json({ data: r.rows[0] ? r.rows[0].data : null });
}));

app.put("/api/data", auth, wrap(async (q, s) => {
  const d = q.body.data;
  if (!d || typeof d !== "object" || Array.isArray(d)) return s.status(400).json({ error: "Invalid data" });
  await pool.query(
    "insert into dashboards(user_id,data,updated_at) values($1,$2,now()) on conflict (user_id) do update set data=excluded.data, updated_at=now()",
    [q.uid, JSON.stringify(d)]
  );
  s.json({ ok: true });
}));

app.post("/api/change-password", auth, wrap(async (q, s) => {
  const { oldPassword, newPassword } = q.body;
  if (!okPass(newPassword)) return s.status(400).json({ error: "New password must be at least 8 characters." });
  const r = await pool.query("select pass_hash from users where id=$1", [q.uid]);
  if (!r.rows[0] || !(await bcrypt.compare(String(oldPassword || ""), r.rows[0].pass_hash)))
    return s.status(401).json({ error: "Current password is wrong." });
  await pool.query("update users set pass_hash=$1 where id=$2", [await bcrypt.hash(newPassword, 10), q.uid]);
  s.json({ ok: true });
}));

app.use(express.static(path.join(__dirname, "public")));

(async () => {
  await pool.query(`create table if not exists users(
    id serial primary key, email text unique not null, pass_hash text not null, created_at timestamptz default now())`);
  await pool.query(`create table if not exists dashboards(
    user_id int primary key references users(id) on delete cascade, data jsonb not null, updated_at timestamptz default now())`);
  app.listen(process.env.PORT || 3000, () => console.log("Dashboard running"));
})().catch((e) => { console.error("Startup failed:", e.message); process.exit(1); });
