"use strict";
const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");

const PORT = process.env.PORT || 8080;
const DATA_DIR = path.join(__dirname, "..", "data");
const DB_PATH = path.join(DATA_DIR, "music.db");

function genSalt(len = 32) {
  return crypto.randomBytes(len).toString("hex");
}
function sha256Hex(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}
function saltedHash(password, salt) {
  return sha256Hex(salt + password);
}
function generateSessionId() {
  return crypto.randomBytes(24).toString("hex");
}

// Database
const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    salt TEXT NOT NULL,
    hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS favorites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    song_id INTEGER NOT NULL,
    song_name TEXT NOT NULL,
    artist TEXT NOT NULL,
    album TEXT NOT NULL,
    album_pic TEXT,
    added_at TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, song_id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS play_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    song_id INTEGER NOT NULL,
    song_name TEXT NOT NULL,
    artist TEXT NOT NULL,
    album TEXT NOT NULL,
    played_at TEXT DEFAULT (datetime('now'))
  )`);
});

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "public")));

const sessionStore = new Map();

function authRequired(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "未登录" });
  }
  const sid = authHeader.slice(7);
  const session = sessionStore.get(sid);
  if (!session || new Date(session.expiresAt) < new Date()) {
    sessionStore.delete(sid);
    return res.status(401).json({ error: "登录已过期" });
  }
  req.userId = session.userId;
  req.userName = session.userName;
  next();
}

async function apiFetch(url, options = {}) {
  const { default: nodeFetch } = await import("node-fetch");
  const resp = await nodeFetch(url, options);
  return await resp.json();
}

// ─── Auth ──────────────────────────────────────────────────

app.post("/api/auth/register", (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: "用户名和密码不能为空" });
  if (name.length < 2 || name.length > 20) return res.status(400).json({ error: "用户名长度 2-20 位" });
  if (password.length < 6) return res.status(400).json({ error: "密码至少 6 位" });
  const salt = genSalt();
  const hash = saltedHash(password, salt);
  db.run("INSERT INTO users (name, salt, hash) VALUES (?, ?, ?)", [name, salt, hash], function (err) {
    if (err) {
      if (err.message.includes("UNIQUE constraint")) return res.status(409).json({ error: "用户名已存在" });
      return res.status(500).json({ error: "注册失败" });
    }
    const sid = generateSessionId();
    sessionStore.set(sid, { userId: this.lastID, userName: name, expiresAt: new Date(Date.now() + 30*24*60*60*1000).toISOString() });
    res.json({ sessionId: sid, user: { id: this.lastID, name } });
  });
});

app.post("/api/auth/login", (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: "用户名和密码不能为空" });
  db.get("SELECT * FROM users WHERE name = ?", [name], (err, user) => {
    if (err || !user) return res.status(401).json({ error: "用户名或密码错误" });
    if (saltedHash(password, user.salt) !== user.hash) return res.status(401).json({ error: "用户名或密码错误" });
    const sid = generateSessionId();
    sessionStore.set(sid, { userId: user.id, userName: user.name, expiresAt: new Date(Date.now() + 30*24*60*60*1000).toISOString() });
    res.json({ sessionId: sid, user: { id: user.id, name: user.name } });
  });
});

app.post("/api/auth/logout", authRequired, (req, res) => {
  const sid = (req.body && req.body.sessionId) || req.headers.authorization?.slice(7);
  if (sid) sessionStore.delete(sid);
  res.json({ ok: true });
});

// ─── Search (gdstudio API) ────────────────────────────────

app.get("/api/search", authRequired, async (req, res) => {
  const { q } = req.query;
  if (!q || !q.trim()) return res.status(400).json({ error: "搜索词不能为空" });
  try {
    const data = await apiFetch(
      `https://music-api.gdstudio.xyz/api.php?types=search&name=${encodeURIComponent(q.trim())}&limit=30`,
      { headers: { "User-Agent": "Mozilla/5.0" }, timeout: 10000 }
    );
    // gdstudio returns array of {id, name, artist[], album, pic_id, url_id}
    const songs = (Array.isArray(data) ? data : []).map(s => ({
      id: s.url_id || s.id,
      name: s.name || "未知曲目",
      artists: Array.isArray(s.artist) ? s.artist : [s.artist || "未知歌手"],
      artist: Array.isArray(s.artist) ? s.artist.join(",") : (s.artist || "未知歌手"),
      album: s.album || "未知专辑",
      picUrl: s.pic_id ? `https://p1.music.126.net/pic/${s.pic_id}.jpg` : "",
    }));
    res.json({ songs });
  } catch (e) {
    res.status(502).json({ error: "搜索失败: " + e.message });
  }
});

// ─── Play URL (gdstudio API) ───────────────────────────────

app.get("/api/play/url", authRequired, async (req, res) => {
  const { id } = req.query;
  if (!id) return res.status(400).json({ error: "缺少歌曲ID" });
  try {
    // Primary: gdstudio
    const d1 = await apiFetch(
      `https://music-api.gdstudio.xyz/api.php?types=url&source=netease&id=${id}`,
      { headers: { "User-Agent": "Mozilla/5.0" }, timeout: 8000 }
    );
    if (d1 && d1.url) {
      return res.json({ url: d1.url, quality: d1.br || "standard" });
    }
    // Fallback: kgqy
    const d2 = await apiFetch(
      `https://api.nn.ci/kgqy/?id=${id}`,
      { headers: { "User-Agent": "Mozilla/5.0" }, timeout: 8000 }
    );
    const url = d2 && (d2.url || d2.link || d2.data);
    if (url && typeof url === "string" && url.startsWith("http")) {
      return res.json({ url, quality: "standard" });
    }
    return res.status(404).json({ error: "暂无法解析该歌曲直链，请换一首试试" });
  } catch (e) {
    res.status(502).json({ error: "解析失败: " + e.message });
  }
});

// ─── Favorites ─────────────────────────────────────────────

app.get("/api/favorites", authRequired, (req, res) => {
  db.all("SELECT * FROM favorites WHERE user_id = ? ORDER BY added_at DESC", [req.userId],
    (err, rows) => err ? res.status(500).json({ error: "获取失败" }) : res.json(rows));
});
app.post("/api/favorites", authRequired, (req, res) => {
  const { songId, songName, artist, album, albumPic } = req.body;
  if (!songId || !songName) return res.status(400).json({ error: "参数不足" });
  db.run(
    "INSERT OR IGNORE INTO favorites (user_id, song_id, song_name, artist, album, album_pic) VALUES (?, ?, ?, ?, ?, ?)",
    [req.userId, songId, songName, artist || "", album || "", albumPic || ""],
    function(err) { if (err) return res.status(500).json({ error: "收藏失败" }); res.json({ ok: true }); }
  );
});
app.delete("/api/favorites/:songId", authRequired, (req, res) => {
  db.run("DELETE FROM favorites WHERE user_id = ? AND song_id = ?", [req.userId, req.params.songId], function(err) {
    if (err) return res.status(500).json({ error: "删除失败" });
    res.json({ ok: true });
  });
});

// ─── History ───────────────────────────────────────────────

app.get("/api/history", authRequired, (req, res) => {
  db.all("SELECT * FROM play_history WHERE user_id = ? ORDER BY played_at DESC LIMIT 100", [req.userId],
    (err, rows) => err ? res.status(500).json({ error: "获取失败" }) : res.json(rows));
});
app.post("/api/history", authRequired, (req, res) => {
  const { songId, songName, artist, album } = req.body;
  if (!songId || !songName) return res.status(400).json({ error: "参数不足" });
  db.run(
    "INSERT INTO play_history (user_id, song_id, song_name, artist, album) VALUES (?, ?, ?, ?, ?)",
    [req.userId, songId, songName, artist || "", album || ""],
    function(err) { if (err) return res.status(500).json({ error: "记录失败" }); res.json({ ok: true }); }
  );
});

// ─── Current User ──────────────────────────────────────────

app.get("/api/me", authRequired, (req, res) => {
  res.json({ user: { id: req.userId, name: req.userName } });
});

fs.mkdirSync(DATA_DIR, { recursive: true });
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Music server running at http://0.0.0.0:${PORT}`);
});
