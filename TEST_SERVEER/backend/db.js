const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, 'database.sqlite');
const db = new Database(dbPath);

// Enable WAL mode for better concurrent read performance
db.pragma('journal_mode = WAL');

// ─────────────────────────────────────────────
//  Schema — create tables if they don't exist
// ─────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT DEFAULT '',
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    createdAt TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    userId TEXT NOT NULL,
    originalName TEXT NOT NULL,
    fileName TEXT NOT NULL,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    mimetype TEXT NOT NULL,
    createdAt TEXT NOT NULL,
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// ─────────────────────────────────────────────
//  Users
// ─────────────────────────────────────────────
const findUserByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const insertUser = db.prepare(`
  INSERT INTO users (id, name, email, password, createdAt)
  VALUES (@id, @name, @email, @password, @createdAt)
`);
const getAllUsers = db.prepare('SELECT * FROM users');

// ─────────────────────────────────────────────
//  Files
// ─────────────────────────────────────────────
const getFilesByUserId = db.prepare('SELECT * FROM files WHERE userId = ?');
const getFileByIdAndUser = db.prepare('SELECT * FROM files WHERE id = ? AND userId = ?');
const insertFile = db.prepare(`
  INSERT INTO files (id, userId, originalName, fileName, path, size, mimetype, createdAt)
  VALUES (@id, @userId, @originalName, @fileName, @path, @size, @mimetype, @createdAt)
`);
const updateFileName = db.prepare('UPDATE files SET originalName = ? WHERE id = ? AND userId = ?');
const deleteFileById = db.prepare('DELETE FROM files WHERE id = ? AND userId = ?');

module.exports = {
  db,
  findUserByEmail,
  insertUser,
  getAllUsers,
  getFilesByUserId,
  getFileByIdAndUser,
  insertFile,
  updateFileName,
  deleteFileById,
};
