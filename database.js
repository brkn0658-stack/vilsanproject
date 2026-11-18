const { createClient } = require('@libsql/client');
const bcrypt = require('bcrypt');

const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// Tabloları Oluştur
async function initDB() {
  await db.executeMultiple(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      full_name TEXT
    );

    CREATE TABLE IF NOT EXISTS submissions (
      id TEXT PRIMARY KEY,
      date TEXT NOT NULL,
      time TEXT NOT NULL,
      personnel_name TEXT NOT NULL,
      submitted_at TEXT NOT NULL,
      values_json TEXT NOT NULL,
      note TEXT,
      approved INTEGER DEFAULT 0,
      approved_by TEXT,
      approved_at TEXT
    );

    CREATE TABLE IF NOT EXISTS custom_items (
      id TEXT PRIMARY KEY,
      section_id TEXT NOT NULL,
      name TEXT NOT NULL,
      unit TEXT,
      range TEXT,
      type TEXT DEFAULT 'number'
    );
  `);

  // Varsayılan Yönetici Kullanıcısını Ekleyen Fonksiyon
  const checkUser = await db.execute({
    sql: 'SELECT * FROM users WHERE username = ?',
    args: ['admin']
  });

  if (checkUser.rows.length === 0) {
    const defaultPassword = 'admin123';
    const hash = await bcrypt.hash(defaultPassword, 10);
    await db.execute({
      sql: 'INSERT INTO users (username, password_hash, full_name) VALUES (?, ?, ?)',
      args: ['admin', hash, 'Sistem Yöneticisi']
    });
    console.log('[Sistem] Varsayılan yönetici hesabı bulutta oluşturuldu.');
  }
}

initDB();

module.exports = db;