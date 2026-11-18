require('dotenv').config({ path: './dotenv.env' });
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Statik Dosya Sunumu
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

app.use(session({
  secret: 'vilsan-gizli-anahtar-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  res.status(401).json({ success: false, message: 'Oturum açmanız gerekiyor.' });
}

/* ================= SAYFA YÖNLENDİRMELERİ ================= */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'personel.html'), (err) => {
    if (err) res.sendFile(path.join(__dirname, 'public', 'personel.html'));
  });
});

app.get(['/yonetici.html', '/yönetici.html', '/admin.html', '/yonetici', '/admin', '/yönetici'], (req, res) => {
  res.sendFile(path.join(__dirname, 'yonetici.html'), (err) => {
    if (err) {
      res.sendFile(path.join(__dirname, 'public', 'yonetici.html'), (err2) => {
        if (err2) res.status(404).send('yonetici.html dosyası klasörde bulunamadı!');
      });
    }
  });
});

/* ================= API ROTASI: KULLANICI GİRİŞİ ================= */
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Lütfen kullanıcı adı ve şifre girin.' });
  }

  try {
    const result = await db.execute({
      sql: 'SELECT * FROM users WHERE username = ?',
      args: [username]
    });

    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ success: false, message: 'Geçersiz kullanıcı adı veya şifre.' });
    }

    let match = false;
    if (user.password_hash && (user.password_hash.startsWith('$2b$') || user.password_hash.startsWith('$2a$'))) {
      match = await bcrypt.compare(password, user.password_hash);
    } else {
      match = (password === user.password_hash);
    }

    if (match) {
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.fullName = user.full_name;
      return res.json({ success: true, message: 'Giriş başarılı.', user: { username: user.username, fullName: user.full_name } });
    } else {
      return res.status(401).json({ success: false, message: 'Geçersiz kullanıcı adı veya şifre.' });
    }
  } catch (err) {
    console.error('Login Hatası:', err);
    res.status(500).json({ success: false, message: 'Sunucu hatası.' });
  }
});

/* ================= API ROTASI: ŞİFRE DEĞİŞTİRME ================= */
app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  if (!oldPassword || !newPassword) {
    return res.status(400).json({ success: false, message: 'Eski ve yeni şifre alanları zorunludur.' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ success: false, message: 'Yeni şifre en az 6 karakter olmalıdır.' });
  }

  try {
    const result = await db.execute({
      sql: 'SELECT * FROM users WHERE id = ?',
      args: [req.session.userId]
    });
    const user = result.rows[0];

    let match = false;
    if (user.password_hash && (user.password_hash.startsWith('$2b$') || user.password_hash.startsWith('$2a$'))) {
      match = await bcrypt.compare(oldPassword, user.password_hash);
    } else {
      match = (oldPassword === user.password_hash);
    }

    if (!match) {
      return res.status(400).json({ success: false, message: 'Mevcut şifreniz yanlış!' });
    }

    const newHash = await bcrypt.hash(newPassword, 10);
    await db.execute({
      sql: 'UPDATE users SET password_hash = ? WHERE id = ?',
      args: [newHash, user.id]
    });

    return res.json({ success: true, message: 'Şifreniz başarıyla değiştirildi.' });
  } catch (err) {
    console.error('Şifre Değiştirme Hatası:', err);
    res.status(500).json({ success: false, message: 'Şifre güncellenirken hata oluştu.' });
  }
});

/* ================= API ROTASI: OTURUM ÇIKIŞI ================= */
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true, message: 'Çıkış yapıldı.' });
});

/* ================= API ROTASI: OTURUM SORGULAMA ================= */
app.get('/api/auth/me', (req, res) => {
  if (req.session && req.session.userId) {
    res.json({ authenticated: true, user: { username: req.session.username, fullName: req.session.fullName } });
  } else {
    res.json({ authenticated: false });
  }
});

/* ================= API ROTASI: FORM VERİSİ KAYDI ================= */
app.post('/api/submissions', async (req, res) => {
  const { id, date, time, personnelName, values, note } = req.body;

  if (!personnelName || !date || !time) {
    return res.status(400).json({ success: false, message: 'Lütfen zorunlu alanları doldurun.' });
  }

  try {
    await db.execute({
      sql: `INSERT INTO submissions (id, date, time, personnel_name, submitted_at, values_json, note)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
      args: [
        id || Date.now().toString(36),
        date,
        time,
        personnelName,
        new Date().toISOString(),
        JSON.stringify(values || {}),
        note || ''
      ]
    });
    res.json({ success: true, message: 'Form kaydı başarıyla oluşturuldu.' });
  } catch (err) {
    console.error('Kayıt Hatası:', err);
    res.status(500).json({ success: false, message: 'Kayıt veritabanına işlenemedi.' });
  }
});

/* ================= API ROTASI: FORM VERİLERİNİ LİSTELEME ================= */
app.get('/api/submissions', requireAuth, async (req, res) => {
  try {
    const data = await db.execute('SELECT * FROM submissions ORDER BY date DESC, time DESC');
    const result = data.rows.map(r => ({
      id: r.id,
      date: r.date,
      time: r.time,
      personnelName: r.personnel_name,
      submittedAt: r.submitted_at,
      values: JSON.parse(r.values_json || '{}'),
      note: r.note,
      approved: Boolean(r.approved),
      approvedBy: r.approved_by,
      approvedAt: r.approved_at
    }));
    res.json({ success: true, submissions: result });
  } catch (err) {
    console.error('Listeleme Hatası:', err);
    res.status(500).json({ success: false, message: 'Veriler getirilemedi.' });
  }
});

/* ================= API ROTASI: FORM SİLME ================= */
app.delete('/api/submissions/:id', requireAuth, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await db.execute({
      sql: 'DELETE FROM submissions WHERE id = ?',
      args: [id]
    });

    if (result.rowsAffected > 0) {
      return res.json({ success: true, message: 'Form kaydı başarıyla silindi.' });
    } else {
      return res.status(404).json({ success: false, message: 'Silinmek istenen form bulunamadı.' });
    }
  } catch (err) {
    console.error('Silme Hatası:', err);
    return res.status(500).json({ success: false, message: 'Silme işlemi sırasında sunucu hatası oluştu.' });
  }
});

/* ================= API ROTASI: ÖZEL KALEMLER ================= */
app.get('/api/custom-items', async (req, res) => {
  try {
    const data = await db.execute('SELECT * FROM custom_items');
    const grouped = {};
    data.rows.forEach(r => {
      if (!grouped[r.section_id]) grouped[r.section_id] = [];
      grouped[r.section_id].push({
        id: r.id,
        no: '+',
        name: r.name,
        unit: r.unit,
        range: r.range,
        type: r.type,
        custom: true
      });
    });
    res.json({ success: true, customItems: grouped });
  } catch (err) {
    console.error('Özel Kalemler Hatası:', err);
    res.status(500).json({ success: false, message: 'Özel kalemler getirilemedi.' });
  }
});

app.post('/api/custom-items', requireAuth, async (req, res) => {
  const { id, sectionId, name, unit, range } = req.body;
  try {
    await db.execute({
      sql: `INSERT INTO custom_items (id, section_id, name, unit, range)
            VALUES (?, ?, ?, ?, ?)`,
      args: [id || ('custom-' + Date.now().toString(36)), sectionId, name, unit || '-', range || '-']
    });
    res.json({ success: true, message: 'Özel kalem başarıyla eklendi.' });
  } catch (err) {
    console.error('Özel Kalem Ekleme Hatası:', err);
    res.status(500).json({ success: false, message: 'Özel kalem eklenemedi.' });
  }
});

app.listen(PORT, () => {
  console.log(`Vilsan Su Sistemleri Sunucusu Aktif! Port: ${PORT}`);
});