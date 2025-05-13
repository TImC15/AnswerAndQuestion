const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(express.json());
app.use(express.static('public'));

const SECRET = process.env.JWT_SECRET;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Создание таблиц
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE,
      password TEXT,
      full_name TEXT,
      role TEXT DEFAULT 'user'
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS questions (
      id SERIAL PRIMARY KEY,
      question TEXT NOT NULL,
      answer TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      user_id INTEGER REFERENCES users(id),
      answered_by INTEGER REFERENCES users(id)
    );
  `);
})();

// Middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Что-то пошло не так!');
});

function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Нет токена' });

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Неверный токен' });
    req.user = user;
    next();
  });
}

// Регистрация
app.post('/register', async (req, res) => {
  const { email, password, fullname } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (email, password, full_name) VALUES ($1, $2, $3)',
      [email, hash, fullname]
    );

    // Получаем только что созданного пользователя
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, role: user.role }, SECRET);

    res.json({ token, role: user.role, fullname: user.full_name });
  } catch (e) {
    if (e.code === '23505') {
      res.json({ error: 'Пользователь уже существует' });
    } else {
      res.status(500).json({ error: 'Ошибка сервера' });
    }
  }
});

// Вход
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];

  if (!user) return res.json({ error: 'Нет такого пользователя' });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.json({ error: 'Неверный пароль' });

  const token = jwt.sign({ id: user.id, role: user.role }, SECRET);
  res.json({ token, role: user.role, fullName: user.full_name });
});

// Добавление вопроса
app.post('/questions', authMiddleware, async (req, res) => {
    const { question } = req.body;
    const userId = req.user.id;
    console.log('[POST /questions]', { userId, question });
  
    try {
      await pool.query(
        'INSERT INTO questions (question, user_id) VALUES ($1, $2)',
        [question, userId]
      );
      res.json({ status: 'ok' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Ошибка при добавлении вопроса' });
    }
});

// Добавление ответа
app.post('/answer', authMiddleware, async (req, res) => {
  const { id } = req.user;
  const { questionId, answer } = req.body;

  try {
    await pool.query(
      'UPDATE questions SET answer = $1, answer_user_id = $2 WHERE id = $3',
      [answer, id, questionId]
    );
    res.json({ status: 'ok' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка при сохранении ответа' });
  }
});

app.get('/profile', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  const result = await pool.query('SELECT full_name, role FROM users WHERE id = $1', [userId]);
  res.json(result.rows[0]);
});

// Получение всех вопросов
app.get('/questions', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        q.id,
        q.question,
        q.answer,
        qu.full_name AS question_author,
        au.full_name AS answer_author
      FROM questions q
      LEFT JOIN users qu ON q.user_id = qu.id
      LEFT JOIN users au ON q.answer_user_id = au.id
      ORDER BY q.created_at DESC
    `);
    console.log('[GET /questions]', result.rows);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка при получении вопросов' });
  }
});

const path = require('path');

// Статика из папки public
app.use(express.static(path.join(__dirname, 'public')));

// Путь по умолчанию — index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Запуск
app.listen(3001, '0.0.0.0', () => console.log('Сервер запущен: http://localhost:3001'));
