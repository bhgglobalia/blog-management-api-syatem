import express from 'express';
import bcrypt from 'bcrypt';
import { getDB } from '../config/db.js';
import { isValidEmail, isStrongPassword } from '../utils/validators.js';
import { getFormattedDate } from '../utils/date.js';
import { signToken } from '../config/jwt.js';

const router = express.Router();

router.post('/register', async (req, res, next) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name?.trim() || !email?.trim() || !password || !role) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email' });
    if (!isStrongPassword(password)) return res.status(400).json({ error: 'Weak password' });
    if (!['user', 'admin'].includes(role)) return res.status(400).json({ error: 'Invalid role' });

    const db = getDB();
    const collection = role === 'admin' ? 'admin' : 'user';
    if (await db.collection(collection).findOne({ email: email.toLowerCase() })) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    await db.collection(collection).insertOne({
      name: name.trim(),
      email: email.toLowerCase(),
      password: hashedPassword,
      role,
      createdAt: getFormattedDate()
    });

    res.json({ message: 'Registration successful', role });
  } catch (err) {
    next(err);
  }
});

router.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email?.trim() || !password) return res.status(400).json({ error: 'Email & password required' });

    const db = getDB();
    let user = await db.collection('user').findOne({ email: email.toLowerCase() });
    let roleType = 'user';
    if (!user) {
      user = await db.collection('admin').findOne({ email: email.toLowerCase() });
      roleType = 'admin';
    }
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid credentials' });

    const token = signToken({ id: user._id, role: user.role, email: user.email });
    await db.collection(`${roleType}-login`).insertOne({ email: user.email, loginTime: getFormattedDate() });

    res.cookie('token', token, { httpOnly: true, secure: false, maxAge: 3600000 });
    res.json({ message: 'Login successful', role: user.role, token });
  } catch (err) {
    next(err);
  }
});

router.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully' });
});

export default router;
