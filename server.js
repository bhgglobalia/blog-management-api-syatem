// server.js
import express from 'express';
import { MongoClient, ObjectId } from 'mongodb';
import path from 'path';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dbName = 'blog';
const client = new MongoClient('mongodb://localhost:27017');
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

let db;
await client.connect();
db = client.db(dbName);

function authenticateToken(req, res, next) {
  const token = req.cookies.token || (req.headers['authorization']?.split(' ')[1]);
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

function authorizeRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    next();
  };
}

const asyncHandler = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

function getFormattedDate() {
  const now = new Date();
  return now.toLocaleString('en-IN', {
    timeZone: 'Asia/Kolkata',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

function validateObjectId(id) {
  return ObjectId.isValid(id);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isStrongPassword(password) {
  return password.length >= 6;
}

app.get('/', (req, res) => res.render('home'));
app.get('/register', (req, res) => res.render('registretion'));
app.get('/login', (req, res) => res.render('login'));


app.post('/api/auth/register', asyncHandler(async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name?.trim() || !email?.trim() || !password || !role) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  if (!isStrongPassword(password)) {
    return res.status(400).json({ error: 'Password must be at least 6 characters long' });
  }
  if (!['user', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }

  const collectionName = role === 'admin' ? 'admin' : 'user';
  const existing = await db.collection(collectionName).findOne({ email: email.toLowerCase() });
  if (existing) {
    return res.status(400).json({ error: 'Email already registered' });
  }

  const hashedPassword = await bcrypt.hash(password, 12);

  await db.collection(collectionName).insertOne({
    name: name.trim(),
    email: email.toLowerCase(),
    password: hashedPassword,
    role,
    createdAt: getFormattedDate()
  });

  res.json({ message: 'Registration successful', role });
}));


app.post('/api/auth/login', asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  if (!email?.trim() || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  let user = await db.collection('user').findOne({ email: email.toLowerCase() });
  let roleType = 'user';
  if (!user) {
    user = await db.collection('admin').findOne({ email: email.toLowerCase() });
    roleType = 'admin';
  }
  if (!user) return res.status(400).json({ error: 'Invalid email or password' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ error: 'Invalid email or password' });

  const token = jwt.sign(
    { id: user._id, role: user.role, email: user.email, name: user.name },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  const loginCollection = roleType === 'admin' ? 'admin-login' : 'user-login';
  await db.collection(loginCollection).insertOne({
    email: user.email,
    loginTime: getFormattedDate()
  });

  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 60 * 60 * 1000
  });

  res.json({ message: 'Login successful', role: user.role, token });
}));

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully' });
});

app.get('/api/posts', asyncHandler(async (req, res) => {
  const posts = await db.collection('posts')
    .find({}, { projection: { _id: 1, title: 1, content: 1, tags: 1, createdAt: 1, updatedAt: 1 } })
    .sort({ createdAt: -1 })
    .toArray();
  res.json(posts);
}));

app.get('/api/posts/:id', asyncHandler(async (req, res) => {
  if (!validateObjectId(req.params.id)) {
    return res.status(400).json({ error: 'Invalid post ID' });
  }
  const post = await db.collection('posts')
    .findOne({ _id: new ObjectId(req.params.id) },
      { projection: { _id: 1, title: 1, content: 1, tags: 1, createdAt: 1, updatedAt: 1 } }
    );
  if (!post) return res.status(404).json({ error: 'Post not found' });
  res.json(post);
}));

app.post('/api/posts', authenticateToken, asyncHandler(async (req, res) => {
  const { title, content, tags } = req.body;

  if (!title?.trim() || !content?.trim()) {
    return res.status(400).json({ error: 'Title and content are required' });
  }
  if (title.length > 150) {
    return res.status(400).json({ error: 'Title cannot exceed 150 characters' });
  }
  const tagList = (tags || '').split(',').map(t => t.trim()).filter(Boolean);
  if (tagList.some(tag => tag.length > 20)) {
    return res.status(400).json({ error: 'Tags cannot exceed 20 characters each' });
  }

  const newPost = {
    title: title.trim(),
    content: content.trim(),
    tags: tagList,
    author: req.user.email,
    createdAt: getFormattedDate(),
    updatedAt: getFormattedDate()
  };

  const result = await db.collection('posts').insertOne(newPost);
  res.status(201).json({ message: 'Post created successfully', postId: result.insertedId });
}));

app.put('/api/posts/:id', authenticateToken, asyncHandler(async (req, res) => {
  if (!validateObjectId(req.params.id)) {
    return res.status(400).json({ error: 'Invalid post ID' });
  }
  const { title, content, tags } = req.body;
  const post = await db.collection('posts').findOne({ _id: new ObjectId(req.params.id) });
  if (!post) return res.status(404).json({ error: 'Post not found' });
  if (req.user.role !== 'admin' && req.user.email !== post.author) {
    return res.status(403).json({ error: 'You can only edit your own posts' });
  }

  await db.collection('posts').updateOne(
    { _id: new ObjectId(req.params.id) },
    {
      $set: {
        title: title?.trim() || post.title,
        content: content?.trim() || post.content,
        tags: tags ? tags.split(',').map(t => t.trim()) : post.tags,
        updatedAt: getFormattedDate()
      }
    }
  );

  res.json({ message: 'Post updated successfully' });
}));

app.delete('/api/posts/:id', authenticateToken, asyncHandler(async (req, res) => {
  if (!validateObjectId(req.params.id)) {
    return res.status(400).json({ error: 'Invalid post ID' });
  }
  const post = await db.collection('posts').findOne({ _id: new ObjectId(req.params.id) });
  if (!post) return res.status(404).json({ error: 'Post not found' });
  if (req.user.role !== 'admin' && req.user.email !== post.author) {
    return res.status(403).json({ error: 'You can only delete your own posts' });
  }
  await db.collection('posts').deleteOne({ _id: new ObjectId(req.params.id) });
  res.json({ message: 'Post deleted successfully' });
}));


app.get('/api/posts/:id/comments', asyncHandler(async (req, res) => {
  if (!validateObjectId(req.params.id)) {
    return res.status(400).json({ error: 'Invalid post ID' });
  }

  const comments = await db.collection('comments')
    .find(
      { postId: req.params.id },
      { projection: { _id: 1, postId: 1, authorName: 1, content: 1, createdAt: 1 } }
    )
    .sort({ createdAt: -1 })
    .toArray();

  res.json(comments);
}));

app.post('/api/posts/:id/comments', asyncHandler(async (req, res) => {
  if (!validateObjectId(req.params.id)) {
    return res.status(400).json({ error: 'Invalid post ID' });
  }

  const { authorName, content, deletePassword } = req.body;

  if (!authorName?.trim()) {
    return res.status(400).json({ error: 'Name is required' });
  }
  if (!content?.trim()) {
    return res.status(400).json({ error: 'Comment cannot be empty' });
  }
  if (!deletePassword || deletePassword.length < 4) {
    return res.status(400).json({ error: 'Delete password must be at least 4 characters' });
  }

  const postExists = await db.collection('posts').findOne({ _id: new ObjectId(req.params.id) });
  if (!postExists) {
    return res.status(404).json({ error: 'Post not found' });
  }

  const hashedPassword = await bcrypt.hash(deletePassword, 10);

  const newComment = {
    postId: req.params.id,
    authorName: authorName.trim(),
    content: content.trim(),
    passwordHash: hashedPassword,
    createdAt: getFormattedDate()
  };

  const result = await db.collection('comments').insertOne(newComment);
  res.status(201).json({
    message: 'Comment added successfully',
    commentId: result.insertedId
  });
}));

app.delete('/api/comments/:commentId', asyncHandler(async (req, res) => {
  if (!validateObjectId(req.params.commentId)) {
    return res.status(400).json({ error: 'Invalid comment ID' });
  }

  const { deletePassword } = req.body;
  const adminKey = process.env.ADMIN_KEY || null;
  const isAdmin = adminKey && req.headers['x-admin-key'] === adminKey;

  console.log('ADMIN_KEY in env:', process.env.ADMIN_KEY);
  console.log('Header received:', req.headers['x-admin-key']);
  console.log('isAdmin result:', isAdmin);

  const comment = await db.collection('comments').findOne({ _id: new ObjectId(req.params.commentId) });
  if (!comment) {
    return res.status(404).json({ error: 'Comment not found' });
  }



  if (!isAdmin) {
    if (!deletePassword) {
      return res.status(400).json({ error: 'Delete password is required' });
    }
    const match = await bcrypt.compare(deletePassword, comment.passwordHash);
    if (!match) {
      return res.status(403).json({ error: 'Invalid delete password' });
    }
  }

  await db.collection('comments').deleteOne({ _id: new ObjectId(req.params.commentId) });
  res.json({ message: 'Comment deleted successfully' });
}));




// ===== ERROR HANDLER =====
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Server error' });
});

app.listen(3000, () => {
  console.log('Server running at http://localhost:3000');
});
