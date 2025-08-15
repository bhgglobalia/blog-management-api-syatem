import express from 'express';
import path from 'path';
import cookieParser from 'cookie-parser';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { connectDB } from './config/db.js';
import authRoutes from './routes/authRoutes.js';
import postRoutes from './routes/postRoutes.js';
import commentRoutes from './routes/commentRoutes.js';
import { errorHandler } from './middlewares/errorHandler.js';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => res.render('home'));
app.get('/register', (req, res) => res.render('registretion'));
app.get('/login', (req, res) => res.render('login'));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/posts', postRoutes);
app.use('/api', commentRoutes);

// Error Handler
app.use(errorHandler);

await connectDB();
app.listen(3000, () => console.log('Server running at http://localhost:3000'));
