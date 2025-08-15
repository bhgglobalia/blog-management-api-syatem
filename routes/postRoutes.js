import express from 'express';
import { ObjectId } from 'mongodb';
import { getDB } from '../config/db.js';
import { authenticateToken } from '../middlewares/auth.js';
import { validateObjectId } from '../utils/validators.js';
import { getFormattedDate } from '../utils/date.js';

const router = express.Router();

// GET all posts
router.get('/', async (req, res, next) => {
  try {
    const posts = await getDB()
      .collection('posts')
      .find({}, { projection: { _id: 1, title: 1, content: 1, tags: 1, createdAt: 1, updatedAt: 1 } })
      .sort({ createdAt: -1 })
      .toArray();
    res.json(posts);
  } catch (err) {
    next(err);
  }
});

// GET single post
router.get('/:id', async (req, res, next) => {
  try {
    if (!validateObjectId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid post ID' });
    }
    const post = await getDB()
      .collection('posts')
      .findOne({ _id: new ObjectId(req.params.id) }, { projection: { _id: 1, title: 1, content: 1, tags: 1, createdAt: 1, updatedAt: 1 } });

    if (!post) return res.status(404).json({ error: 'Post not found' });
    res.json(post);
  } catch (err) {
    next(err);
  }
});

// CREATE post
router.post('/', authenticateToken, async (req, res, next) => {
  try {
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

    const result = await getDB().collection('posts').insertOne(newPost);
    res.status(201).json({ message: 'Post created successfully', postId: result.insertedId });
  } catch (err) {
    next(err);
  }
});

// UPDATE post
router.put('/:id', authenticateToken, async (req, res, next) => {
  try {
    if (!validateObjectId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid post ID' });
    }

    const { title, content, tags } = req.body;
    const db = getDB();
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
  } catch (err) {
    next(err);
  }
});

// DELETE post
router.delete('/:id', authenticateToken, async (req, res, next) => {
  try {
    if (!validateObjectId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid post ID' });
    }

    const db = getDB();
    const post = await db.collection('posts').findOne({ _id: new ObjectId(req.params.id) });

    if (!post) return res.status(404).json({ error: 'Post not found' });
    if (req.user.role !== 'admin' && req.user.email !== post.author) {
      return res.status(403).json({ error: 'You can only delete your own posts' });
    }

    await db.collection('posts').deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ message: 'Post deleted successfully' });
  } catch (err) {
    next(err);
  }
});

export default router;
