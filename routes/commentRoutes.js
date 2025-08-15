import express from 'express';
import bcrypt from 'bcrypt';
import { ObjectId } from 'mongodb';
import { getDB } from '../config/db.js';
import { validateObjectId } from '../utils/validators.js';
import { getFormattedDate } from '../utils/date.js';

const router = express.Router();

// GET comments for a post
router.get('/posts/:id/comments', async (req, res, next) => {
  try {
    if (!validateObjectId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid post ID' });
    }

    const comments = await getDB()
      .collection('comments')
      .find(
        { postId: req.params.id },
        { projection: { _id: 1, postId: 1, authorName: 1, content: 1, createdAt: 1 } }
      )
      .sort({ createdAt: -1 })
      .toArray();

    res.json(comments);
  } catch (err) {
    next(err);
  }
});

// ADD comment to a post
router.post('/posts/:id/comments', async (req, res, next) => {
  try {
    if (!validateObjectId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid post ID' });
    }

    const { authorName, content, deletePassword } = req.body;
    if (!authorName?.trim()) return res.status(400).json({ error: 'Name is required' });
    if (!content?.trim()) return res.status(400).json({ error: 'Comment cannot be empty' });
    if (!deletePassword || deletePassword.length < 4) {
      return res.status(400).json({ error: 'Delete password must be at least 4 characters' });
    }

    const db = getDB();
    const postExists = await db.collection('posts').findOne({ _id: new ObjectId(req.params.id) });
    if (!postExists) return res.status(404).json({ error: 'Post not found' });

    const hashedPassword = await bcrypt.hash(deletePassword, 10);

    const newComment = {
      postId: req.params.id,
      authorName: authorName.trim(),
      content: content.trim(),
      passwordHash: hashedPassword,
      createdAt: getFormattedDate()
    };

    const result = await db.collection('comments').insertOne(newComment);
    res.status(201).json({ message: 'Comment added successfully', commentId: result.insertedId });
  } catch (err) {
    next(err);
  }
});

// DELETE comment
router.delete('/comments/:commentId', async (req, res, next) => {
  try {
    if (!validateObjectId(req.params.commentId)) {
      return res.status(400).json({ error: 'Invalid comment ID' });
    }

    const adminKey = process.env.ADMIN_KEY || null;
    const isAdmin = adminKey && req.headers['x-admin-key'] === adminKey;
    const { deletePassword } = req.body || {};

    const db = getDB();
    const comment = await db.collection('comments').findOne({ _id: new ObjectId(req.params.commentId) });

    if (!comment) return res.status(404).json({ error: 'Comment not found' });

    if (!isAdmin) {
      if (!deletePassword) return res.status(400).json({ error: 'Delete password is required' });
      const match = await bcrypt.compare(deletePassword, comment.passwordHash);
      if (!match) return res.status(403).json({ error: 'Invalid delete password' });
    }

    await db.collection('comments').deleteOne({ _id: new ObjectId(req.params.commentId) });
    res.json({ message: 'Comment deleted successfully' });
  } catch (err) {
    next(err);
  }
});

export default router;
