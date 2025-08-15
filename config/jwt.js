import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

export const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

export function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
}

export function verifyToken(token, callback) {
  return jwt.verify(token, JWT_SECRET, callback);
}
