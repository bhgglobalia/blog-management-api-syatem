import { MongoClient } from 'mongodb';
import dotenv from 'dotenv';
dotenv.config();

const client = new MongoClient(process.env.MONGO_URI || 'mongodb://localhost:27017');
let db;

export async function connectDB() {
  await client.connect();
  db = client.db(process.env.DB_NAME || 'blog');
  console.log(`Connected to database: ${process.env.DB_NAME || 'blog'}`);
}

export function getDB() {
  if (!db) throw new Error('Database not connected');
  return db;
}
