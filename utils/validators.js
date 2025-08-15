import { ObjectId } from 'mongodb';

export function validateObjectId(id) {
  return ObjectId.isValid(id);
}

export function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export function isStrongPassword(password) {
  return password.length >= 6;
}
