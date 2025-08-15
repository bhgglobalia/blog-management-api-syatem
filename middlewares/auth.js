import { verifyToken } from '../config/jwt.js';

export function authenticateToken(req, res, next) {
  const token = req.cookies.token || (req.headers['authorization']?.split(' ')[1]);
  if (!token) return res.status(401).json({ error: 'Access token required' });

  verifyToken(token, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

export function authorizeRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    next();
  };
}
