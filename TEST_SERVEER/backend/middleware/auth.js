const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'secret_key_for_student_project';

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  // Token usually comes as "Bearer <token>"
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified; // verified contains the payload ({ id: user.id })
    next();
  } catch (error) {
    res.status(403).json({ message: 'Invalid token.' });
  }
};

module.exports = { authenticateToken, JWT_SECRET };
