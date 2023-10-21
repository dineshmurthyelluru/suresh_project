const jwt = require('jsonwebtoken');
const secretKey = 'x2&67A$9Lp@ZbWdQ3T*fFvU7m!JcVnXq';

const generateToken = (user) => {
  return jwt.sign({user_name: user.user_name }, secretKey, { expiresIn: '1h' });
};

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(403).json({ message: 'No token provided' });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    req.user = decoded;
    next();
  });
};

module.exports = {
  generateToken,
  verifyToken,
};
