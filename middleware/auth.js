const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = function(req, res, next) {
  // Get Token from header
  const token = req.header('x-auth-token');

  // Check if not token
  if (!token) {
    res.status(401).json({ msg: 'No Token, Authorisation denied' });
  }

  try {
    const decoded = jwt.verify(token, config.get('jwtsecret'));

    req.user = decoded.user;
    next();
  } catch (err) {
    console.error(err.message);

    res.status(401).send({ msg: 'Token is not valid' });
  }
};
