const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const auth = require('../middleware/auth');
const { check, validationResult } = require('express-validator');

// @route      GET api/auth
// @desc       Get logged in user
// @access     Private
router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.send(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// @route      POST api/auth
// @desc       Auth User and get token
// @access     Public
router.post(
  '/',
  [
    check('email', 'Please enter a valid email').isEmail(),
    check('password', 'PPassword is required').exists()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { email, password } = req.body;
    let user = await User.findOne({ email: email });
    if (!user) {
      return res.status(400).json({ msg: 'User doesnt exist' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      res.status(400).json({ msg: 'Password doesnt match' });
    }
    const payload = {
      user: {
        id: user.id,
        name: user.name
      }
    };
    jwt.sign(payload, config.get('jwtsecret'), { expiresIn: '3h' }, function(
      err,
      token
    ) {
      if (err) throw err;
      res.status(200).send({ token });
    });
  }
);

module.exports = router;
