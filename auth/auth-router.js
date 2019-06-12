const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken')

const Users = require('../users/users-model.js');

function generateToken(user) {
  const payload = {
    userId: user.id,
    userRole: 'student',
  };
  const secret = 'mitochondria are the powerhouses of the cell';

  const options = {
    expiresIn:'1h'
  };

  return jwt.sign(payload, secret, options)
}

// for endpoints beginning with /api/auth
router.post('/register', (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10); // 2 ^ n
  user.password = hash;

  Users.add(user)
    .then(saved => {
      const token = generateToken(saved)
      
      res.status(201).json({
        message: `Welcome ${saved.username}!`,
        authToken: token
      });
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

router.post('/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = generateToken(user)
        
        res.status(200).json({
          message: `Welcome ${user.username}!`,
          authToken: token
        })
      } else {
        res.status(401).json({ message: 'Invalid creds.' })
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

module.exports = router;
