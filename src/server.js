const bodyParser = require('body-parser');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const User = require('./user');
const cors = require('cors');

const corsOptions = {
  "origin": "http://localhost:3000",
  "credentials": true
};

mongoose.Promise = global.Promise;
mongoose.connect('mongodb://localhost/user', { useMongoClient: true });

const STATUS_USER_ERROR = 422;
const BCRYPT_COST = 11;

const server = express();
// to enable parsing of json bodies for post requests
server.use(bodyParser.json());
server.use(session({
  secret: 'e5SPiqsEtjexkTj3Xqovsjzq8ovjfgVDFMfUzSmJO21dtXs4re',
  resave: false,
  saveUninitialized: true
}));
server.use(cors(corsOptions));

/* Sends the given err, a string or an object, to the client. Sets the status
 * code appropriately. */
const sendUserError = (err, res) => {
  res.status(STATUS_USER_ERROR);
  if (err && err.message) {
    res.json({ message: err.message, stack: err.stack });
  } else {
    res.json({ error: err });
  }
};

//server middlewares =================================================

const hashPasswordMiddle = (req, res, next) => {
  const { password } = req.body;
  if (!password) return sendUserError(new Error('Please provide the password'), res);
  bcrypt.hash(password, BCRYPT_COST)
    .then((hash) => {
      req.passwordHash = hash;
      next();
    })
    .catch((error) => {
      sendUserError(error, res);
    });
};

const loginMiddle = (req, res, next) => {
  if (!req.session.username) return sendUserError(new Error('No user logged in'), res);
  const username = req.session.username;
  User.findOne({ username })
    .then((user) => {
      if (!user) return sendUserError(new Error('User not found'), res);
      req.user = user;
      next();
    })
    .catch((error) => {
      sendUserError(error, res);
    });
};

// restricted global middleware
// const restricted = (req, res, next) => {
//   const path = req.path;
//   const { username } = req.session;
//   if (/restricted/.test(path)) {
//     if (!username) {
//       return sendUserError(new Error('Not authorized'), res);
//     }
//   }
//   next();
// };
server.use('/restricted/*', loginMiddle);

const comparePassword = (req, res, next) => {
  const { username, password } = req.body;
  if (!username || !password) return sendUserError(new Error('Please provide password'), res);
  User.findOne({ username })
    .then((user) => {
      if (!user) return sendUserError(new Error('No user found'), res);
      return bcrypt.compare(password, user.passwordHash);
    })
    .then((result) => {
      if (!result) return sendUserError(new Error('Invalid password'), res);
      req.session.username = username;
      req.username = username;
      next();
    })
    .catch((error) => {
      sendUserError(error, res);
    });
};

//server route handlers start================================

server.post('/users', hashPasswordMiddle, (req, res) => {
  const { username } = req.body;
  if (!username) return sendUserError(new Error('Please provide username'), res);
  const { passwordHash } = req;
  const newUser = new User({ username, passwordHash });
  newUser.save()
    .then((user) => {
      if (!user) sendUserError(new Error('User created failed'), res);
      res.status(200).json(user);
    })
    .catch((error) => {
      sendUserError(error, res);
    });
});

server.post('/login', comparePassword, (req, res) => {
  if(!req.session.username) return sendUserError(new Error('Not authorized'), res);
  res.status(200).json({ success: true });
});

server.post('/logout', (req, res) => {
  req.session.username = null;
  res.status(200).json({ message: 'User logged out' });
});

// TODO: add local middleware to this route to ensure the user is logged in
server.get('/me', loginMiddle, (req, res) => {
  // Do NOT modify this route handler in any way.
  res.json(req.user);
});

server.get('/restricted/users', (req, res) => {
  User.find({})
    .then((users) => {
      if (!users || users.length === 0) return sendUserError(new Error('No user found'), res);
      res.status(200).json(users);
    })
    .catch((error) => {
      sendUserError(error, res);
    })
});

module.exports = { server };
