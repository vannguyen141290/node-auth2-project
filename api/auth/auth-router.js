const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');

const Users = require('../users/users-model')
const bcrypt = require('bcryptjs')
const tokenBuilder = require('./token-builder')

router.post("/register", validateRoleName, (req, res, next) => {

  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  const rounds = process.env.BCRYPT_ROUNDS || 4
  let user = req.body

  const hash = bcrypt.hashSync(user.password, rounds)

  user.password = hash

  Users.add(user)
    .then(newUser => {
      res.status(201).json(newUser)
    })
    .catch(next)

});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  const { username, password } = req.body
  if (password === undefined) {
    next({ status: 401, message: 'invalid credentials' })
  } else {
    Users.findBy({ username })
      .then(([user]) => {
        if (bcrypt.compareSync(password, user.password)) {
          const token = tokenBuilder(user)
          res.status(200).json({
            message: `${user.username} is back!`,
            token
          })
        } else {
          next({ status: 401, message: 'Invalid credentials' })
        }
      })
      .catch(next)

  }

});

module.exports = router;
