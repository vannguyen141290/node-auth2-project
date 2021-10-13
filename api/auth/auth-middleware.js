const e = require('express');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets"); // use this secret!

const restricted = (req, res, next) => {
  
  const token = req.headers.authorization

  if (!token) {
    return next({
      status: 401,
      message: 'Token required'
    })
  }

  jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
    if (err) {
      return next({
        status: 401,
        message: 'Token invalid'
      })
    }
    req.decodedToken = decodedToken
    next()
  })
}

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
  if (req.decodedToken.role_name === role_name){
    next()
  } else {
    next({
      status: 403,
      message: 'This is not for you'
    })
  }
}


const checkUsernameExists = (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
  next()
}


const validateRoleName = (req, res, next) => {
  const { role_name } = req.body
  if (!role_name || !role_name.trim()) {
    req.body.role_name = 'student'
    return next()
  }
  req.body.role_name = req.body.role_name.trim()
  if (req.body.role_name === 'admin') {
    return next({
      status: 422,
      message: 'Role name can not be admin'
    })
  }
  if (req.body.role_name.length > 32) {
    return next({
      status: 422,
      message: 'Role name can not be longer than 32 chars'
    })
  }
  next()
}


module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
