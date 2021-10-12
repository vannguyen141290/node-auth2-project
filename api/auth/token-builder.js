const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken')

module.exports = user => {
    const payload = {
        subject: user.user_id,
        username: user.username,
        role_name: user.role_name
    }

    const options = {
        expiresIn: '1d'
    }

    const token = jwt.sign(
        payload,
        JWT_SECRET,
        options
    )
    return token
}
