const { JWT_SECRET } = require("../secrets"); // use this secret!

module.exports = user => {
    const payload = {
        subject: user.user_id,
        user_name: user.user_name,
        role_name: user.role_name
    }

    const options = {
        expiresIn: '1d'
    }

    const token = {
        payload,
        JWT_SECRET,
        options
    }
    return token
}
