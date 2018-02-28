const jwt = require('jsonwebtoken')

const getDecode = (token) => {
  return new Promise((resolve, reject) => {
    jwt.verify(token, process.env.SECURITY, (err, decoded) => {
      if (!err) {
        resolve(decoded)
      } else {
        reject(err)
      }
    })
  })
}

module.exports = getDecode
