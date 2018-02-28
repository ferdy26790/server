const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const saltRounds = 10
const userModel = require('../models/User')
const getDecode = require('../helpers/getDecode')
class User{
  static getSelf (req, res) {
    getDecode(req.headers.token)
      .then((decode) => {
        userModel.findById(decode.id)
          .then((user) => {
            res.status(200).json({
              user: user
            })
          }).catch((err) => {
            res.status(500).send(err)
          })
      }).catch((err) => {
        res.status(500)
      })
  }

  static createAdmin (req, res) {
    if (!req.body.password) {
      res.status(402).json({
        msg: 'password required'
      })
    } else {
      bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
        if (!err) {
          let newUser = new userModel({
            name: req.body.name,
            email: req.body.email,
            password: hash,
            role: 'admin'
          })
          newUser.save()
            .then((userCreated) => {
              res.status(200).json({
                msg: "admin created",
                userAdmin: userCreated
              })
            }).catch((err) => {
              res.send(err)
            })
        } else {
          res.status(500).send(err)
        }
      })
    }
  }

  static register (req, res) {
    if (!req.body.password) {
      res.status(402).json({
        msg: 'password required'
      })
    } else {
      bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
        if (!err) {
          let newUser = new userModel({
            name: req.body.name,
            email: req.body.email,
            password: hash,
            role: 'user'
          })
          newUser.save()
            .then((userCreated) => {
              res.status(200).json({
                msg: "user created",
                user: userCreated
              })
            }).catch((err) => {
              if (!err.errmsg) {
                res.status(422).send(err.errors)
              } else {
                res.status(500).send(err.errmsg)
              }
            })
        } else {
          res.status(500).send(err)
        }
      })
    }
  }

  static login (req, res) {
    userModel.find({email:req.body.email})
      .then((user) => {
        if (user.length <= 0) {
          res.status(204).send('wrong email')
        } else {
          bcrypt.compare(req.body.password, user[0].password, (err, respond) => {
            if (err) {
              res.status(500).send(err)
            } else {
              if (respond) {
                console.log(respond);
                console.log(user[0]);
                let userLogin = {
                  id: user[0]._id,
                  name: user[0].name,
                  email: user[0].email,
                  role: user[0].role
                }
                jwt.sign(userLogin, process.env.SECURITY, (err, token) => {
                  if (!err) {
                    res.status(200).json({
                      msg: "login success",
                      token: token,
                      user: userLogin
                    })
                  } else {
                    console.log(respond);
                  }
                })
              } else {
                res.status(400).send('wrong password')
              }
            }
          })
        }
      }).catch((err) => {
        res.status(500).send(err)
      })
  }

  static getUsers (req, res) {
    getDecode(req.headers.token)
      .then((decode) => {
        if (decode.role == 'admin') {
          userModel.find()
            .then((users) => {
              res.status(200).json({
                users: users
              })
            }).catch((err) => {
              res.status(500).send(err)
            })
        } else {
          res.status(401).send('forbidden')
        }
      }).catch((err) => {
        res.status(500).send(err)
      })
  }

  static getUser (req, res) {
    getDecode(req.headers.token)
      .then((decode) => {
        if(decode.id == req.params.id || decode.role == 'admin') {
          userModel.findById(req.params.id)
          .then((user) => {
            let thisUser = {
              id: user.id,
              name: user.name,
              email: user.email
            }
            res.status(200).json({
              user: thisUser
            })
          }).catch((err) => {
            res.status(500).send(err)
          })
        } else {
          res.status(401).send('forbidden')
        }
      }).catch((err) => {
        res.status(500).send(err)
      })
  }

  static editUser (req, res) {
    getDecode(req.headers.token)
      .then((decoded) => {
        userModel.findById(req.params.id)
        .then((user) => {
          if (decoded.id == user._id || decoded.role == 'admin') {
            console.log('masuk');
            user.name = req.body.name || user.name
            user.email = req.body.email || user.email
            user.save()
              .then((userUpdated) => {
                res.status(200).json({
                  msg: "user updated",
                  user: userUpdated
                })
              }).catch((err) => {
                res.status(500).send(err)
              })
          } else {
            res.status(401).send('unauthorized')
          }
        }).catch((err) => {
          res.status(500).send(err)
        })
      }).catch((err) => {
        res.status(401).json({
          msg: "unauthorized"
        })
      })
  }

  static deleteUser (req, res) {
    getDecode(req.headers.token)
      .then((decoded) => {
        if (decoded.role == 'admin') {
          userModel.findByIdAndRemove(req.params.id)
            .then((userDeleted) => {
              res.status(200).json({
                msg: "user deleted",
                user: userDeleted
              })
            }).catch((err) => {
              res.status(500).send(err)
            })
        } else {
          res.status(401).send('unauthorized')
        }
      }).catch((err) => {
        res.status(500).send(err)
      })
  }
}

module.exports = User;
