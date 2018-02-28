var mongoose = require('mongoose');
var Schema = mongoose.Schema;

const userSchema = new Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: [true, 'email is required'],
    unique: true,
    validate: {
      validator: function(value) {
        return /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/igm.test(value)
      },
      message: 'not a valid email'
    }
  },
  password: {
    type: String,
    required:true
  },
  role: {
    type: String,
    required: true
  }
})

const User = mongoose.model('User', userSchema)

module.exports = User;
