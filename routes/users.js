var express = require('express');
var router = express.Router();
var userController = require('../controllers/userController')
/* GET users listing. */
router.get('/', userController.getUsers)
router.get('/:id', userController.getUser)
router.put('/:id', userController.editUser)
router.delete('/:id', userController.deleteUser)

module.exports = router;
