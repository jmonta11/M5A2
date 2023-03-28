const express = require('express');
const router = express.Router();
const authController = require('../controllers/authenticationController');

router.get('/signup', authController.register);
router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.post('/logout', authController.logout);

module.exports = router;