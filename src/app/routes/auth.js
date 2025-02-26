// src/app/routes/auth.js

const express = require('express');
const authMiddleware = require('../middleware/auth'); // Updated path
const { register, login, logout, me } = require('../controllers/authController');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/logout', logout);
router.get('/me', authMiddleware, me);

module.exports = router;