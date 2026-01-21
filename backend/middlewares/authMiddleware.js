// middleware/auth.js
const jwt = require('jsonwebtoken');
const User = require('../models/usersModel');

exports.protect = async (req, res, next) => {
  let token;
  
  // ดึง token จาก header หรือ cookie
  if (
    req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } 
  
  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'กรุณาเข้าสู่ระบบ'
    });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id);
    
    if (!req.user || !req.user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'ไม่พบผู้ใช้หรือบัญชีถูกระงับ'
      });
    }
    
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Token ไม่ถูกต้อง'
    });
  }
};