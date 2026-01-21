const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const User = require('../models/usersModel');

// Local Strategy
passport.use(
  new LocalStrategy(
    { usernameField: 'email' },
    async (email, password, done) => {
      try {
        const user = await User.findOne({
          email: email.toLowerCase(),
          isActive: true,
        }).select('+password');

        // ❌ ไม่พบ user
        if (!user) {
          return done(null, false, {
            message: 'ไม่พบบัญชีผู้ใช้นี้',
          });
        }

        // ❌ ไม่มี password → สมัครด้วย Google ล้วน
        if (!user.password) {
          return done(null, false, {
            message: 'บัญชีนี้เข้าสู่ระบบด้วย Google กรุณาใช้ Google Login',
          });
        }

        // ❌ ยังไม่ยืนยันอีเมล
        if (!user.isEmailVerified) {
          return done(null, false, {
            message: 'กรุณายืนยันอีเมลก่อนเข้าสู่ระบบ',
          });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return done(null, false, {
            message: 'รหัสผ่านไม่ถูกต้อง',
          });
        }

        // ✅ ผ่านทั้งหมด
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);



// Google Strategy
// ใน passport.js หรือ googleStrategy.js
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: '/api/auth/google/callback'
    },
    async (accessToken, refreshToken, profile, done) => {
      
      try {
        const email = profile.emails?.[0]?.value;

        if (!email) {
          return done(new Error("Google account has no email"), null);
        }

        // 🔹 1. หา user จาก email (สำคัญที่สุด)
        let user = await User.findOne({ email });

        if (user) {
          console.log("🔗 LINK EXISTING USER WITH GOOGLE");

          // ถ้ายังไม่เคยผูก google
          if (!user.googleId) {
            user.googleId = profile.id;
            user.authProvider = "google";
            await user.save();
          }

          return done(null, user);
        }

        
        if (!user) {
          console.log("🆕 CREATE GOOGLE USER");
          // 🔴 สร้าง user ใหม่
          user = await User.create({
            googleId: profile.id,
            email: profile.emails[0].value,
            user_fullname: profile.displayName,
            authProvider: 'google',
            role: 'Customer',
            isEmailVerified: true,      
            profileCompleted: false,    
            user_img: profile.photos?.[0]?.value || null,
            isActive: true
          });
          
          console.log('✅ Created new Google user:', user.email);
        }

        return done(null, user);
      } catch (error) {
        console.error('Google Strategy Error:', error);
        return done(error, null);
      }
    }
  )
);





module.exports = passport;