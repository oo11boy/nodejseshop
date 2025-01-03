const express = require('express');
const mysql = require('mysql2');
const nodemailer = require('nodemailer');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const app = express();

// استفاده از middleware برای پردازش داده‌ها
app.use(cors());
app.use(bodyParser.json());

// اطلاعات اتصال به دیتابیس MySQL
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'shoping'
});

db.connect(err => {
  if (err) {
    console.error('Error connecting to the database:', err);
    return;
  }
  console.log('Connected to MySQL database');
});

// تنظیمات ارسال ایمیل
const transporter = nodemailer.createTransport({
  host: 'mail.abzarkhone.com',
  port: 587,
  secure: false,
  auth: {
    user: 'mailing@abzarkhone.com',
    pass: 'Ra13781379'
  }
});

// ایجاد یک کد رندم برای تأیید ایمیل
const generateVerificationCode = () => {
  return Math.floor(10000 + Math.random() * 90000).toString();
};

// کلید مخفی برای JWT
const secretKey = 'your-secret-key';

// API برای ارسال کد تأیید
app.post('/api/send-verification-code', (req, res) => {
  const { email } = req.body;
  const verificationCode = generateVerificationCode();

  // ذخیره کد احراز هویت در دیتابیس
  const updateQuery = 'UPDATE users SET verification_code = ? WHERE email = ?';
  db.query(updateQuery, [verificationCode, email], (err, results) => {
    if (err) {
      console.error('Error updating verification code:', err);
      return res.status(500).json({ success: false });
    }

    // ارسال ایمیل با کد تأیید
    const mailOptions = {
      from: 'mailing@abzarkhone.com',
      to: email,
      subject: 'Password Reset Verification Code',
      text: `Your verification code is: ${verificationCode}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending email:', error);
        return res.status(500).json({ success: false });
      } else {
        console.log('Email sent: ' + info.response);
        return res.status(200).json({ success: true, verificationCode });
      }
    });
  });
});

// API برای ثبت‌نام کاربر
app.post('/api/register', (req, res) => {
  const { email, verificationCode, enteredCode } = req.body;

  if (verificationCode !== enteredCode) {
    return res.status(400).json({ success: false, message: 'کد تأیید اشتباه است' });
  }

  // هش کردن enteredCode با استفاده از SHA512
  const hashedCode = crypto.createHash('sha512').update(enteredCode).digest('hex');

  // ذخیره ایمیل و کد هش‌شده در دیتابیس
  const query = 'INSERT INTO users (email, password, password_changed) VALUES (?, ?, false)';
  db.query(query, [email, hashedCode], (err, results) => {
    if (err) {
      console.error('Error inserting user:', err);
      return res.status(500).json({ success: false });
    }

    // ارسال ایمیل پس از ثبت‌نام موفقیت‌آمیز
    const mailOptions = {
      from: 'mailing@abzarkhone.com',
      to: email,
      subject: 'ثبت‌نام موفقیت‌آمیز',
      text: 'ثبت‌نام شما با موفقیت انجام شد. خوش آمدید!'
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending email:', error);
      } else {
        console.log('Email sent: ' + info.response);
      }
    });

    res.status(200).json({ success: true, message: 'ثبت نام موفقیت‌آمیز بود' });
  });
});

// API برای تغییر رمز عبور
app.post('/api/change-password', (req, res) => {
  const { email, oldPassword, newPassword } = req.body;

  // هش کردن رمز عبور قدیمی
  const hashedOldPassword = crypto.createHash('sha512').update(oldPassword).digest('hex');

  // بررسی صحت رمز عبور قدیمی
  const checkPasswordQuery = 'SELECT * FROM users WHERE email = ? AND password = ?';
  db.query(checkPasswordQuery, [email, hashedOldPassword], (err, results) => {
    if (err) {
      return res.status(500).json({ success: false, message: 'خطا در بررسی رمز عبور' });
    }

    if (results.length === 0) {
      return res.status(400).json({ success: false, message: 'رمز عبور قدیمی اشتباه است' });
    }

    // هش کردن رمز عبور جدید
    const hashedNewPassword = crypto.createHash('sha512').update(newPassword).digest('hex');

    // به‌روزرسانی رمز عبور و وضعیت password_changed
    const updatePasswordQuery = 'UPDATE users SET password = ?, password_changed = true WHERE email = ?';
    db.query(updatePasswordQuery, [hashedNewPassword, email], (err, updateResult) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'خطا در تغییر رمز عبور' });
      }

      // ارسال ایمیل پس از تغییر رمز عبور
      const mailOptions = {
        from: 'mailing@abzarkhone.com',
        to: email,
        subject: 'تغییر رمز عبور',
        text: `رمز عبور شما با موفقیت تغییر یافت. رمز عبور جدید شما: ${newPassword}`
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Error sending email:', error);
        } else {
          console.log('Email sent: ' + info.response);
        }
      });

      res.status(200).json({ success: true, message: 'رمز عبور با موفقیت تغییر یافت' });
    });
  });
});

app.post('/api/login', (req, res) => {
  const { email, password, deviceInfo } = req.body;

  // هش کردن رمز وارد شده
  const hashedPassword = crypto.createHash('sha512').update(password).digest('hex');

  // بررسی صحت رمز
  const query = 'SELECT * FROM users WHERE email = ? AND password = ?';
  db.query(query, [email, hashedPassword], (err, results) => {
    if (err) {
      console.error('Error querying users:', err);
      return res.status(500).json({ success: false });
    }
    if (results.length > 0) {
      const user = results[0]; // اولین نتیجه کوئری
      const userId = user.id; // استخراج ID کاربر

      // تغییر وضعیت کاربر به آنلاین
      const updateQuery = 'UPDATE users SET is_online = true, deviceinfo = ? WHERE email = ?';
      db.query(updateQuery, [JSON.stringify(deviceInfo), email], (err, updateResult) => {
        if (err) {
          console.error('Error updating user online status and device info:', err);
          return res.status(500).json({ success: false });
        }

        // ایجاد توکن JWT
        const token = jwt.sign({ email, userId }, secretKey, { expiresIn: '1h' }); // اضافه کردن userId به توکن
        res.status(200).json({
          success: true,
          message: 'ورود موفقیت‌آمیز بود',
          token,
          userId, // اضافه کردن userId به پاسخ
        });
      });
    } else {
      res.status(400).json({ success: false, message: 'ایمیل یا رمز عبور اشتباه است' });
    }
  });
});


// API برای ذخیره سفارش
app.post('/api/save-order', (req, res) => {
  const { userId, orderCode, totalPrice, shippingAddress, postalCode, paymentMethod, shippingMethod } = req.body;

  // بررسی صحت اطلاعات دریافتی
  if (!userId || !orderCode || !totalPrice || !shippingAddress || !postalCode || !paymentMethod || !shippingMethod) {
    return res.status(400).json({ success: false, message: 'لطفا تمام فیلدهای اجباری را پر کنید.' });
  }

  // ذخیره اطلاعات سفارش در دیتابیس
  const query = 'INSERT INTO `order` (user_id, order_code, total_price, shipping_address, postal_code, payment_method, shipping_method) VALUES (?, ?, ?, ?, ?, ?, ?)';
  db.query(query, [userId, orderCode, totalPrice, shippingAddress, postalCode, paymentMethod, shippingMethod], (err, results) => {
    if (err) {
      console.error('Error saving order:', err);
      return res.status(500).json({ success: false, message: 'خطا در ذخیره سفارش' });
    }

    res.status(200).json({ success: true, message: 'سفارش با موفقیت ذخیره شد', orderId: results.insertId });
  });
});

// API برای خروج کاربر
app.post('/api/logout', (req, res) => {
  const { email } = req.body;

  const updateQuery = 'UPDATE users SET is_online = false WHERE email = ?';
  db.query(updateQuery, [email], (err, updateResult) => {
    if (err) {
      console.error('Error updating user online status:', err);
      return res.status(500).json({ success: false });
    }
    res.status(200).json({ success: true, message: 'خروج موفقیت‌آمیز بود' });
  });
});

// API برای بررسی ایمیل
app.post('/api/check-email', (req, res) => {
  const { email } = req.body;

  // بررسی ایمیل در دیتابیس
  const checkEmailQuery = 'SELECT * FROM users WHERE email = ?';
  db.query(checkEmailQuery, [email], (err, results) => {
    if (err) {
      console.error('Error checking email:', err);
      return res.status(500).json({ success: false, message: 'خطا در بررسی ایمیل' });
    }

    if (results.length > 0) {
      // اگر ایمیل موجود بود
      return res.status(400).json({ success: false, message: 'این ایمیل قبلاً ثبت شده است' });
    }

    // اگر ایمیل موجود نبود
    res.status(200).json({ success: true });
  });
});

// API برای دریافت اطلاعات محصولات
app.get('/product', (req, res) => {
  const query = 'SELECT * FROM product';
  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

// API برای مشاهده کاربران آنلاین
app.get('/api/online-users', (req, res) => {
  const query = 'SELECT email FROM users WHERE is_online = true';
  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

// API برای دریافت اطلاعات کاربران
app.get('/UserLogindata', (req, res) => {
  const query = 'SELECT * FROM users';
  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

// API برای بررسی کد احراز هویت و تغییر رمز عبور
app.post('/api/verify-and-reset-password', (req, res) => {
  const { email, verificationCode, newPassword } = req.body;

  // بررسی صحت کد احراز هویت
  const checkCodeQuery = 'SELECT * FROM users WHERE email = ? AND verification_code = ?';
  db.query(checkCodeQuery, [email, verificationCode], (err, results) => {
    if (err) {
      console.error('Error verifying code:', err);
      return res.status(500).json({ success: false, message: 'An error occurred while verifying the code.' });
    }

    if (results.length === 0) {
      return res.status(400).json({ success: false, message: 'Invalid verification code.' });
    }

    // بررسی شرایط رمز عبور جدید
    if (!newPassword || newPassword.length < 9 || !/[A-Z]/.test(newPassword) || !/[a-z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
      return res.status(400).json({ success: false, message: 'Password must be at least 9 characters long and include one uppercase letter, one lowercase letter, and one number.' });
    }

    // هش کردن رمز عبور جدید
    const hashedNewPassword = crypto.createHash('sha512').update(newPassword).digest('hex');

    // به‌روزرسانی رمز عبور و پاک کردن کد احراز هویت
    const updatePasswordQuery = 'UPDATE users SET password = ?, verification_code = NULL WHERE email = ?';
    db.query(updatePasswordQuery, [hashedNewPassword, email], (err, updateResult) => {
      if (err) {
        console.error('Error resetting password:', err);
        return res.status(500).json({ success: false, message: 'An error occurred while resetting the password.' });
      }

      res.status(200).json({ success: true, message: 'Password reset successfully.' });
    });
  });
});

// شروع سرور
app.listen(5000, () => {
  console.log('Server is running on port 5000');
});