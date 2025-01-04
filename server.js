const express = require('express');
const mysql = require('mysql2');
const nodemailer = require('nodemailer');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const app = express();

// Using middleware for data processing
app.use(cors());
app.use(bodyParser.json());

// MySQL database connection information
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

// Email sending settings
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure:true,
  auth: {
    user: 'rswlq2503@gmail.com',
    pass: 'uyjw rpvn sqni yssg'
  }
});

// Generate a random code for email verification
const generateVerificationCode = () => {
  return Math.floor(10000 + Math.random() * 90000).toString();
};

// Secret key for JWT
const secretKey = 'your-secret-key';

// API to send verification code
app.post('/api/send-verification-code', (req, res) => {
  const { email } = req.body;
  const verificationCode = generateVerificationCode();

  // Save the verification code in the database
  const updateQuery = 'UPDATE users SET verification_code = ? WHERE email = ?';
  db.query(updateQuery, [verificationCode, email], (err, results) => {
    if (err) {
      console.error('Error updating verification code:', err);
      return res.status(500).json({ success: false });
    }

    // Send email with the verification code
    const mailOptions = {
      from: '"shopping" <rswlq2503@gmail.com>',
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

// API for user registration
app.post('/api/register', (req, res) => {
  const { email, verificationCode, enteredCode } = req.body;

  if (verificationCode !== enteredCode) {
    return res.status(400).json({ success: false, message: 'Verification code is incorrect' });
  }

  // Hash the enteredCode using SHA512
  const hashedCode = crypto.createHash('sha512').update(enteredCode).digest('hex');

  // Save email and hashed code in the database
  const query = 'INSERT INTO users (email, password, password_changed ,is_online) VALUES (?, ?, false ,true)';
  db.query(query, [email, hashedCode], (err, results) => {
    if (err) {
      console.error('Error inserting user:', err);
      return res.status(500).json({ success: false });
    }

    // Send email after successful registration
    const mailOptions = {
      from: '"shopping" <rswlq2503@gmail.com>',
      to: email,
      subject: 'Successful Registration',
      text: 'You have successfully registered. Welcome!'
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending email:', error);
      } else {
        console.log('Email sent: ' + info.response);
      }
    });

    res.status(200).json({ success: true, message: 'Registration was successful' });
  });
});

// API for changing password
app.post('/api/change-password', (req, res) => {
  const { email, oldPassword, newPassword } = req.body;

  // Hash the old password
  const hashedOldPassword = crypto.createHash('sha512').update(oldPassword).digest('hex');

  // Check the correctness of the old password
  const checkPasswordQuery = 'SELECT * FROM users WHERE email = ? AND password = ?';
  db.query(checkPasswordQuery, [email, hashedOldPassword], (err, results) => {
    if (err) {
      return res.status(500).json({ success: false, message: 'Error checking password' });
    }

    if (results.length === 0) {
      return res.status(400).json({ success: false, message: 'Old password is incorrect' });
    }

    // Hash the new password
    const hashedNewPassword = crypto.createHash('sha512').update(newPassword).digest('hex');

    // Update the password and password_changed status
    const updatePasswordQuery = 'UPDATE users SET password = ?, password_changed = true WHERE email = ?';
    db.query(updatePasswordQuery, [hashedNewPassword, email], (err, updateResult) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Error changing password' });
      }

      // Send email after changing the password
      const mailOptions = {
          from: '"shopping" <rswlq2503@gmail.com>',
        to: email,
        subject: 'Password Changed',
        text: `Your password has been successfully changed. Your new password is: ${newPassword}`
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Error sending email:', error);
        } else {
          console.log('Email sent: ' + info.response);
        }
      });

      res.status(200).json({ success: true, message: 'Password changed successfully' });
    });
  });
});

app.post('/api/login', (req, res) => {
  const { email, password, deviceInfo } = req.body;

  // Hash the entered password
  const hashedPassword = crypto.createHash('sha512').update(password).digest('hex');

  // Check the correctness of the password
  const query = 'SELECT * FROM users WHERE email = ? AND password = ?';
  db.query(query, [email, hashedPassword], (err, results) => {
    if (err) {
      console.error('Error querying users:', err);
      return res.status(500).json({ success: false });
    }
    if (results.length > 0) {
      const user = results[0]; // First result of the query
      const userId = user.id; // Extract user ID

      // Change user status to online
      const updateQuery = 'UPDATE users SET is_online = true, deviceinfo = ? WHERE email = ?';
      db.query(updateQuery, [JSON.stringify(deviceInfo), email], (err, updateResult) => {
        if (err) {
          console.error('Error updating user online status and device info:', err);
          return res.status(500).json({ success: false });
        }

        // Create JWT token
        const token = jwt.sign({ email, userId }, secretKey, { expiresIn: '1h' }); // Add userId to the token
        res.status(200).json({
          success: true,
          message: 'Login successful',
          token,
          userId, // Add userId to the response
        });
      });
    } else {
      res.status(400).json({ success: false, message: 'Email or password is incorrect' });
    }
  });
});

// API to save an order
app.post('/api/save-order', (req, res) => {
  const { userId, orderCode, totalPrice, shippingAddress, postalCode, paymentMethod, shippingMethod, products } = req.body;

  // Check the correctness of the received data
  if (!userId || !orderCode || !totalPrice || !shippingAddress || !postalCode || !paymentMethod || !shippingMethod || !products) {
    return res.status(400).json({ success: false, message: 'Please fill all required fields.' });
  }

  // Convert products array to JSON
  const productsJSON = JSON.stringify(products);

  // Save order information in the database
  const query = 'INSERT INTO `orders` (user_id, order_code, total_price, shipping_address, postal_code, payment_method, shipping_method, products) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
  db.query(query, [userId, orderCode, totalPrice, shippingAddress, postalCode, paymentMethod, shippingMethod, productsJSON], (err, results) => {
    if (err) {
      console.error('Error saving order:', err);
      return res.status(500).json({ success: false, message: 'Error saving order' });
    }

    res.status(200).json({ success: true, message: 'Order saved successfully', orderId: results.insertId });
  });
});

// API for user logout
app.post('/api/logout', (req, res) => {
  const { email } = req.body;

  const updateQuery = 'UPDATE users SET is_online = false WHERE email = ?';
  db.query(updateQuery, [email], (err, updateResult) => {
    if (err) {
      console.error('Error updating user online status:', err);
      return res.status(500).json({ success: false });
    }
    res.status(200).json({ success: true, message: 'Logout successful' });
  });
});

// API to check email
app.post('/api/check-email', (req, res) => {
  const { email } = req.body;

  // Check email in the database
  const checkEmailQuery = 'SELECT * FROM users WHERE email = ?';
  db.query(checkEmailQuery, [email], (err, results) => {
    if (err) {
      console.error('Error checking email:', err);
      return res.status(500).json({ success: false, message: 'Error checking email' });
    }

    if (results.length > 0) {
      // If email exists
      return res.status(400).json({ success: false, message: 'This email is already registered' });
    }

    // If email does not exist
    res.status(200).json({ success: true });
  });
});

// API to get product information
app.get('/product', (req, res) => {
  const query = 'SELECT * FROM product';
  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

// API to view online users
app.get('/api/online-users', (req, res) => {
  const query = 'SELECT email FROM users WHERE is_online = true';
  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

// API to get user information
app.get('/UserLogindata', (req, res) => {
  const query = 'SELECT * FROM users';
  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

// API to verify verification code and reset password
app.post('/api/verify-and-reset-password', (req, res) => {
  const { email, verificationCode, newPassword } = req.body;

  // Check the correctness of the verification code
  const checkCodeQuery = 'SELECT * FROM users WHERE email = ? AND verification_code = ?';
  db.query(checkCodeQuery, [email, verificationCode], (err, results) => {
    if (err) {
      console.error('Error verifying code:', err);
      return res.status(500).json({ success: false, message: 'An error occurred while verifying the code.' });
    }

    if (results.length === 0) {
      return res.status(400).json({ success: false, message: 'Invalid verification code.' });
    }

    // Check new password conditions
    if (!newPassword || newPassword.length < 9 || !/[A-Z]/.test(newPassword) || !/[a-z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
      return res.status(400).json({ success: false, message: 'Password must be at least 9 characters long and include one uppercase letter, one lowercase letter, and one number.' });
    }

    // Hash the new password
    const hashedNewPassword = crypto.createHash('sha512').update(newPassword).digest('hex');

    // Update the password and clear the verification code
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

// Start the server
app.listen(5000, () => {
  console.log('Server is running on port 5000');
});