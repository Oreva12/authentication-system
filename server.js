// server.js
require('dotenv').config();
const path = require('path');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const { check, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const crypto = require('crypto');
const { 
  sendVerificationEmail, 
  sendPasswordResetEmail,
  generateVerificationToken,
  generatePasswordResetToken
} = require('./emailService');

const app = express();

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests, please try again later.'
});
app.use(limiter);

// Utility functions
function generateBackupCodes(count = 10) {
  return Array(count).fill().map(() => 
    crypto.randomBytes(6).toString('hex').toUpperCase().match(/.{1,4}/g).join('-')
  );
}

// ============ REGISTRATION & EMAIL VERIFICATION ============
app.post('/register', 
  [
    check('email').isEmail().normalizeEmail(),
    check('password').isLength({ min: 8 })
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { email, password } = req.body;
      
      // Check if user already exists
      const userExists = await pool.query(
        'SELECT id FROM users WHERE email = $1', 
        [email]
      );
      
      if (userExists.rows.length > 0) {
        return res.status(409).json({ error: 'Email already registered' });
      }

      const verificationToken = generateVerificationToken();
      const hashedPassword = await bcrypt.hash(password, 12);

      const result = await pool.query(
        `INSERT INTO users (email, password, verification_token, is_verified) 
         VALUES ($1, $2, $3, $4) RETURNING id`,
        [email, hashedPassword, verificationToken, false]
      );

      await sendVerificationEmail(email, verificationToken);

      res.status(201).json({ 
        message: 'Registration successful! Please check your email.',
        userId: result.rows[0].id
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Registration failed' });
    }
  }
);

app.get('/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    
    const result = await pool.query(
      `UPDATE users 
       SET is_verified = true, verification_token = NULL, verified_at = NOW() 
       WHERE verification_token = $1 
       RETURNING id`,
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    res.json({ message: 'Email verified successfully!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// ============ LOGIN & SESSION MANAGEMENT ============
app.post('/login', 
  [
    check('email').isEmail().normalizeEmail(),
    check('password').notEmpty()
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { email, password } = req.body;
      
      const userResult = await pool.query(
        `SELECT id, email, password, is_verified, mfa_enabled, mfa_secret, failed_login_attempts, 
         account_locked_until FROM users WHERE email = $1`,
        [email]
      );
      
      if (userResult.rows.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      const user = userResult.rows[0];
      
      // Check if account is locked
      if (user.account_locked_until && new Date(user.account_locked_until) > new Date()) {
        return res.status(403).json({ 
          error: 'Account temporarily locked due to too many failed attempts',
          locked_until: user.account_locked_until
        });
      }
      
      // Verify password
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        // Increment failed attempts
        await pool.query(
          `UPDATE users 
           SET failed_login_attempts = failed_login_attempts + 1,
               account_locked_until = CASE 
                 WHEN failed_login_attempts + 1 >= 5 THEN NOW() + INTERVAL '30 minutes'
                 ELSE NULL
               END
           WHERE email = $1`,
          [email]
        );
        
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      // Reset failed attempts on successful login
      await pool.query(
        'UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL WHERE email = $1',
        [email]
      );
      
      if (!user.is_verified) {
        return res.status(403).json({ error: 'Email not verified' });
      }
      
      if (user.mfa_enabled) {
        const tempToken = jwt.sign(
          { userId: user.id, mfaPending: true },
          process.env.JWT_SECRET,
          { expiresIn: '5m' }
        );
        
        return res.json({ 
          mfaRequired: true,
          tempToken
        });
      }
      
      const token = jwt.sign(
        { userId: user.id }, 
        process.env.JWT_SECRET, 
        { expiresIn: '1h' }
      );
      
      const refreshToken = jwt.sign(
        { userId: user.id },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '7d' }
      );
      
      // Store refresh token
      await pool.query(
        'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL \'7 days\')',
        [user.id, refreshToken]
      );
      
      res.json({ 
        token, 
        refreshToken,
        mfaRequired: false 
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Login failed' });
    }
  }
);

// ============ PASSWORD RESET ============
app.post('/password-reset/request', 
  [check('email').isEmail().normalizeEmail()],
  async (req, res) => {
    try {
      const { email } = req.body;
      
      const userResult = await pool.query(
        'SELECT id FROM users WHERE email = $1',
        [email]
      );
      
      if (userResult.rows.length === 0) {
        // Don't reveal if user exists
        return res.json({ message: 'If an account exists, a reset email has been sent' });
      }
      
      const resetToken = generatePasswordResetToken();
      const expiresAt = new Date(Date.now() + 3600000); // 1 hour from now
      
      await pool.query(
        `UPDATE users 
         SET password_reset_token = $1, password_reset_expires = $2
         WHERE email = $3`,
        [resetToken, expiresAt, email]
      );
      
      await sendPasswordResetEmail(email, resetToken);
      
      res.json({ message: 'Password reset email sent' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Password reset request failed' });
    }
  }
);

app.post('/password-reset/confirm', 
  [
    check('token').notEmpty(),
    check('newPassword').isLength({ min: 8 })
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { token, newPassword } = req.body;
      
      const userResult = await pool.query(
        `SELECT id FROM users 
         WHERE password_reset_token = $1 
         AND password_reset_expires > NOW()`,
        [token]
      );
      
      if (userResult.rows.length === 0) {
        return res.status(400).json({ error: 'Invalid or expired token' });
      }
      
      const hashedPassword = await bcrypt.hash(newPassword, 12);
      
      await pool.query(
        `UPDATE users 
         SET password = $1, 
             password_reset_token = NULL, 
             password_reset_expires = NULL,
             failed_login_attempts = 0
         WHERE password_reset_token = $2`,
        [hashedPassword, token]
      );
      
      res.json({ message: 'Password reset successful' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Password reset failed' });
    }
  }
);

// ============ MFA ENDPOINTS ============
app.post('/mfa/setup', 
  [check('userId').isInt()],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { userId } = req.body;
      
      // Verify user exists and is verified
      const userResult = await pool.query(
        'SELECT id, is_verified FROM users WHERE id = $1',
        [userId]
      );
      
      if (userResult.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      if (!userResult.rows[0].is_verified) {
        return res.status(403).json({ error: 'Email not verified' });
      }
      
      const secret = speakeasy.generateSecret({
        length: 20,
        name: `AuthApp (${userId})`,
        issuer: 'AuthSystem'
      });

      // Generate backup codes
      const backupCodes = generateBackupCodes();
      const hashedCodes = await Promise.all(
        backupCodes.map(code => bcrypt.hash(code, 10))
      );

      // Store MFA secret and backup codes
      await pool.query(
        `UPDATE users 
         SET mfa_secret = $1, backup_codes = $2 
         WHERE id = $3`,
        [secret.base32, hashedCodes, userId]
      );

      // Generate QR Code
      QRCode.toDataURL(secret.otpauth_url, (err, qrCodeUrl) => {
        if (err) throw err;
        
        res.json({
          secret: secret.base32,
          qrCodeUrl,
          manualEntryCode: secret.otpauth_url.match(/secret=([^&]+)/)[1],
          backupCodes, // Show only once!
          warning: "Save these backup codes securely. They won't be shown again."
        });
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'MFA setup failed' });
    }
  }
);

app.post('/mfa/verify', 
  [
    check('userId').isInt(),
    check('token').isLength({ min: 6, max: 6 })
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { userId, token } = req.body;
      
      const userResult = await pool.query(
        'SELECT mfa_secret FROM users WHERE id = $1',
        [userId]
      );
      
      if (userResult.rows.length === 0 || !userResult.rows[0].mfa_secret) {
        return res.status(400).json({ error: 'MFA not configured' });
      }

      const verified = speakeasy.totp.verify({
        secret: userResult.rows[0].mfa_secret,
        encoding: 'base32',
        token,
        window: 2
      });

      if (verified) {
        await pool.query(
          'UPDATE users SET mfa_enabled = true WHERE id = $1',
          [userId]
        );
      }

      res.json({ verified });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'MFA verification failed' });
    }
  }
);

app.post('/mfa/finalize', 
  [
    check('tempToken').notEmpty(),
    check('mfaToken').optional().isLength({ min: 6, max: 6 }),
    check('backupCode').optional().isLength({ min: 8 })
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { tempToken, mfaToken, backupCode } = req.body;
      
      const decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
      if (!decoded.mfaPending) {
        return res.status(400).json({ error: 'Invalid token' });
      }

      const userResult = await pool.query(
        'SELECT mfa_secret, backup_codes FROM users WHERE id = $1',
        [decoded.userId]
      );
      
      if (userResult.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      const user = userResult.rows[0];
      let verified = false;

      if (backupCode) {
        // Verify backup code
        const backupCodes = user.backup_codes || [];
        for (const hashedCode of backupCodes) {
          if (await bcrypt.compare(backupCode, hashedCode)) {
            verified = true;
            
            // Remove used backup code
            const updatedCodes = backupCodes.filter(
              code => !bcrypt.compareSync(backupCode, code)
            );
            
            await pool.query(
              'UPDATE users SET backup_codes = $1 WHERE id = $2',
              [updatedCodes, decoded.userId]
            );
            
            break;
          }
        }
      } else if (mfaToken) {
        // Verify MFA code
        verified = speakeasy.totp.verify({
          secret: user.mfa_secret,
          encoding: 'base32',
          token: mfaToken,
          window: 2
        });
      } else {
        return res.status(400).json({ error: 'Either mfaToken or backupCode is required' });
      }
      
      if (!verified) {
        return res.status(401).json({ error: 'Invalid verification code' });
      }
      
      const token = jwt.sign(
        { userId: decoded.userId },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      
      const refreshToken = jwt.sign(
        { userId: decoded.userId },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '7d' }
      );
      
      // Store refresh token
      await pool.query(
        'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL \'7 days\')',
        [decoded.userId, refreshToken]
      );
      
      res.json({ token, refreshToken });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'MFA finalization failed' });
    }
  }
);

// ============ TOKEN REFRESH ============
app.post('/refresh-token', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh token is required' });
    }
    
    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    
    // Check if token exists in DB and isn't expired
    const tokenResult = await pool.query(
      `SELECT id FROM refresh_tokens 
       WHERE token = $1 AND user_id = $2 AND expires_at > NOW()`,
      [refreshToken, decoded.userId]
    );
    
    if (tokenResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }
    
    // Generate new access token
    const newToken = jwt.sign(
      { userId: decoded.userId },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    res.json({ token: newToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

// ============ USER PROFILE & SESSIONS ============
app.get('/profile', 
  async (req, res) => {
    try {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1];
      
      if (!token) return res.sendStatus(401);
      
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      const userResult = await pool.query(
        `SELECT id, email, is_verified, created_at, verified_at, 
         mfa_enabled FROM users WHERE id = $1`,
        [decoded.userId]
      );
      
      if (userResult.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      res.json(userResult.rows[0]);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Failed to fetch profile' });
    }
  }
);

app.get('/sessions', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.sendStatus(401);
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const sessions = await pool.query(
      `SELECT id, token, created_at, expires_at 
       FROM refresh_tokens 
       WHERE user_id = $1 AND expires_at > NOW()`,
      [decoded.userId]
    );
    
    res.json(sessions.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

app.delete('/sessions/:id', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.sendStatus(401);
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const sessionId = req.params.id;
    
    await pool.query(
      `DELETE FROM refresh_tokens 
       WHERE id = $1 AND user_id = $2`,
      [sessionId, decoded.userId]
    );
    
    res.json({ message: 'Session revoked' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to revoke session' });
  }
});

// ============ DATABASE INITIALIZATION ============
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        is_verified BOOLEAN DEFAULT FALSE,
        verification_token VARCHAR(255),
        verified_at TIMESTAMP,
        password_reset_token VARCHAR(255),
        password_reset_expires TIMESTAMP,
        mfa_secret VARCHAR(255),
        mfa_enabled BOOLEAN DEFAULT FALSE,
        backup_codes TEXT[],
        failed_login_attempts INTEGER DEFAULT 0,
        account_locked_until TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
      
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        token VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP NOT NULL
      );
      
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
    `);
    
    console.log('✅ Database tables initialized');
  } catch (err) {
    console.error('❌ Database initialization failed:', err);
    process.exit(1);
  }
}

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  await initializeDatabase();
  console.log(`Server running on port ${PORT}`);
});