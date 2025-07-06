// emailService.js
require('dotenv').config();
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const handlebars = require('handlebars');
const fs = require('fs').promises;
const path = require('path');


const verificationTemplate = (data) => `
  <p>Hello,</p>
  <p>Please verify your email by clicking the link below:</p>
  <a href="${data.verificationUrl}">Verify Email</a>
  <p>Or copy this URL: ${data.verificationUrl}</p>
`;

const passwordResetTemplate = (data) => `
  <p>Hello,</p>
  <p>Click the link below to reset your password:</p>
  <a href="${data.resetUrl}">Reset Password</a>
  <p>Or copy this URL: ${data.resetUrl}</p>
`;

// Initialize transporter
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Test connection
transporter.verify()
  .then(() => console.log('✅ SMTP Connection READY'))
  .catch(err => console.error('❌ SMTP Connection FAILED:', err.message));

// Email sending functions
const sendEmail = async (to, subject, html) => {
  try {
    const info = await transporter.sendMail({
      from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_FROM}>`,
      to,
      subject,
      html
    });
    return info;
  } catch (error) {
    console.error('Email send error:', error);
    throw error;
  }
};

const sendVerificationEmail = async (email, token) => {
  const verificationUrl = `${process.env.BASE_URL}/verify-email?token=${token}`;
  const html = verificationTemplate({ email, verificationUrl });
  return sendEmail(email, 'Verify Your Email', html);
};

const sendPasswordResetEmail = async (email, token) => {
  const resetUrl = `${process.env.BASE_URL}/reset-password?token=${token}`;
  const html = passwordResetTemplate({ email, resetUrl });
  return sendEmail(email, 'Password Reset Request', html);
};


module.exports = {
  sendVerificationEmail,
  sendPasswordResetEmail,
  generateVerificationToken: uuidv4,
  generatePasswordResetToken: uuidv4
};