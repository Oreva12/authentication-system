// db.js
require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 5432,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
});

// Test connection on startup
pool.connect()
  .then(client => {
    console.log('✅ PostgreSQL Connection READY');
    client.release();
  })
  .catch(err => {
    console.error('❌ PostgreSQL Connection FAILED:', err.message);
    process.exit(1);
  });

module.exports = pool;