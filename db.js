// db.js
require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Required for Render
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