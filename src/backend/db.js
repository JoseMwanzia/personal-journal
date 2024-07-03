const mysql = require('mysql');

// Create MySQL connection pool
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'journaling_DB',
});

// Handle connection errors
pool.on('error', (err) => {
  console.error('MySQL Pool Error:', err);
});

module.exports = {
  query: (sql, params) => {
    return new Promise((resolve, reject) => {
      pool.query(sql, params, (err, rows) => {
        if (err) {
          console.error('MySQL Query Error:', err);
          return reject(err);
        }
        resolve(rows);
      });
    });
  },
  pool: pool, // If you need direct access to the pool
};
