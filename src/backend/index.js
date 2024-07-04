const Koa = require('koa');
const Router = require('koa-router');
const bodyParser = require('koa-bodyparser');
const session = require('koa-session');
const bcrypt = require('bcrypt');
const db = require('./db'); 
const cors = require('@koa/cors');
const { pool } = require('./db');

const app = new Koa();
const router = new Router();
// Use CORS middleware
app.use(cors());

app.use(bodyParser());

// Set up sessions
app.keys = ['your-session-secret'];

const sessionConfig = {
    key: 'koa-session-id', // Name of the cookie to save session ID
    maxAge: 86400000, // Session expires in 1 day (ms)
    overwrite: false, // Overwrite existing session data
    httpOnly: true, // Cookie accessible only via HTTP(S)
    signed: true, // Cookie is signed
    rolling: false, // Reset session maxAge on every response
    renew: false, // Renew session when session nearly expires
    secure: false, // Set true for HTTPS only
    sameSite: 'lax', // Protect against CSRF
  };

app.use(session(sessionConfig, app));

// Middleware to protect routes
const authMiddleware = async (ctx, next) => {
  if (!ctx.session.userId) {
    ctx.status = 401;
    ctx.body = 'You are not authorized to access this resource';
  } else {
    await next();
  }
};

// Registration route
router.post('/register', async (ctx) => {
  const { name, email, password } = ctx.request.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
    const result = await db.query(sql, [name, email, hashedPassword]);
    ctx.status = 201;
    ctx.body = result;
  } catch (err) {
    ctx.status = 500;
    ctx.body = err.message;
  }
});

// Login route
router.post('/login', async (ctx) => {
  const { email, password } = ctx.request.body;
  try {
    const sql = 'SELECT * FROM users WHERE email = ?';
    const result = await db.query(sql, [email]);
    if (result.length > 0) {
      const user = result[0];
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        ctx.session.userId = user.id; // Set session ID upon successful login
        ctx.body = result;
      } else {
        ctx.status = 401;
        ctx.body = 'Invalid credentials';
      }
    } else {
      ctx.status = 401;
      ctx.body = 'Invalid credentials';
    }
  } catch (err) {
    ctx.status = 500;
    ctx.body = err.message;
  }
});

// Logout route
router.post('/logout', async (ctx) => {
  ctx.session = null;
  ctx.body = 'Logged out successfully';
});


// Get all users route
router.get('/users', authMiddleware, async (ctx) => {
  try {
    const sql = 'SELECT * FROM users';
    const users = await db.query(sql);
    ctx.body = users;
  } catch (err) {
    ctx.status = 500;
    ctx.body = err.message;
  }
});

// Update username
router.put('/profile', authMiddleware, async (ctx) => {
    const { name } = ctx.request.body;
    const userId = ctx.session.userId;

    if (!name) {
        ctx.status = 400;
        ctx.body = { message: 'New Username is required' };
        return;
    }

    try {
        const sql = 'UPDATE users SET name = ? WHERE id = ?';
        const result = await pool.query(sql, [name, userId]);

        if (result) {
            ctx.response.status = 200;
            ctx.response.body = result.values[0]
        } else {
            ctx.status = 404;
            ctx.body = { message: 'User not found or not authorized' };
        }
    } catch (err) {
        ctx.status = 500;
        ctx.body = { message: err.message };
    }
});


// Update password
router.put('/password', authMiddleware, async (ctx) => {
    const { oldPassword, newPassword } = ctx.request.body;
    const userId = ctx.session.userId;

    if (!oldPassword || !newPassword) {
        ctx.status = 400;
        ctx.body = { message: 'Old and new passwords are required' };
        return;
    }

    try {
        // Fetch the current password for the user
        const sql = 'SELECT * FROM users WHERE id = ?';
        const getUser = await db.query(sql, [userId]);
        const userPassword = getUser[0].password

        // console.log(userPassword);
        // console.log(sql);

        if (userPassword.length === 0) {
            ctx.status = 404;
            ctx.body = { message: 'User not found or not authorized' };
            return;
        }

        // const user = userPassword.values[0];
        if (!userPassword) {
            ctx.status = 500;
            ctx.body = { message: 'User password not found' };
            return;
        }

        const match = await bcrypt.compare(oldPassword, userPassword);

        if (!match) {
            ctx.status = 401;
            ctx.body = { message: 'Old password is incorrect' };
            return;
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const updateSql = 'UPDATE users SET password = ? WHERE id = ?';
        const result = await pool.query(updateSql, [hashedPassword, userId]);

        if (result) {
            ctx.response.status = 200;
            ctx.response.body = { message: 'Password updated successfully' };
        } else {
            ctx.status = 404;
            ctx.body = { message: 'User not found or not authorized' };
        }
    } catch (err) {
        ctx.status = 500;
        ctx.body = { message: err.message };
    }
});


app
  .use(router.routes())
  .use(router.allowedMethods());

const port = 3000;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
