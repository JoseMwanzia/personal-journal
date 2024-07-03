const Koa = require('koa');
const Router = require('koa-router');
const bodyParser = require('koa-bodyparser');
const session = require('koa-session');
const bcrypt = require('bcrypt');
const pool = require('./db');

const app = new Koa();
const router = new Router();

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
    const res = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *',
      [name, email, hashedPassword]
    );
    ctx.status = 201;
    ctx.body = res.rows[0];
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


// CRUD routes (as before, protected by authMiddleware if needed)
router.get('/users', authMiddleware, async (ctx) => {
  try {
    const res = await pool.query('SELECT * FROM users');
    ctx.body = res.rows;
  } catch (err) {
    ctx.status = 500;
    ctx.body = err.message;
  }
});

app
  .use(router.routes())
  .use(router.allowedMethods());

const port = 3000;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
