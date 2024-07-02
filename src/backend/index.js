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
app.use(session(app));

// Middleware to protect routes
const authMiddleware = async (ctx, next) => {
  if (!ctx.session.userId) {
    ctx.status = 401;
    ctx.body = 'Unauthorized';
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
    const res = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (res.rows.length > 0) {
      const user = res.rows[0];
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        ctx.session.userId = user.id;
        ctx.body = 'Login successful';
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

// Protected route example
router.get('/protected', authMiddleware, async (ctx) => {
  ctx.body = 'This is a protected route';
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
