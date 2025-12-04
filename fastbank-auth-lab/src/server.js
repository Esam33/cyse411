// fastbank-auth-lab/src/server.js
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');

const app = express();
const PORT = 3001;
const IS_PROD = process.env.NODE_ENV === 'production';

// --- Security middleware ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// Global (light) rate limiting
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(globalLimiter);

// Serve static login page / JS bundle
app.use(express.static('public'));

// --- User "database" (in-memory) ---
const PASSWORD_PLAIN = 'password123';
const PASSWORD_HASH = bcrypt.hashSync(PASSWORD_PLAIN, 12);

const users = [
  {
    id: 1,
    username: 'student',
    passwordHash: PASSWORD_HASH
  }
];

// --- Session store ---
const sessions = new Map(); // token -> { userId, createdAt, expiresAt }

// Create a cryptographically strong session token
function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  const expiresAt = now + 60 * 60 * 1000; // 1 hour

  sessions.set(token, { userId, createdAt: now, expiresAt });
  return token;
}

function getSession(token) {
  const session = sessions.get(token);
  if (!session) return null;
  if (session.expiresAt < Date.now()) {
    sessions.delete(token);
    return null;
  }
  return session;
}

function destroySession(token) {
  sessions.delete(token);
}

// Helper: find user by username
function findUser(username) {
  return users.find((u) => u.username === username);
}

// --- Authentication middleware ---
function attachUser(req, res, next) {
  const token = req.cookies.session;
  if (!token) {
    return next();
  }

  const session = getSession(token);
  if (!session) {
    return next();
  }

  const user = users.find((u) => u.id === session.userId);
  if (!user) {
    return next();
  }

  req.user = { id: user.id, username: user.username };
  next();
}

app.use(attachUser);

// Require authentication for protected routes
function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ authenticated: false });
  }
  next();
}

// --- CSRF protection ---
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'lax'
  }
});

// Endpoint to fetch CSRF token (frontend calls this first)
app.get('/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// --- Rate limit login attempts ---
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: 'Too many login attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false
});

// --- API: Who am I? ---
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ authenticated: true, username: req.user.username });
});

// --- API: Login (secure) ---
// Uses bcrypt, CSRF, and rate limiting; no username enumeration.
app.post('/api/login', loginLimiter, csrfProtection, async (req, res) => {
  const { username, password } = req.body || {};

  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ success: false, message: 'Invalid request' });
  }

  const user = findUser(username);

  // To avoid timing differences & username enumeration, always run bcrypt
  const hashToCompare = user ? user.passwordHash : PASSWORD_HASH;
  const passwordMatches = await bcrypt.compare(password, hashToCompare);

  if (!user || !passwordMatches) {
    return res
      .status(401)
      .json({ success: false, message: 'Invalid username or password' });
  }

  const token = createSession(user.id);

  res.cookie('session', token, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'lax',
    maxAge: 60 * 60 * 1000 // 1 hour
  });

  res.json({ success: true });
});

// --- API: Logout (secure) ---
app.post('/api/logout', csrfProtection, requireAuth, (req, res) => {
  const token = req.cookies.session;
  if (token) {
    destroySession(token);
  }

  res.clearCookie('session', {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'lax'
  });

  res.json({ success: true });
});

// Health check
app.get('/', (req, res) => {
  res.json({ message: 'FastBank Auth Lab (secure)' });
});

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
