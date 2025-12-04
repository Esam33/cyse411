// server.js (FIXED - secure auth, hashing, sessions, rate limiting)

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

const app = express();
const PORT = 3001;

// ---------- Middleware ----------
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static('public'));

// In-memory user + session stores
// Password now stored using bcrypt instead of fast SHA-256
const users = [
  {
    id: 1,
    username: 'student',
    passwordHash: bcrypt.hashSync('password123', 10), // strong salted hash
  },
];

const sessions = {}; // token -> { userId, createdAt }

// Simple login rate limiter (per username)
const loginAttempts = {}; // username -> { count, firstTs }
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 5 * 60 * 1000; // 5 minutes

function isRateLimited(username) {
  const now = Date.now();
  const entry = loginAttempts[username];

  if (!entry) {
    loginAttempts[username] = { count: 1, firstTs: now };
    return false;
  }

  if (now - entry.firstTs > WINDOW_MS) {
    // reset window
    loginAttempts[username] = { count: 1, firstTs: now };
    return false;
  }

  entry.count += 1;
  return entry.count > MAX_ATTEMPTS;
}

// Helper: find user by username
function findUser(username) {
  return users.find((u) => u.username === username);
}

// Helper: generate strong random token
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Helper: create session + cookie
function createSession(res, userId) {
  const token = generateSessionToken();
  sessions[token] = {
    userId,
    createdAt: Date.now(),
  };

  // Secure cookie flags added
  res.cookie('session', token, {
    httpOnly: true,
    secure: true,      // assume HTTPS in production; OK for demo
    sameSite: 'lax',
    maxAge: 30 * 60 * 1000, // 30 minutes
  });

  return token;
}

// Middleware to load session from cookie
function loadSession(req, res, next) {
  const token = req.cookies.session;
  if (!token || !sessions[token]) {
    req.session = null;
    return next();
  }

  const session = sessions[token];

  // Simple expiration check (30 minutes)
  const age = Date.now() - session.createdAt;
  if (age > 30 * 60 * 1000) {
    delete sessions[token];
    req.session = null;
    return next();
  }

  req.session = session;
  next();
}

app.use(loadSession);

// ---------- Routes ----------

// Show who is logged in
app.get('/api/me', (req, res) => {
  if (!req.session) {
    return res.status(401).json({ authenticated: false });
  }

  const user = users.find((u) => u.id === req.session.userId);
  if (!user) {
    return res.status(401).json({ authenticated: false });
  }

  res.json({ authenticated: true, username: user.username });
});

// Secure login endpoint
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Missing credentials' });
  }

  // Rate limiting per username
  if (isRateLimited(username)) {
    return res
      .status(429)
      .json({ success: false, message: 'Too many login attempts, please try again later.' });
  }

  const user = findUser(username);
  if (!user) {
    // Generic message to avoid username enumeration
    return res.status(401).json({ success: false, message: 'Invalid username or password' });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.status(401).json({ success: false, message: 'Invalid username or password' });
  }

  const token = createSession(res, user.id);

  // Do NOT leak token via JSON in a real app; here we just confirm success
  res.json({ success: true, tokenIssued: !!token });
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) {
    delete sessions[token];
  }

  res.clearCookie('session');
  res.json({ success: true });
});

// ---------- Start server ----------
app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
