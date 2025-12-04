// idor/server.js
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());

// Fake "database"
const users = [
  { id: 1, name: 'Alice', role: 'customer', department: 'north' },
  { id: 2, name: 'Bob', role: 'customer', department: 'south' },
  { id: 3, name: 'Charlie', role: 'support', department: 'north' }
];

const orders = [
  { id: 1, userId: 1, item: 'Laptop',  region: 'north', total: 2000 },
  { id: 2, userId: 1, item: 'Mouse',   region: 'north', total:  40 },
  { id: 3, userId: 2, item: 'Monitor', region: 'south', total: 300 },
  { id: 4, userId: 2, item: 'Keyboard', region: 'south', total:  60 }
];

// Rate-limit access to the orders API
const ordersLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false
});

// Very simple "authentication" via headers
// X-User-Id: <user id>
function fakeAuth(req, res, next) {
  const idHeader = req.header('X-User-Id');
  const id = parseInt(idHeader, 10);

  if (!Number.isInteger(id)) {
    return res.status(401).json({ error: 'Unauthenticated: set valid X-User-Id header' });
  }

  const user = users.find((u) => u.id === id);
  if (!user) {
    return res.status(401).json({ error: 'Unauthenticated: unknown user' });
  }

  req.user = user;
  next();
}

// Apply fakeAuth to all routes below
app.use(fakeAuth);

// --- Secure orders endpoint ---
// Only the owner of the order OR a support user can see an order.
app.get('/orders/:id', ordersLimiter, (req, res) => {
  const orderId = parseInt(req.params.id, 10);
  if (!Number.isInteger(orderId)) {
    return res.status(400).json({ error: 'Invalid order id' });
  }

  const order = orders.find((o) => o.id === orderId);
  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }

  // Enforce ownership / authorization
  const isOwner = order.userId === req.user.id;
  const isSupport = req.user.role === 'support';

  if (!isOwner && !isSupport) {
    // Previously: IDOR vulnerability, we returned the order unconditionally.
    return res.status(403).json({ error: 'Forbidden: you are not allowed to see this order' });
  }

  res.json(order);
});

// Simple health check
app.get('/', (req, res) => {
  res.json({
    message: 'Access Control Tutorial API',
    currentUser: { id: req.user.id, name: req.user.name, role: req.user.role }
  });
});

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`IDOR lab listening at http://localhost:${PORT}`);
  });
}

module.exports = app;
