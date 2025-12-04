// idor/server.js
const express = require("express");
const app = express();

app.use(express.json());

// Fake "database"
const users = [
  { id: 1, name: "Alice", role: "customer", department: "north" },
  { id: 2, name: "Bob", role: "customer", department: "south" },
  { id: 3, name: "Charlie", role: "support", department: "north" },
];

const orders = [
  { id: 1, userId: 1, item: "Laptop", region: "north", total: 2000 },
  { id: 2, userId: 1, item: "Mouse", region: "north", total: 40 },
  { id: 3, userId: 2, item: "Monitor", region: "south", total: 300 },
  { id: 4, userId: 2, item: "Keyboard", region: "south", total: 60 },
];

// Very simple "authentication" via headers:
//   X-User-Id: <user id>
function fakeAuth(req, res, next) {
  const idHeader = req.header("X-User-Id");
  const id = idHeader ? parseInt(idHeader, 10) : NaN;

  const user = users.find((u) => u.id === id);
  if (!user) {
    return res.status(401).json({ error: "Unauthenticated: set valid X-User-Id" });
  }

  req.user = user;
  next();
}

// Apply fakeAuth to all routes below this line
app.use(fakeAuth);

// SECURE endpoint: enforce ownership or support role
app.get("/orders/:id", (req, res) => {
  const orderId = parseInt(req.params.id, 10);
  if (!Number.isInteger(orderId)) {
    return res.status(400).json({ error: "Invalid order id" });
  }

  const order = orders.find((o) => o.id === orderId);
  if (!order) {
    return res.status(404).json({ error: "Order not found" });
  }

  const isOwner = order.userId === req.user.id;
  const isSupport = req.user.role === "support";

  if (!isOwner && !isSupport) {
    // Previously we returned the order with no check (IDOR).
    return res
      .status(403)
      .json({ error: "Forbidden: you are not allowed to view this order" });
  }

  return res.json(order);
});

// Health check
app.get("/", (req, res) => {
  res.json({ message: "Access Control Tutorial API", currentUser: req.user });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`IDOR lab server running at http://localhost:${PORT}`);
});

module.exports = app;
