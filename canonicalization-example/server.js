// canonicalization-example/server.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// --- Security middleware ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Static files for the demo UI
app.use(express.static(path.join(__dirname, 'public')));

// Folder that will contain files
const BASE_DIR = path.resolve(__dirname, 'files');
if (!fs.existsSync(BASE_DIR)) {
  fs.mkdirSync(BASE_DIR, { recursive: true });
}

// Rate limiting for read endpoints
const readLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20,             // max 20 requests per minute per IP
  standardHeaders: true,
  legacyHeaders: false
});

// Only allow filenames like: notes/readme.md or hello.txt
const FILENAME_REGEX = /^[a-zA-Z0-9_\-\/]{1,100}\.(txt|md|log)$/;

// Helper to canonicalize and validate the path
function resolveSafe(baseDir, userInput) {
  if (typeof userInput !== 'string' || userInput.trim() === '') {
    throw new Error('Filename is required');
  }

  if (!FILENAME_REGEX.test(userInput)) {
    throw new Error('Invalid filename format');
  }

  // Normalize separators
  const sanitized = userInput.replace(/\\/g, '/');

  // Build absolute path and normalize
  const normalized = path.resolve(baseDir, sanitized);

  // Ensure the resolved path is still inside BASE_DIR (no ../ traversal)
  if (!normalized.startsWith(baseDir + path.sep)) {
    throw new Error('Path traversal detected');
  }

  if (!fs.existsSync(normalized)) {
    throw new Error('File not found');
  }

  return normalized;
}

// ---- Secure route to read files ----
app.post(
  '/read',
  readLimiter,
  body('filename').isString().trim().isLength({ min: 1, max: 100 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const filename = req.body.filename;
      const normalizedPath = resolveSafe(BASE_DIR, filename);
      const content = fs.readFileSync(normalizedPath, 'utf8');
      res.json({ path: normalizedPath, content });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }
);

// This endpoint used to be intentionally vulnerable.
// Now it simply delegates to the same safe logic as /read.
app.post(
  '/read-no-validate',
  readLimiter,
  body('filename').isString().trim().isLength({ min: 1, max: 100 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const filename = req.body.filename;
      const normalizedPath = resolveSafe(BASE_DIR, filename);
      const content = fs.readFileSync(normalizedPath, 'utf8');
      res.json({ path: normalizedPath, content });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }
);

// Helper route to create some safe sample files
app.post('/setup-sample', (req, res) => {
  const samples = {
    'hello.txt': 'Hello from safe file!\n',
    'notes/readme.md': '# Readme\nSample readme file contents\n'
  };

  Object.keys(samples).forEach((relativePath) => {
    const fullPath = path.resolve(BASE_DIR, relativePath);
    const dir = path.dirname(fullPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(fullPath, samples[relativePath], 'utf8');
  });

  res.json({ ok: true, baseDir: BASE_DIR });
});

// Start server if run directly
if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Canonicalization example listening on http://localhost:${port}`);
  });
}

module.exports = app;
