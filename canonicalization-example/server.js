// server.js (FIXED - secure canonicalization and path usage)

const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');

const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Base directory where files must live
const BASE_DIR = path.resolve(__dirname, 'files');
if (!fs.existsSync(BASE_DIR)) {
  fs.mkdirSync(BASE_DIR, { recursive: true });
}

/**
 * Safely resolve a user-supplied path so it:
 *  - is decoded
 *  - normalized
 *  - stays inside BASE_DIR (no ../ traversal)
 */
function resolveSafe(baseDir, userInput) {
  try {
    const decoded = decodeURIComponent(userInput);
    const normalized = path.resolve(baseDir, decoded);

    // Ensure the normalized path is still under BASE_DIR
    if (!normalized.startsWith(baseDir + path.sep)) {
      throw new Error('Path traversal detected');
    }

    return normalized;
  } catch (e) {
    throw new Error('Invalid path');
  }
}

// ---------- Secure route (used in the lab) ----------
app.post(
  '/read',
  body('filename')
    .exists().withMessage('filename required')
    .bail()
    .isString()
    .trim()
    .notEmpty().withMessage('filename must not be empty'),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const filename = req.body.filename;
      const normalized = resolveSafe(BASE_DIR, filename);

      if (!fs.existsSync(normalized)) {
        return res.status(404).json({ error: 'File not found' });
      }

      const content = fs.readFileSync(normalized, 'utf8');
      res.json({ path: normalized, content });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }
);

// ---------- Previously vulnerable route: now secured ----------
app.post(
  '/read-no-validate',
  body('filename')
    .exists().withMessage('filename required')
    .bail()
    .isString()
    .trim()
    .notEmpty().withMessage('filename must not be empty'),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const filename = req.body.filename;
      const normalized = resolveSafe(BASE_DIR, filename);

      if (!fs.existsSync(normalized)) {
        return res.status(404).json({ error: 'File not found' });
      }

      const content = fs.readFileSync(normalized, 'utf8');
      res.json({ path: normalized, content });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }
);

// ---------- Helper route to create sample files ----------
app.post('/setup-sample', (req, res) => {
  const samples = {
    'hello.txt': 'Hello from safe file!\n',
    'notes/readme.md': '# Readme\nSample readme file',
  };

  Object.keys(samples).forEach((p) => {
    const fullPath = resolveSafe(BASE_DIR, p);
    const dir = path.dirname(fullPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(fullPath, samples[p], 'utf8');
  });

  res.json({ ok: true, base: BASE_DIR });
});

// ---------- Start server ----------
if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;
