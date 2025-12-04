// canonicalization-example/server.js
const express = require("express");
const path = require("path");
const fs = require("fs");
const { body, validationResult } = require("express-validator");

const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const BASE_DIR = path.resolve(__dirname, "files");
if (!fs.existsSync(BASE_DIR)) {
  fs.mkdirSync(BASE_DIR, { recursive: true });
}

// Helper: canonicalize and normalize path
function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {
    // ignore decode errors and use raw value
  }
  return path.resolve(baseDir, userInput);
}

// Common validation for filenames
const validateFilename = [
  body("filename")
    .exists()
    .withMessage("filename required")
    .bail()
    .isString()
    .trim()
    .notEmpty()
    .withMessage("filename must not be empty")
    .custom((value) => {
      if (value.includes("\0")) {
        throw new Error("null byte not allowed");
      }
      return true;
    }),
];

// Shared handler used by both endpoints
function handleRead(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const filename = req.body.filename;
  const normalized = resolveSafe(BASE_DIR, filename);

  // Ensure we stayed inside BASE_DIR
  if (!normalized.startsWith(BASE_DIR + path.sep)) {
    return res.status(403).json({ error: "Path traversal detected" });
  }

  if (!fs.existsSync(normalized)) {
    return res.status(404).json({ error: "File not found" });
  }

  const content = fs.readFileSync(normalized, "utf8");
  res.json({ path: normalized, content });
}

// SECURE route (already safe)
app.post("/read", validateFilename, handleRead);

// PREVIOUSLY-VULNERABLE route now reuses the same safe logic
app.post("/read-no-validate", validateFilename, handleRead);

// Helper route for samples
app.post("/setup-sample", (req, res) => {
  const samples = {
    "hello.txt": "Hello from safe file!\n",
    "notes/readme.md": "# Readme\nSample readme file\n",
  };

  Object.keys(samples).forEach((k) => {
    const p = path.resolve(BASE_DIR, k);
    const d = path.dirname(p);
    if (!fs.existsSync(d)) {
      fs.mkdirSync(d, { recursive: true });
    }
    fs.writeFileSync(p, samples[k], "utf8");
  });

  res.json({ ok: true, base: BASE_DIR });
});

// Only listen when run directly
if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Canonicalization server listening on http://localhost:${port}`);
  });
}

module.exports = app;
