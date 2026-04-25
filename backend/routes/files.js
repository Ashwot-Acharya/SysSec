const express = require('express');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs').promises;
const { readDB, writeDB } = require('../db');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Multer storage configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
});

// GET user's files
router.get('/', authenticateToken, async (req, res) => {
  try {
    const db = await readDB();
    const userFiles = db.files.filter(f => f.userId === req.user.id);
    res.json(userFiles);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// POST upload file
router.post('/upload', authenticateToken, upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded' });
  }

  try {
    const db = await readDB();
    const newFile = {
      id: uuidv4(),
      userId: req.user.id,
      originalName: req.file.originalname,
      fileName: req.file.filename,
      path: req.file.path,
      size: req.file.size,
      mimetype: req.file.mimetype,
      createdAt: new Date().toISOString()
    };

    db.files.push(newFile);
    await writeDB(db);

    res.status(201).json({ message: 'File uploaded successfully', file: newFile });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// PUT update file metadata (e.g. rename)
router.put('/:id', authenticateToken, async (req, res) => {
  const { newName } = req.body;
  
  if (!newName) {
    return res.status(400).json({ message: 'New name is required' });
  }

  try {
    const db = await readDB();
    const fileIndex = db.files.findIndex(f => f.id === req.params.id && f.userId === req.user.id);
    
    if (fileIndex === -1) {
      return res.status(404).json({ message: 'File not found or unauthorized' });
    }

    db.files[fileIndex].originalName = newName;
    await writeDB(db);

    res.json({ message: 'File renamed successfully', file: db.files[fileIndex] });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// DELETE file
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const db = await readDB();
    const fileIndex = db.files.findIndex(f => f.id === req.params.id && f.userId === req.user.id);
    
    if (fileIndex === -1) {
      return res.status(404).json({ message: 'File not found or unauthorized' });
    }

    const file = db.files[fileIndex];
    
    // Remove from filesystem
    try {
      await fs.unlink(file.path);
    } catch (err) {
      console.error('Failed to delete file from filesystem:', err);
      // Even if filesystem delete fails (e.g., file already deleted manually), we still remove from DB
    }

    // Remove from DB
    db.files.splice(fileIndex, 1);
    await writeDB(db);

    res.json({ message: 'File deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
