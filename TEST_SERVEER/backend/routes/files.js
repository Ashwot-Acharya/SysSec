const express = require('express');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs').promises;
const { getFilesByUserId, getFileByIdAndUser, insertFile, updateFileName, deleteFileById } = require('../db');
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
router.get('/', authenticateToken, (req, res) => {
  try {
    const userFiles = getFilesByUserId.all(req.user.id);
    res.json(userFiles);
  } catch (error) {
    console.error('Get files error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST upload file
router.post('/upload', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded' });
  }

  try {
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

    insertFile.run(newFile);

    res.status(201).json({ message: 'File uploaded successfully', file: newFile });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// PUT update file metadata (e.g. rename)
router.put('/:id', authenticateToken, (req, res) => {
  const { newName } = req.body;
  
  if (!newName) {
    return res.status(400).json({ message: 'New name is required' });
  }

  try {
    const file = getFileByIdAndUser.get(req.params.id, req.user.id);

    if (!file) {
      return res.status(404).json({ message: 'File not found or unauthorized' });
    }

    updateFileName.run(newName, req.params.id, req.user.id);

    res.json({ message: 'File renamed successfully', file: { ...file, originalName: newName } });
  } catch (error) {
    console.error('Rename error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// DELETE file
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const file = getFileByIdAndUser.get(req.params.id, req.user.id);

    if (!file) {
      return res.status(404).json({ message: 'File not found or unauthorized' });
    }

    // Remove from filesystem
    try {
      await fs.unlink(file.path);
    } catch (err) {
      console.error('Failed to delete file from filesystem:', err);
      // Even if filesystem delete fails, we still remove from DB
    }

    // Remove from DB
    deleteFileById.run(req.params.id, req.user.id);

    res.json({ message: 'File deleted successfully' });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
