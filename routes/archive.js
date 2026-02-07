// ARCHIVE DOWNLOAD ENDPOINT - Final puzzle location
// Hint from processing logs: "archive download endpoint with key: ARCHIVE_MASTER_2024"
// PRESERVED FOR PUZZLE CHAIN - All security issues fixed

const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const router = express.Router();

// ==================== CONFIGURATION ====================
const JWT_SECRET = process.env.JWT_SECRET || 'file-upload-secret-2024';
const ENCRYPTION_KEY = 'ARCHIVE_MASTER_2024'; // PUZZLE 4 KEY

// XOR encrypted final message (PUZZLE 4)
const FINAL_SECRET_MESSAGE = 'SECRET_ARCHIVE_ACCESS_UNLOCKED_CONGRATULATIONS_FILE_MASTER_ACHIEVEMENT_2024';

// ==================== XOR ENCRYPTION FUNCTIONS ====================
function xorEncrypt(text, key) {
  let result = '';
  for (let i = 0; i < text.length; i++) {
    result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return Buffer.from(result).toString('base64');
}

function xorDecrypt(encryptedBase64, key) {
  try {
    const encrypted = Buffer.from(encryptedBase64, 'base64').toString();
    let result = '';
    for (let i = 0; i < encrypted.length; i++) {
      result += String.fromCharCode(encrypted.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return result;
  } catch (error) {
    return '[DECRYPTION_FAILED]';
  }
}

const ENCRYPTED_FINAL_MESSAGE = xorEncrypt(FINAL_SECRET_MESSAGE, ENCRYPTION_KEY);

// ==================== MOCK ARCHIVE DATA ====================
const archiveContents = [
  {
    filename: 'system-backup.zip',
    size: 104857600, // 100MB
    created: new Date('2024-01-01').toISOString(),
    modified: new Date('2024-01-01').toISOString(),
    contains: ['user-data.csv', 'config.json', 'logs.txt'],
    downloadKey: 'backup-2024-q1',
    checksum: 'a1b2c3d4e5f67890',
    compression: 'zip',
    encrypted: true,
    restricted: false,
    owner: 'system'
  },
  {
    filename: 'processed-files.tar.gz',
    size: 52428800, // 50MB
    created: new Date('2024-01-15').toISOString(),
    modified: new Date('2024-01-15').toISOString(),
    contains: ['images/', 'documents/', 'spreadsheets/'],
    downloadKey: 'processed-jan-2024',
    checksum: 'b2c3d4e5f67890a1',
    compression: 'tar.gz',
    encrypted: true,
    restricted: false,
    owner: 'system'
  },
  {
    filename: 'audit-trail.zip',
    size: 10485760, // 10MB
    created: new Date().toISOString(),
    modified: new Date().toISOString(),
    contains: ['access-logs.json', 'error-reports.csv', 'security-events.log'],
    downloadKey: 'audit-current',
    checksum: 'c3d4e5f67890a1b2',
    compression: 'zip',
    encrypted: true,
    restricted: true,
    owner: 'admin'
  },
  {
    filename: 'user-uploads-backup.zip',
    size: 209715200, // 200MB
    created: new Date('2024-01-10').toISOString(),
    modified: new Date('2024-01-10').toISOString(),
    contains: ['user1/', 'user2/', 'user3/'],
    downloadKey: 'user-backup-jan',
    checksum: 'd4e5f67890a1b2c3',
    compression: 'zip',
    encrypted: true,
    restricted: true,
    owner: 'admin'
  }
];

// ==================== MIDDLEWARE ====================

// Archive access middleware (multiple methods for puzzle)
function authenticateArchive(req, res, next) {
  const authHeader = req.get('authorization');
  const archiveKey = req.get('x-archive-key');
  const masterKey = req.query.master_key;
  const downloadKey = req.query.download_key;
  
  let hasAccess = false;
  let accessLevel = 'none';
  let currentUser = null;
  
  // Method 1: Archive Master Key (ultimate access - PUZZLE 4)
  if (archiveKey === ENCRYPTION_KEY || masterKey === ENCRYPTION_KEY) {
    hasAccess = true;
    accessLevel = 'master';
  }
  // Method 2: JWT Token (limited access)
  else if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const token = authHeader.split(' ')[1];
      currentUser = jwt.verify(token, JWT_SECRET);
      
      if (currentUser.role === 'admin') {
        hasAccess = true;
        accessLevel = 'admin';
      } else {
        // Regular users can access non-restricted archives
        hasAccess = true;
        accessLevel = 'user';
      }
      
      req.user = currentUser;
    } catch (error) {
      // Continue to check download key
    }
  }
  // Method 3: Download Key (archive-specific access)
  else if (downloadKey) {
    const validArchive = archiveContents.find(a => a.downloadKey === downloadKey);
    if (validArchive && !validArchive.restricted) {
      hasAccess = true;
      accessLevel = 'archive';
      req.archive = validArchive;
    }
  }
  
  if (!hasAccess) {
    return res.status(403).json({
      error: 'Access denied to archive system',
      hints: [
        'Try with valid JWT token (user/admin access)',
        'Use specific download key for archives: ?download_key=<key>',
        'Master archive key in X-Archive-Key header',
        'Master key in query parameter: ?master_key=<key>',
        'The processing logs might have mentioned a key...'
      ],
      code: 'ARCHIVE_ACCESS_DENIED',
      requiredMethods: [
        'Header: X-Archive-Key: <master_key>',
        'Query: ?master_key=<master_key>',
        'Query: ?download_key=<archive_key>',
        'Header: Authorization: Bearer <jwt_token>'
      ]
    });
  }
  
  req.accessLevel = accessLevel;
  next();
}

// ==================== UTILITY FUNCTIONS ====================

function sanitizeArchive(archive, accessLevel, currentUser) {
  const sanitized = {
    filename: archive.filename,
    size: archive.size,
    created: archive.created,
    modified: archive.modified,
    downloadKey: archive.downloadKey,
    compression: archive.compression
  };
  
  // Add more details based on access level
  if (accessLevel === 'admin' || accessLevel === 'master') {
    sanitized.contains = archive.contains;
    sanitized.restricted = archive.restricted || false;
    sanitized.owner = archive.owner;
    sanitized.downloadUrl = `/api/download/${archive.downloadKey}`;
  }
  
  // Add sensitive information for master access
  if (accessLevel === 'master') {
    sanitized.internalPath = `/secure/archives/${archive.filename}`;
    sanitized.checksum = archive.checksum;
    sanitized.encrypted = archive.encrypted;
    sanitized.compressionRatio = '75%';
    sanitized.backupLocation = `s3://secure-archives/${archive.filename}`;
  }
  
  // For archive-specific access (download key)
  if (accessLevel === 'archive') {
    sanitized.downloadUrl = `/api/download/${archive.downloadKey}`;
    sanitized.expiresAt = new Date(Date.now() + 3600000).toISOString(); // 1 hour
  }
  
  return sanitized;
}

// ==================== ROUTES ====================

// Get archives
router.get('/', authenticateArchive, async (req, res) => {
  try {
    let availableArchives = [...archiveContents];
    
    // Filter archives based on access level
    if (req.accessLevel === 'user') {
      availableArchives = availableArchives.filter(a => !a.restricted);
    } else if (req.accessLevel === 'archive') {
      availableArchives = availableArchives.filter(a => a.downloadKey === req.archive.downloadKey);
    }
    // admin and master see all archives
    
    // Prepare response data
    const responseData = {
      accessLevel: req.accessLevel,
      archives: availableArchives.map(archive => 
        sanitizeArchive(archive, req.accessLevel, req.user)
      ),
      systemStatus: {},
      downloadLinks: {},
      timestamp: new Date().toISOString()
    };
    
    // Add system status information
    if (req.accessLevel === 'admin' || req.accessLevel === 'master') {
      const totalSize = archiveContents.reduce((sum, a) => sum + a.size, 0);
      
      responseData.systemStatus = {
        totalArchives: archiveContents.length,
        totalSizeGB: (totalSize / (1024 * 1024 * 1024)).toFixed(2),
        totalSizeMB: (totalSize / (1024 * 1024)).toFixed(2),
        lastBackup: new Date(Date.now() - 86400000).toISOString(), // 24 hours ago
        compressionEnabled: true,
        encryptionStatus: 'active',
        storageType: 'secure-cloud',
        retentionPolicy: '90-days'
      };
    }
    
    // Add ultimate secret for master access (PUZZLE 4)
    if (req.accessLevel === 'master') {
      responseData.masterAccess = {
        congratulations: '🎉 You have achieved MASTER level access to the archive system!',
        puzzleCompleted: true,
        encryptedSecret: ENCRYPTED_FINAL_MESSAGE,
        decryptionKey: ENCRYPTION_KEY,
        decryptionHint: 'Use XOR decryption with the master key',
        decryptionMethod: 'xorDecrypt(encryptedSecret, decryptionKey)',
        achievementUnlocked: 'FILE_PROCESSING_MASTER_2024',
        finalMessage: 'You have successfully completed all file processing challenges!',
        rewards: [
          'Complete system access',
          'All security features unlocked',
          'Master achievement badge',
          'Priority support access'
        ]
      };
      
      // Automatically decrypt the message
      responseData.masterAccess.decryptedSecret = xorDecrypt(ENCRYPTED_FINAL_MESSAGE, ENCRYPTION_KEY);
      
      responseData.puzzleChain = {
        completed: true,
        steps: [
          { step: 1, name: 'Header Discovery', completed: true },
          { step: 2, name: 'Processing Logs Access', completed: true },
          { step: 3, name: 'Base64 Decryption', completed: true },
          { step: 4, name: 'Archive Master Access', completed: true }
        ],
        finalAchievement: 'FILE_PROCESSING_MASTER_2024'
      };
    }
    
    // Add download links for accessible archives
    availableArchives.forEach(archive => {
      responseData.downloadLinks[archive.downloadKey] = {
        url: `/api/download/${archive.downloadKey}`,
        expiresIn: '1 hour',
        method: 'GET',
        requiresAuth: archive.restricted
      };
    });
    
    // Set response headers
    const headers = {
      'X-Access-Level': req.accessLevel,
      'X-Available-Archives': responseData.archives.length.toString(),
      'X-Master-Access': req.accessLevel === 'master' ? 'UNLOCKED' : 'LOCKED',
      'X-Achievement': req.accessLevel === 'master' ? 'FILE_PROCESSING_MASTER_2024' : 'none',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0'
    };
    
    // Add puzzle-related headers
    if (req.accessLevel === 'master') {
      headers['X-Puzzle-Complete'] = 'true';
      headers['X-Final-Achievement'] = 'FILE_PROCESSING_MASTER_2024';
    }
    
    res.set(headers);
    
    res.json(responseData);
    
  } catch (error) {
    console.error('Archive access error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Failed to access archive system',
      code: 'ARCHIVE_ERROR'
    });
  }
});

// Download specific archive
router.get('/download/:downloadKey', authenticateArchive, async (req, res) => {
  try {
    const { downloadKey } = req.params;
    const archive = archiveContents.find(a => a.downloadKey === downloadKey);
    
    if (!archive) {
      return res.status(404).json({ 
        error: 'Archive not found',
        message: 'The requested archive does not exist',
        code: 'ARCHIVE_NOT_FOUND'
      });
    }
    
    // Check access permissions
    const canAccess = 
      req.accessLevel === 'master' ||
      req.accessLevel === 'admin' ||
      (req.accessLevel === 'user' && !archive.restricted) ||
      (req.accessLevel === 'archive' && archive.downloadKey === downloadKey);
    
    if (!canAccess) {
      return res.status(403).json({ 
        error: 'Access denied',
        message: 'You do not have permission to download this archive',
        code: 'DOWNLOAD_PERMISSION_DENIED'
      });
    }
    
    // Simulate file download (mock)
    res.set({
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${archive.filename}"`,
      'Content-Length': archive.size.toString(),
      'X-Archive-Name': archive.filename,
      'X-Archive-Size': archive.size.toString(),
      'X-Archive-Checksum': archive.checksum,
      'X-Download-Expires': new Date(Date.now() + 3600000).toISOString() // 1 hour
    });
    
    // In a real system, you would stream the actual file
    // For this assessment, return mock download info
    res.json({
      message: 'Archive download initiated',
      archive: {
        filename: archive.filename,
        size: archive.size,
        downloadKey: archive.downloadKey,
        downloadUrl: `/api/archive/download/${archive.downloadKey}/file`,
        // Mock download token (would be JWT in production)
        downloadToken: `mock-token-${Date.now()}-${archive.downloadKey}`,
        expiresAt: new Date(Date.now() + 3600000).toISOString()
      },
      instructions: 'Use the downloadUrl with the downloadToken to download the file',
      note: 'This is a mock implementation. In production, this would stream the actual file.'
    });
    
  } catch (error) {
    console.error('Archive download error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Failed to initiate archive download',
      code: 'DOWNLOAD_ERROR'
    });
  }
});

// Get archive statistics (admin/master only)
router.get('/stats', authenticateArchive, async (req, res) => {
  try {
    if (req.accessLevel !== 'admin' && req.accessLevel !== 'master') {
      return res.status(403).json({ 
        error: 'Permission denied',
        message: 'Admin or master access required for statistics',
        code: 'STATS_ACCESS_DENIED'
      });
    }
    
    const totalSize = archiveContents.reduce((sum, a) => sum + a.size, 0);
    const restrictedCount = archiveContents.filter(a => a.restricted).length;
    const compressedSize = totalSize * 0.75; // Assuming 25% compression
    
    const stats = {
      totalArchives: archiveContents.length,
      totalSize: {
        bytes: totalSize,
        megabytes: (totalSize / (1024 * 1024)).toFixed(2),
        gigabytes: (totalSize / (1024 * 1024 * 1024)).toFixed(2)
      },
      compressedSize: {
        bytes: compressedSize,
        megabytes: (compressedSize / (1024 * 1024)).toFixed(2),
        savingsPercent: '25%'
      },
      byType: {
        zip: archiveContents.filter(a => a.compression === 'zip').length,
        tarGz: archiveContents.filter(a => a.compression === 'tar.gz').length
      },
      byAccess: {
        public: archiveContents.filter(a => !a.restricted).length,
        restricted: restrictedCount
      },
      oldestArchive: archiveContents.reduce((oldest, current) => 
        new Date(current.created) < new Date(oldest.created) ? current : oldest
      ),
      newestArchive: archiveContents.reduce((newest, current) => 
        new Date(current.created) > new Date(newest.created) ? current : newest
      ),
      averageSize: (totalSize / archiveContents.length).toFixed(2)
    };
    
    res.json({
      statistics: stats,
      accessLevel: req.accessLevel,
      timestamp: new Date().toISOString(),
      generatedBy: req.user?.userId || 'system'
    });
    
  } catch (error) {
    console.error('Archive stats error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Failed to retrieve archive statistics',
      code: 'STATS_ERROR'
    });
  }
});

module.exports = router;