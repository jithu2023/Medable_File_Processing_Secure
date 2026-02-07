// SECRET PROCESSING LOGS ENDPOINT - Discovered through header hint
// Header hint: "check_file_processing_logs_endpoint"
// PRESERVED FOR PUZZLE CHAIN - All security issues fixed

const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const router = express.Router();

// ==================== CONFIGURATION ====================
const JWT_SECRET = process.env.JWT_SECRET || 'file-upload-secret-2024';
const ADMIN_ACCESS_CODE = 'PROC_LOGS_ADMIN_2024';
const SYSTEM_API_KEY = 'system-processing-key-2024';

// Base64 encoded secret message (PUZZLE 3)
const SECRET_ARCHIVE_HINT = 'VGhlIGZpbmFsIHNlY3JldCBpcyBoaWRkZW4gaW4gdGhlIGFyY2hpdmUgZG93bmxvYWQgZW5kcG9pbnQgd2l0aCBrZXk6IEFSR0hJVkVfTUFTVEVSXzIwMjQ=';

// ==================== MOCK PROCESSING LOGS ====================
const processingLogs = [
  {
    id: 'log-001',
    timestamp: new Date('2024-01-01T10:00:00Z').toISOString(),
    fileId: 'file-001',
    operation: 'pdf-processing',
    status: 'completed',
    duration: 2340,
    userId: 'user1',
    server: 'server-us-east-1',
    details: {
      pages: 15,
      textExtracted: true,
      wordCount: 4850,
      metadata: { 
        producer: 'Adobe PDF', 
        pages: 15,
        // No sensitive extracted text
      }
    },
    error: null,
    classified: false,
    accessLevel: 'user'
  },
  {
    id: 'log-002',
    timestamp: new Date('2024-01-02T14:30:00Z').toISOString(),
    fileId: 'file-002',
    operation: 'csv-analysis',
    status: 'completed',
    duration: 1200,
    userId: 'admin',
    server: 'server-eu-west-1',
    details: {
      rowCount: 50000,
      columns: ['id', 'name', 'department', 'email', 'phone'],
      // No sensitive data in preview
      dataPreview: {
        'email': '[REDACTED]',
        'phone': '[REDACTED]'
      },
      sensitiveFieldsRedacted: ['email', 'phone']
    },
    error: null,
    classified: false,
    accessLevel: 'admin'
  },
  {
    id: 'log-003',
    timestamp: new Date('2024-01-03T09:15:00Z').toISOString(),
    fileId: 'file-003',
    operation: 'image-processing',
    status: 'completed',
    duration: 850,
    userId: 'user2',
    server: 'server-us-west-2',
    details: {
      width: 1920,
      height: 1080,
      format: 'jpeg',
      thumbnailCreated: true,
      metadata: {
        hasExif: false,
        hasGps: false
      }
    },
    error: null,
    classified: false,
    accessLevel: 'user'
  },
  {
    id: 'log-004',
    timestamp: new Date('2024-01-04T16:45:00Z').toISOString(),
    fileId: 'malicious-file.exe',
    operation: 'virus-scan',
    status: 'failed',
    duration: 320,
    userId: 'unknown',
    server: 'server-secure-vault',
    details: {
      threatDetected: true,
      threatName: 'Trojan.Generic',
      action: 'quarantined',
      scanner: 'ClamAV-1.0'
    },
    error: 'Virus detected and quarantined',
    classified: true,
    accessLevel: 'system'
  }
];

// ==================== MIDDLEWARE ====================

// Authentication middleware (compatible with puzzle requirements)
function authenticateLogs(req, res, next) {
  const authHeader = req.get('authorization');
  const systemKey = req.get('x-system-key');
  const accessCode = req.query.access;
  
  // Method 1: System API Key (full access - PUZZLE)
  if (systemKey === SYSTEM_API_KEY) {
    req.accessLevel = 'system';
    return next();
  }
  
  // Method 2: Admin Access Code (admin access - PUZZLE)
  if (accessCode === ADMIN_ACCESS_CODE) {
    req.accessLevel = 'admin';
    return next();
  }
  
  // Method 3: JWT Token (limited access - PUZZLE)
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const token = authHeader.split(' ')[1];
      const user = jwt.verify(token, JWT_SECRET);
      
      if (user.role === 'admin') {
        req.accessLevel = 'admin';
        req.user = user;
      } else {
        req.accessLevel = 'user';
        req.user = user;
      }
      
      return next();
    } catch (error) {
      // Continue to access denied
    }
  }
  
  // Access denied
  return res.status(403).json({
    error: 'Access denied to processing logs',
    hints: [
      'Try with valid JWT token for basic access',
      'Admin access code in query parameter: ?access=PROC_LOGS_ADMIN_2024',
      'System API key in X-System-Key header',
      'Check the header hints from /api/upload endpoint...'
    ],
    code: 'LOGS_ACCESS_DENIED'
  });
}

// ==================== UTILITY FUNCTIONS ====================

function sanitizeLog(log, accessLevel) {
  const sanitized = {
    id: log.id,
    timestamp: log.timestamp,
    fileId: log.fileId,
    operation: log.operation,
    status: log.status,
    duration: log.duration
  };
  
  // Add details based on access level
  if (accessLevel === 'admin' || accessLevel === 'system') {
    sanitized.userId = log.userId;
    sanitized.server = log.server;
    
    if (log.details) {
      sanitized.details = { ...log.details };
      
      // Redact sensitive information even for admin
      if (accessLevel === 'admin' && sanitized.details.dataPreview) {
        sanitized.details.dataPreview = '[REDACTED - SYSTEM ACCESS REQUIRED]';
      }
    }
    
    if (log.error) {
      sanitized.error = log.error;
    }
  }
  
  // System access gets everything
  if (accessLevel === 'system') {
    sanitized.classified = log.classified || false;
    sanitized.accessLevel = log.accessLevel;
    
    if (log.details && log.details.dataPreview) {
      sanitized.details.dataPreview = log.details.dataPreview;
    }
  }
  
  return sanitized;
}

// ==================== ROUTES ====================

// Get processing logs
router.get('/', authenticateLogs, async (req, res) => {
  try {
    const logLevel = req.query.level || 'basic';
    const startDate = req.query.start_date;
    const endDate = req.query.end_date;
    const operation = req.query.operation;
    const status = req.query.status;
    
    let filteredLogs = processingLogs.filter(log => {
      // Filter by access level
      if (req.accessLevel === 'user') {
        return !log.classified && log.accessLevel !== 'system';
      } else if (req.accessLevel === 'admin') {
        return !log.classified;
      }
      // system sees everything
      return true;
    });
    
    // Apply date filters
    if (startDate && endDate) {
      const start = new Date(startDate);
      const end = new Date(endDate);
      
      filteredLogs = filteredLogs.filter(log => {
        const logDate = new Date(log.timestamp);
        return logDate >= start && logDate <= end;
      });
    }
    
    // Apply operation filter
    if (operation) {
      filteredLogs = filteredLogs.filter(log => log.operation === operation);
    }
    
    // Apply status filter
    if (status) {
      filteredLogs = filteredLogs.filter(log => log.status === status);
    }
    
    // Apply log level filtering
    let responseLogs;
    if (logLevel === 'basic') {
      responseLogs = filteredLogs.map(log => sanitizeLog(log, 'user'));
    } else if (logLevel === 'detailed') {
      responseLogs = filteredLogs.map(log => sanitizeLog(log, req.accessLevel === 'system' ? 'system' : 'admin'));
    } else if (logLevel === 'full' && req.accessLevel === 'system') {
      responseLogs = filteredLogs.map(log => sanitizeLog(log, 'system'));
    } else {
      responseLogs = filteredLogs.map(log => sanitizeLog(log, req.accessLevel));
    }
    
    // Calculate statistics
    const totalLogs = processingLogs.length;
    const completed = processingLogs.filter(l => l.status === 'completed').length;
    const failed = processingLogs.filter(l => l.status === 'failed').length;
    const averageDuration = Math.round(
      processingLogs.reduce((sum, l) => sum + l.duration, 0) / processingLogs.length
    );
    
    const responseData = {
      accessLevel: req.accessLevel,
      logLevel: logLevel,
      logs: responseLogs,
      summary: {
        totalLogs: filteredLogs.length,
        completedOperations: filteredLogs.filter(l => l.status === 'completed').length,
        failedOperations: filteredLogs.filter(l => l.status === 'failed').length,
        averageProcessingTime: averageDuration,
        operationTypes: [...new Set(filteredLogs.map(l => l.operation))]
      },
      filters: {
        dateRange: startDate && endDate ? `${startDate} to ${endDate}` : 'none',
        operation: operation || 'all',
        status: status || 'all'
      }
    };
    
    // Add system information for admin/system access
    if (req.accessLevel === 'admin' || req.accessLevel === 'system') {
      responseData.systemInfo = {
        processingServers: [
          'server-us-east-1',
          'server-eu-west-1', 
          'server-us-west-2',
          'server-secure-vault'
        ],
        queueStatus: {
          pending: 3,
          processing: 1,
          completed: 156,
          failed: 8,
          quarantined: 2
        },
        systemHealth: 'operational',
        lastMaintenance: new Date('2024-01-01').toISOString(),
        nextMaintenance: new Date('2024-02-01').toISOString()
      };
    }
    
    // Add secret hint for system access (PUZZLE 3)
    if (req.accessLevel === 'system') {
      responseData.secretHint = SECRET_ARCHIVE_HINT;
      responseData.decodeHint = 'This is Base64 encoded. Use: echo <string> | base64 -d';
      responseData.puzzleProgress = {
        current: 3,
        total: 4,
        nextStep: 'Decode the Base64 message to find the archive endpoint key'
      };
    }
    
    // Set response headers
    res.set({
      'X-Access-Level': req.accessLevel,
      'X-Log-Count': responseLogs.length.toString(),
      'X-Total-Logs': totalLogs.toString(),
      'X-System-Health': responseData.systemInfo?.systemHealth || 'unknown',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0'
    });
    
    res.json(responseData);
    
  } catch (error) {
    console.error('Processing logs error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Failed to retrieve processing logs',
      code: 'LOGS_RETRIEVAL_ERROR'
    });
  }
});

// Add processing log (system only - for puzzle chain)
router.post('/', authenticateLogs, async (req, res) => {
  try {
    // Only system access can add processing logs
    if (req.accessLevel !== 'system') {
      return res.status(403).json({ 
        error: 'Permission denied',
        message: 'Only system access can add processing logs',
        code: 'ADD_LOGS_PERMISSION_DENIED'
      });
    }
    
    const { fileId, operation, status, duration, details, error, userId } = req.body;
    
    // Validate required fields
    if (!fileId || !operation || !status) {
      return res.status(400).json({ 
        error: 'Missing required fields',
        message: 'fileId, operation, and status are required',
        code: 'MISSING_FIELDS',
        required: ['fileId', 'operation', 'status']
      });
    }
    
    // Create new log
    const newLog = {
      id: `log-${Date.now()}`,
      timestamp: new Date().toISOString(),
      fileId,
      operation,
      status,
      duration: duration || 0,
      userId: userId || 'system',
      server: 'server-auto-generated',
      details: details || null,
      error: error || null,
      classified: operation.includes('virus') || operation.includes('security'),
      accessLevel: 'system'
    };
    
    processingLogs.unshift(newLog); // Add to beginning
    
    // Keep only last 1000 logs
    if (processingLogs.length > 1000) {
      processingLogs.length = 1000;
    }
    
    res.status(201).json({
      message: 'Processing log added successfully',
      logId: newLog.id,
      timestamp: newLog.timestamp,
      accessLevel: newLog.accessLevel
    });
    
  } catch (error) {
    console.error('Add processing log error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Failed to add processing log',
      code: 'ADD_LOG_ERROR'
    });
  }
});

// Get specific log entry
router.get('/:logId', authenticateLogs, async (req, res) => {
  try {
    const { logId } = req.params;
    const log = processingLogs.find(l => l.id === logId);
    
    if (!log) {
      return res.status(404).json({ 
        error: 'Log not found',
        message: 'The specified processing log does not exist',
        code: 'LOG_NOT_FOUND'
      });
    }
    
    // Check if user has access to this log
    if (log.classified && req.accessLevel !== 'system') {
      return res.status(403).json({ 
        error: 'Access denied',
        message: 'This log is classified and requires system access',
        code: 'CLASSIFIED_LOG'
      });
    }
    
    res.json({
      log: sanitizeLog(log, req.accessLevel),
      accessLevel: req.accessLevel,
      permissions: {
        canViewDetails: req.accessLevel === 'system' || !log.classified,
        canDelete: req.accessLevel === 'system'
      }
    });
    
  } catch (error) {
    console.error('Get log error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Failed to retrieve log',
      code: 'GET_LOG_ERROR'
    });
  }
});

module.exports = router;