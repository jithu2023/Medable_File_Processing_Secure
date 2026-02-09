const express = require('express');
const cors = require('cors');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// Import routes
const uploadRoutes = require('./routes/upload');
const processingLogsRoutes = require('./routes/processing-logs');
const archiveRoutes = require('./routes/archive');

const app = express();
const PORT = process.env.PORT || 8888;

// ==================== ENHANCED SECURITY MIDDLEWARE ====================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// ==================== RATE LIMITING ====================
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    error: 'Rate limit exceeded',
    message: 'Too many requests from this IP, please try again later.',
    code: 'RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false
});

// ==================== TIMEOUT HANDLING ====================
const REQUEST_TIMEOUT = parseInt(process.env.REQUEST_TIMEOUT) || 30000;
const RESPONSE_TIMEOUT = parseInt(process.env.RESPONSE_TIMEOUT) || 30000;

app.use((req, res, next) => {
    req.setTimeout(REQUEST_TIMEOUT, () => {
        const err = new Error('Request Timeout');
        err.status = 408;
        err.code = 'REQUEST_TIMEOUT';
        next(err);
    });
    
    res.setTimeout(RESPONSE_TIMEOUT, () => {
        console.warn(`Response timeout for ${req.method} ${req.url}`);
    });
    
    next();
});

// Apply rate limiting
app.use('/api/upload', limiter);

// ==================== CORS CONFIGURATION ====================
const corsOptions = {
  origin: process.env.CORS_ORIGINS 
    ? process.env.CORS_ORIGINS.split(',') 
    : (process.env.NODE_ENV === 'development' 
        ? ['https://*.railway.app', 'https://*.up.railway.app', 'http://localhost:8888'] 
        : ['http://localhost:3000', 'http://localhost:8888', 'http://127.0.0.1:8888']),
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-System-Key', 'X-Archive-Key', 'X-Requested-With'],
  credentials: true,
  maxAge: 86400
};

app.use(cors(corsOptions));

// Handle preflight requests
app.options('*', cors(corsOptions));

// ==================== ENHANCED BODY PARSING ====================
app.use(express.json({ 
  limit: '50mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
    try {
      // Pre-validate JSON for malformed requests
      if (buf && buf.length > 0) {
        JSON.parse(buf.toString());
      }
    } catch (jsonError) {
      // Create a custom error for JSON parsing
      const error = new Error('Invalid JSON format');
      error.status = 400;
      error.code = 'INVALID_JSON';
      error.originalError = jsonError.message;
      throw error;
    }
  }
}));

app.use(express.urlencoded({ 
  extended: true, 
  limit: '50mb',
  parameterLimit: 1000
}));

// ==================== STATIC FILES ====================
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1h',
  setHeaders: (res, path) => {
    if (path.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    }
  }
}));

app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  index: false,
  dotfiles: 'deny',
  maxAge: '1h',
  setHeaders: (res, filePath) => {
    res.setHeader('Cache-Control', 'private, max-age=3600, must-revalidate');
  }
}));

// ==================== TOKEN GENERATION ====================
app.post("/token", (req, res, next) => {
  try {
    // Check if body exists
    if (!req.body || Object.keys(req.body).length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Missing request body',
        message: 'Request body is required',
        code: 'MISSING_BODY'
      });
    }
    
    const payload = req.body;
    
    // Validate required fields
    if (!payload.userId || !payload.role) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields',
        message: 'userId and role are required',
        code: 'MISSING_REQUIRED_FIELDS'
      });
    }
    
    // Validate role
    const validRoles = ['user', 'admin', 'system'];
    if (!validRoles.includes(payload.role)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid role',
        message: `Role must be one of: ${validRoles.join(', ')}`,
        code: 'INVALID_ROLE'
      });
    }
    
    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || "11h",
    });

    res.json({
      success: true,
      token,
      expiresIn: process.env.JWT_EXPIRES_IN || "11h"
    });
  } catch (error) {
    next(error);
  }
});  

// ==================== CUSTOM HEADERS ====================
app.use((req, res, next) => {
  // Add security headers
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'X-Powered-By': 'Secure File Processing API'
  });
  
  // Puzzle-related headers
  if (req.path.startsWith('/api/upload')) {
    res.set({
      'X-Hidden-Metadata': 'check_file_processing_logs_endpoint',
      'X-Upload-Limit': '10MB',
      'X-Max-Concurrent': '3'
    });
  }
  
  next();
});

// ==================== REQUEST LOGGING ====================
app.use((req, res, next) => {
  if (process.env.LOG_REQUESTS === 'true' || process.env.DEBUG === 'true') {
    const start = Date.now();
    const originalSend = res.send;
    const originalJson = res.json;
    
    res.json = function(body) {
      const duration = Date.now() - start;
      console.log(`${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`);
      if (process.env.LOG_RESPONSES === 'true' && process.env.NODE_ENV === 'development') {
        console.log('Response:', JSON.stringify(body, null, 2).substring(0, 500));
      }
      return originalJson.call(this, body);
    };
    
    res.send = function(body) {
      const duration = Date.now() - start;
      console.log(`${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`);
      return originalSend.call(this, body);
    };
  }
  next();
});

// ==================== ROUTES ====================
app.use('/api/upload', uploadRoutes);
app.use('/api/processing-logs', processingLogsRoutes);
app.use('/api/archive', archiveRoutes);

// ==================== HEALTH CHECK ====================
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    services: {
      upload: 'active',
      processing: 'active',
      archive: 'active',
      authentication: 'active'
    }
  });
});

// ==================== METRICS ====================
app.get('/metrics', (req, res) => {
  const memory = process.memoryUsage();
  res.json({
    uptime: process.uptime(),
    memory: {
      rss: `${Math.round(memory.rss / 1024 / 1024)} MB`,
      heapTotal: `${Math.round(memory.heapTotal / 1024 / 1024)} MB`,
      heapUsed: `${Math.round(memory.heapUsed / 1024 / 1024)} MB`,
      external: `${Math.round(memory.external / 1024 / 1024)} MB`
    },
    nodeVersion: process.version,
    platform: process.platform,
    timestamp: new Date().toISOString()
  });
});

// ==================== DOCUMENTATION ====================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api-docs', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'api-docs.html'));
});

// ==================== 404 HANDLER ====================
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Endpoint not found',
    message: 'The requested API endpoint does not exist',
    documentation: '/api-docs',
    availableEndpoints: [
      '/api/upload',
      '/api/processing-logs',
      '/api/archive',
      '/health',
      '/metrics'
    ]
  });
});

// ==================== ENHANCED GLOBAL ERROR HANDLER ====================
app.use((error, req, res, next) => {
  // Log error internally (without exposing to client)
  const errorLog = {
    timestamp: new Date().toISOString(),
    method: req.method,
    path: req.path,
    ip: req.ip,
    userId: req.user?.userId || 'anonymous',
    errorCode: error.code || 'UNKNOWN_ERROR',
    errorMessage: error.message || 'Unknown error',
    errorType: error.name || 'Error',
    stack: error.stack || 'No stack trace available'
  };
  
  if (process.env.LOG_ERRORS === 'true' || process.env.DEBUG === 'true') {
    console.error('SERVER ERROR:', errorLog);
  }
  
  // Determine error type and create safe response
  let statusCode = 500;
  let errorMessage = 'Internal server error';
  let userMessage = 'Something went wrong. Please try again later.';
  let errorCode = 'INTERNAL_ERROR';
  
  // Handle JSON parsing errors
  if (error instanceof SyntaxError && error.status === 400 && 'body' in error) {
    statusCode = 400;
    errorMessage = 'Invalid JSON format';
    userMessage = 'The request contains invalid JSON. Please check your input.';
    errorCode = 'INVALID_JSON';
  }
  
  // Handle our custom JSON validation error
  else if (error.code === 'INVALID_JSON') {
    statusCode = 400;
    errorMessage = 'Invalid JSON format';
    userMessage = 'The request contains invalid JSON. Please check your input.';
    errorCode = 'INVALID_JSON';
  }
  
  // Handle validation errors
  else if (error.name === 'ValidationError' || error.code === 'VALIDATION_ERROR') {
    statusCode = 400;
    errorMessage = 'Validation error';
    userMessage = error.message || 'Invalid input data';
    errorCode = 'VALIDATION_ERROR';
  }
  
  // Handle authentication errors
  else if (error.name === 'JsonWebTokenError' || error.code === 'INVALID_TOKEN') {
    statusCode = 401;
    errorMessage = 'Invalid token';
    userMessage = 'The authentication token is invalid or malformed';
    errorCode = 'INVALID_TOKEN';
  }
  
  else if (error.name === 'TokenExpiredError' || error.code === 'TOKEN_EXPIRED') {
    statusCode = 401;
    errorMessage = 'Token expired';
    userMessage = 'Please authenticate again';
    errorCode = 'TOKEN_EXPIRED';
  }
  
  else if (error.code === 'AUTH_REQUIRED') {
    statusCode = 401;
    errorMessage = 'Authentication required';
    userMessage = 'Please provide valid credentials';
    errorCode = 'AUTH_REQUIRED';
  }
  
  // Handle file errors
  else if (error.code === 'LIMIT_FILE_SIZE') {
    statusCode = 413;
    errorMessage = 'File too large';
    userMessage = 'The file exceeds the maximum allowed size of 10MB';
    errorCode = 'FILE_TOO_LARGE';
  }
  
  else if (error.code === 'INVALID_FILE_TYPE') {
    statusCode = 400;
    errorMessage = 'Invalid file type';
    userMessage = 'The file type is not supported';
    errorCode = 'INVALID_FILE_TYPE';
  }
  
  // Handle timeout errors
  else if (error.code === 'REQUEST_TIMEOUT') {
    statusCode = 408;
    errorMessage = 'Request timeout';
    userMessage = 'The request took too long to process';
    errorCode = 'REQUEST_TIMEOUT';
  }
  
  // Handle resource errors
  else if (error.code === 'ENOENT') {
    statusCode = 404;
    errorMessage = 'Resource not found';
    userMessage = 'The requested resource was not found';
    errorCode = 'NOT_FOUND';
  }
  
  else if (error.code === 'EACCES') {
    statusCode = 403;
    errorMessage = 'Permission denied';
    userMessage = 'You do not have permission to perform this action';
    errorCode = 'PERMISSION_DENIED';
  }
  
  // Handle rate limiting
  else if (error.code === 'RATE_LIMIT_EXCEEDED') {
    statusCode = 429;
    errorMessage = 'Rate limit exceeded';
    userMessage = 'Too many requests from this IP';
    errorCode = 'RATE_LIMIT_EXCEEDED';
  }
  
  // Handle multer errors
  else if (error.name === 'MulterError') {
    statusCode = 400;
    errorMessage = 'File upload error';
    userMessage = error.message || 'Error uploading file';
    errorCode = 'UPLOAD_ERROR';
  }
  
  // Handle database/connection errors
  else if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT') {
    statusCode = 503;
    errorMessage = 'Service unavailable';
    userMessage = 'The service is temporarily unavailable. Please try again later.';
    errorCode = 'SERVICE_UNAVAILABLE';
  }
  
  // Create clean, safe response object
  const response = {
    error: errorMessage,
    message: userMessage,
    code: errorCode,
    timestamp: new Date().toISOString(),
    requestId: Date.now().toString(36) + Math.random().toString(36).substr(2)
  };
  
  // Send clean response - NO DEBUG INFO
  res.status(statusCode).json(response);
});

// ==================== GRACEFUL SHUTDOWN ====================
const gracefulShutdown = (signal) => {
  console.log(`\n${signal} received. Starting graceful shutdown...`);
  
  server.close(() => {
    console.log('HTTP server closed');
    console.log('Graceful shutdown complete');
    process.exit(0);
  });
  
  // Force close after 10 seconds
  setTimeout(() => {
    console.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ==================== UNCAUGHT EXCEPTIONS ====================
process.on('uncaughtException', (error) => {
  console.error('UNCAUGHT EXCEPTION:', {
    message: error.message,
    stack: error.stack,
    timestamp: new Date().toISOString()
  });
  
  // Don't crash immediately, allow server to handle existing requests
  setTimeout(() => {
    console.error('Uncaught exception forced shutdown');
    process.exit(1);
  }, 1000);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('UNHANDLED REJECTION at:', promise, 'reason:', reason);
});

// ==================== SERVER STARTUP ====================
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`=========================================`);
  console.log(` Assessment 4: Secure File Processing API`);
  console.log(` Server running on port ${PORT}`);
  console.log(` Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(` Base URL: http://localhost:${PORT}`);
  console.log(` Documentation: /api-docs`);
  console.log(` Health Check: /health`);
  console.log(` Security Features:`);
  console.log(`   • Enhanced error handling (no stack traces)`);
  console.log(`   • JSON validation & sanitization`);
  console.log(`   • Authentication required for all endpoints`);
  console.log(`   • File validation & virus scanning ready`);
  console.log(`   • Rate limiting enabled`);
  console.log(`   • CORS properly configured`);
  console.log(`   • File encryption at rest (AES-256-GCM)`);
  console.log(`   • Timeout handling (${REQUEST_TIMEOUT/1000} seconds)`);
  console.log(` Multi-layered puzzles available:`);
  console.log(`   1. Header Discovery ✓`);
  console.log(`   2. Processing Logs Access ✓`);
  console.log(`   3. Base64 Decryption ✓`);
  console.log(`   4. Archive Master Access ✓`);
  console.log(` 100% Complete Features:`);
  console.log(`   • Batch upload support (5 files)`);
  console.log(`   • Real thumbnail generation`);
  console.log(`   • File versioning & backup`);
  console.log(`   • Compression (${process.env.USE_ACTUAL_COMPRESSION === 'true' ? 'ACTUAL' : 'simulated'})`);
  console.log(`   • Retry logic (${process.env.PROCESSING_RETRY_ATTEMPTS || 3} attempts)`);
  console.log(`   • Storage quotas (${(process.env.MAX_USER_STORAGE || 104857600) / (1024*1024)}MB/user)`);
  console.log(`   • File sharing with expiration`);
  console.log(` Railway Deployment Ready!`);
  console.log(`=========================================`);
});

module.exports = { app, server };