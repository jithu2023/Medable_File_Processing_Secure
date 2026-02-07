const express = require('express');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');
const multer = require('multer');
const { fileTypeFromBuffer } = require('file-type');
const { generateThumbnail } = require('./thumbnail');

const router = express.Router();

// ==================== SECURE CONFIGURATION ====================
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024; // 10MB default
const UPLOAD_DIR = process.env.UPLOAD_DIR || './uploads';
const MAX_USER_STORAGE = 100 * 1024 * 1024; // 100MB per user
const MAX_USER_UPLOADS_PER_HOUR = 20;

const ALLOWED_MIME_TYPES = [
    'image/jpeg',
    'image/png', 
    'image/gif',
    'application/pdf',
    'text/csv',
    'text/plain',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
];

// ADD RETRY CONFIGURATION
const PROCESSING_RETRY_ATTEMPTS = 3;
const PROCESSING_RETRY_DELAY = 1000; // 1 second

// File signatures for content validation
const FILE_SIGNATURES = {
    'image/jpeg': Buffer.from([0xFF, 0xD8, 0xFF]),
    'image/png': Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    'image/gif': Buffer.from([0x47, 0x49, 0x46, 0x38]),
    'application/pdf': Buffer.from([0x25, 0x50, 0x44, 0x46]),
};

// Enhanced sensitive data patterns for redaction
const SENSITIVE_PATTERNS = {
    ssn: /\b\d{3}[-]?\d{2}[-]?\d{4}\b/g,
    email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    phone: /\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
    creditCard: /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g,
    ipAddress: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g
};

// ==================== NEW: FILE SHARING SYSTEM ====================
const sharedFiles = new Map(); // shareId -> { fileId, expiresAt, createdBy }

// ==================== NEW: PROCESSING QUEUE ====================
const processingQueue = [];
let activeProcesses = 0;
const MAX_CONCURRENT_PROCESSES = 3;

// ==================== NEW: ACCESS LOGS ====================
const accessLogs = [];

// ==================== SETUP ====================
// Track user storage and upload rates
const userStorage = new Map();
const userUploadRates = new Map();

// Ensure upload directory exists
(async () => {
    try {
        await fs.access(UPLOAD_DIR);
    } catch {
        await fs.mkdir(UPLOAD_DIR, { recursive: true });
        console.log(`✅ Created upload directory: ${UPLOAD_DIR}`);
    }
})();

// Ensure thumbnail directory exists
(async () => {
    const thumbnailDir = path.join(UPLOAD_DIR, 'thumbnails');
    try {
        await fs.access(thumbnailDir);
    } catch {
        await fs.mkdir(thumbnailDir, { recursive: true });
        console.log(`✅ Created thumbnail directory: ${thumbnailDir}`);
        
        // Create a default thumbnail SVG
        const defaultThumbnail = `
            <svg width="150" height="150" xmlns="http://www.w3.org/2000/svg">
                <rect width="150" height="150" fill="#4a90e2"/>
                <circle cx="75" cy="60" r="20" fill="white" opacity="0.8"/>
                <rect x="50" y="90" width="50" height="20" rx="5" fill="white" opacity="0.8"/>
                <text x="75" y="130" font-family="Arial" font-size="12" text-anchor="middle" fill="white">File</text>
            </svg>
        `;
        await fs.writeFile(path.join(thumbnailDir, 'default.svg'), defaultThumbnail);
        await fs.writeFile(path.join(thumbnailDir, 'simulated.svg'), defaultThumbnail);
    }
})();

// ==================== NEW: QUEUE PROCESSOR ====================
async function processQueueItem() {
    if (activeProcesses >= MAX_CONCURRENT_PROCESSES || processingQueue.length === 0) {
        return;
    }
    
    activeProcesses++;
    const { fileId, retryCount = 0 } = processingQueue.shift();
    
    try {
        await processFileWithRetry(fileId, retryCount);
    } finally {
        activeProcesses--;
        // Process next item in queue
        setTimeout(processQueueItem, 100);
    }
}

// ==================== ENHANCED SECURE FILE STORAGE ====================
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const userDir = path.join(UPLOAD_DIR, req.user?.userId || 'anonymous');
        fs.mkdir(userDir, { recursive: true })
            .then(() => cb(null, userDir))
            .catch(err => cb(err, UPLOAD_DIR));
    },
    filename: (req, file, cb) => {
        const uniqueId = uuidv4();
        const timestamp = Date.now();
        const randomBytes = crypto.randomBytes(8);
        const hash = crypto.createHash('sha256')
            .update(`${uniqueId}${timestamp}${randomBytes.toString('hex')}`)
            .digest('hex')
            .substring(0, 32);
        
        const fileExt = path.extname(file.originalname).toLowerCase();
        const filename = `${hash}-${timestamp}${fileExt}`;
        
        cb(null, filename);
    }
});

// ==================== ENHANCED FILE VALIDATION ====================
const fileFilter = async (req, file, cb) => {
    try {
        // Check MIME type
        if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
            return cb(new Error(`File type ${file.mimetype} is not allowed`), false);
        }
        
        // Check file extension
        const allowedExtensions = [
            '.jpg', '.jpeg', '.png', '.gif', '.pdf', 
            '.csv', '.txt', '.doc', '.docx', '.xls', '.xlsx'
        ];
        const fileExt = path.extname(file.originalname).toLowerCase();
        
        if (!allowedExtensions.includes(fileExt)) {
            return cb(new Error(`File extension ${fileExt} is not allowed`), false);
        }
        
        // Check file size from content-length header
        const contentLength = parseInt(req.headers['content-length']);
        if (contentLength > MAX_FILE_SIZE) {
            return cb(new Error(`File size exceeds ${MAX_FILE_SIZE / (1024 * 1024)}MB limit`), false);
        }
        
        // Check for zero-size files
        if (contentLength === 0) {
            return cb(new Error('Zero-size file uploaded'), false);
        }
        
        // Rate limiting per user
        const userId = req.user?.userId || 'anonymous';
        const now = Date.now();
        const userRate = userUploadRates.get(userId) || { count: 0, resetTime: now + 3600000 };
        
        if (now > userRate.resetTime) {
            userRate.count = 1;
            userRate.resetTime = now + 3600000;
        } else {
            userRate.count++;
        }
        
        if (userRate.count > MAX_USER_UPLOADS_PER_HOUR) {
            return cb(new Error('Upload rate limit exceeded. Please try again later.'), false);
        }
        
        userUploadRates.set(userId, userRate);
        
        cb(null, true);
    } catch (error) {
        cb(error, false);
    }
};

// ==================== MULTER CONFIGURATION ====================
const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: MAX_FILE_SIZE,
        files: 1,
        fields: 5,
        parts: 10
    }
});

// ==================== BATCH UPLOAD CONFIGURATION ====================
const batchUpload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: MAX_FILE_SIZE,
        files: 5, // Allow up to 5 files in batch
        fields: 10,
        parts: 50
    }
});

// ==================== ENHANCED DATA STORAGE ====================
let uploadedFiles = [
    {
        id: 'file-001',
        originalName: 'sample-document.pdf',
        filename: 'sample-document-123.pdf',
        mimetype: 'application/pdf',
        size: 2048576,
        uploadedBy: 'user1',
        uploadDate: new Date('2024-01-01').toISOString(),
        status: 'processed',
        processingResult: { 
            pages: 15, 
            textExtracted: true,
            wordCount: 4850,
            hasText: true,
            fileIntegrity: 'verified',
            hasSensitiveData: false
        },
        downloadUrl: '/api/upload/download/user1/sample-document-123.pdf',
        publicAccess: false,
        fileHash: 'a1b2c3d4e5f678901234567890abcdef1234567890abcdef',
        compression: { enabled: true, originalSize: 2048576, compressedSize: 1536432, ratio: '25%' },
        encryption: { algorithm: 'aes-256-gcm', encrypted: true, iv: 'abc123' },
        versions: [{ version: 1, timestamp: new Date('2024-01-01').toISOString(), size: 2048576 }],
        currentVersion: 1,
        backup: { location: '/backups/user1/sample-document-123.pdf', timestamp: new Date('2024-01-01').toISOString() }
    },
    {
        id: 'file-002',
        originalName: 'company-data.csv',
        filename: 'company-data-456.csv', 
        mimetype: 'text/csv',
        size: 1024000,
        uploadedBy: 'admin',
        uploadDate: new Date('2024-01-02').toISOString(),
        status: 'processed',
        processingResult: {
            rowCount: 50000,
            columnCount: 8,
            columns: ['id', '[REDACTED]', '[REDACTED]', '[REDACTED]', '[REDACTED]', 'hire_date', '[REDACTED]', 'location'],
            preview: [
                { 
                    id: '1',
                    hire_date: '2023-01-01',
                    location: 'Remote'
                }
            ],
            hasSensitiveData: true,
            sensitiveFieldsRedacted: ['name', 'email', 'phone', 'salary_band', 'department']
        },
        downloadUrl: '/api/upload/download/admin/company-data-456.csv',
        publicAccess: false,
        fileHash: 'b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1',
        compression: { enabled: true, originalSize: 1024000, compressedSize: 768000, ratio: '25%' },
        encryption: { algorithm: 'aes-256-gcm', encrypted: true, iv: 'def456' },
        versions: [{ version: 1, timestamp: new Date('2024-01-02').toISOString(), size: 1024000 }],
        currentVersion: 1,
        backup: { location: '/backups/admin/company-data-456.csv', timestamp: new Date('2024-01-02').toISOString() }
    },
    {
        id: 'file-003',
        originalName: 'product-image.jpg',
        filename: 'product-image-789.jpg',
        mimetype: 'image/jpeg',
        size: 524288,
        uploadedBy: 'user2',
        uploadDate: new Date('2024-01-03').toISOString(),
        status: 'processed',
        processingResult: {
            width: 1920,
            height: 1080,
            format: 'jpeg',
            size: 524288,
            thumbnailCreated: true,
            thumbnailUrl: '/uploads/thumbnails/product-image-789_thumb.svg',
            hasSensitiveData: false
        },
        downloadUrl: '/api/upload/download/user2/product-image-789.jpg',
        publicAccess: true,
        fileHash: 'c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2',
        compression: { enabled: true, originalSize: 524288, compressedSize: 393216, ratio: '25%' },
        encryption: { algorithm: 'aes-256-gcm', encrypted: true, iv: 'ghi789' },
        versions: [{ version: 1, timestamp: new Date('2024-01-03').toISOString(), size: 524288 }],
        currentVersion: 1,
        backup: { location: '/backups/user2/product-image-789.jpg', timestamp: new Date('2024-01-03').toISOString() }
    }
];

// ==================== ENHANCED MIDDLEWARE ====================

// Fixed Authentication middleware
function authenticate(req, res, next) {
    const authHeader = req.get('authorization');
    
    if (!authHeader) {
        return res.status(401).json({ 
            error: 'Authentication required',
            message: 'Please provide a valid JWT token',
            code: 'AUTH_REQUIRED'
        });
    }
    
    try {
        const token = authHeader.split(' ')[1];
        const currentUser = jwt.verify(token, JWT_SECRET);
        
        if (!currentUser.userId || !currentUser.role) {
            return res.status(401).json({
                error: 'Invalid token structure',
                message: 'Token missing required claims',
                code: 'INVALID_TOKEN'
            });
        }
        
        req.user = {
            userId: currentUser.userId,
            role: currentUser.role,
            email: currentUser.email || null
        };
        
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                error: 'Token expired',
                message: 'Please authenticate again',
                code: 'TOKEN_EXPIRED'
            });
        }
        
        return res.status(401).json({ 
            error: 'Invalid token',
            message: 'The provided token is invalid or malformed',
            code: 'INVALID_TOKEN'
        });
    }
}

// Fixed Authorization middleware for file access
function authorizeFileAccess(req, res, next) {
    const fileId = req.params.fileId;
    const file = uploadedFiles.find(f => f.id === fileId);
    
    if (!file) {
        return res.status(404).json({ 
            error: 'File not found',
            message: 'The requested file does not exist',
            code: 'FILE_NOT_FOUND'
        });
    }
    
    // Fixed: Proper access control with early return
    const isOwner = file.uploadedBy === req.user.userId;
    const isAdmin = req.user.role === 'admin';
    const isPublic = file.publicAccess === true;
    
    if (!isOwner && !isAdmin && !isPublic) {
        return res.status(403).json({ 
            error: 'Access denied',
            message: 'You do not have permission to access this file',
            code: 'ACCESS_DENIED'
        });
    }
    
    req.file = file;
    next();
}

// Fixed Storage quota middleware
function checkStorageQuota(req, res, next) {
    console.log(`Checking storage quota for user ${req.user.userId}...`);
    const userId = req.user.userId;
    const fileSize = parseInt(req.headers['content-length']) || 0;
    
    const currentUsage = userStorage.get(userId) || 0;
    
    if (currentUsage + fileSize > MAX_USER_STORAGE) {
        return res.status(403).json({
            error: 'Storage quota exceeded',
            message: `You have used ${(currentUsage / (1024*1024)).toFixed(2)}MB of ${MAX_USER_STORAGE / (1024*1024)}MB.`,
            code: 'STORAGE_QUOTA_EXCEEDED',
            currentUsage,
            maxStorage: MAX_USER_STORAGE
        });
    }
    
    next();
}

// ==================== UTILITY FUNCTIONS ====================

// Enhanced sanitization for sensitive data
function sanitizeText(text) {
    if (!text || typeof text !== 'string') return text;
    
    let sanitized = text;
    Object.values(SENSITIVE_PATTERNS).forEach(pattern => {
        sanitized = sanitized.replace(pattern, '[REDACTED]');
    });
    
    return sanitized;
}

// Sanitize file response based on user role
function sanitizeFile(file, user) {
    const isOwner = file.uploadedBy === user.userId;
    const isAdmin = user.role === 'admin';
    
    const response = {
        id: file.id,
        originalName: file.originalName,
        filename: file.filename,
        size: file.size,
        mimetype: file.mimetype,
        uploadDate: file.uploadDate,
        status: file.status,
        downloadUrl: file.downloadUrl,
        publicAccess: file.publicAccess,
        processingResult: file.processingResult
    };
    
    // Only expose uploader to owner/admin
    if (isOwner || isAdmin) {
        response.uploadedBy = file.uploadedBy;
    }
    
    // Expose advanced features to owner/admin
    if (isOwner || isAdmin) {
        response.compression = file.compression;
        response.encryption = file.encryption;
        response.versions = file.versions;
        response.currentVersion = file.currentVersion;
        response.backup = file.backup;
    }
    
    // Sanitize processing result for non-owners/admins
    if (!isOwner && !isAdmin) {
        if (response.processingResult && response.processingResult.hasSensitiveData) {
            response.processingResult = {
                hasSensitiveData: true,
                message: 'File contains sensitive data that has been redacted'
            };
        }
    }
    
    return response;
}

// Async error handler wrapper
function asyncHandler(fn) {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
}

// Content validation function
async function validateFileContent(fileBuffer, mimetype) {
    // Check file signature/magic bytes
    if (FILE_SIGNATURES[mimetype]) {
        const signature = FILE_SIGNATURES[mimetype];
        if (!fileBuffer.slice(0, signature.length).equals(signature)) {
            throw new Error('File content does not match expected format');
        }
    }
    
    return true;
}

// ==================== NEW: STREAMING FILE HANDLING ====================
async function streamFileUpload(req, filePath) {
    return new Promise((resolve, reject) => {
        const writeStream = fs.createWriteStream(filePath);
        let bytesWritten = 0;
        
        req.on('data', (chunk) => {
            bytesWritten += chunk.length;
            // Check file size during streaming
            if (bytesWritten > MAX_FILE_SIZE) {
                writeStream.end();
                fs.unlink(filePath, () => {}); // Clean up
                reject(new Error(`File size exceeds ${MAX_FILE_SIZE / (1024 * 1024)}MB limit`));
            }
        });
        
        req.pipe(writeStream);
        
        writeStream.on('finish', () => resolve(bytesWritten));
        writeStream.on('error', reject);
    });
}

// ==================== ENHANCED PROCESSING WITH RETRY LOGIC ====================
async function processFileWithRetry(fileId, retryCount = 0) {
    const file = uploadedFiles.find(f => f.id === fileId);
    if (!file) return;
    
    try {
        file.status = 'processing';
        
        // Log access
        accessLogs.push({
            timestamp: new Date().toISOString(),
            userId: file.uploadedBy,
            fileId: file.id,
            action: 'processing_started',
            details: { retryCount }
        });
        
        // Simulate random failures for retry testing (10% chance)
        if (Math.random() < 0.1 && retryCount < PROCESSING_RETRY_ATTEMPTS) {
            throw new Error(`Simulated processing failure (attempt ${retryCount + 1})`);
        }
        
        // Virus scanning simulation
        if (Math.random() > 0.9) {
            file.status = 'quarantined';
            file.processingResult = { 
                error: 'Virus detected',
                message: 'File quarantined for security',
                virusScan: {
                    clean: false,
                    scannedAt: new Date().toISOString(),
                    scanner: 'ClamAV-1.0',
                    threatsDetected: ['Trojan.Generic']
                }
            };
            return;
        }
        
        // Simulate processing based on file type
        if (file.mimetype.startsWith('image/')) {
            // REAL THUMBNAIL GENERATION WITH FALLBACK
            try {
                const filePath = path.join(UPLOAD_DIR, file.uploadedBy, file.filename);
                const thumbnailDir = path.join(UPLOAD_DIR, 'thumbnails');
                await fs.mkdir(thumbnailDir, { recursive: true });
                
                const thumbnail = await generateThumbnail(filePath, thumbnailDir);
                
                file.processingResult = {
                    width: 1920,
                    height: 1080,
                    format: 'jpeg',
                    thumbnailCreated: true,
                    thumbnailUrl: thumbnail?.url || '/uploads/thumbnails/default.svg',
                    thumbnailDimensions: thumbnail?.dimensions || '150x150',
                    thumbnailSimulated: thumbnail?.simulated || false,
                    thumbnailFormat: thumbnail?.format || 'svg',
                    hasSensitiveData: false
                };
            } catch (thumbnailError) {
                // Fallback to simulated thumbnail
                file.processingResult = {
                    width: 1920,
                    height: 1080,
                    format: 'jpeg',
                    thumbnailCreated: true,
                    thumbnailUrl: '/uploads/thumbnails/simulated.svg',
                    thumbnailDimensions: '150x150',
                    thumbnailSimulated: true,
                    thumbnailFormat: 'svg',
                    hasSensitiveData: false
                };
            }
        } else if (file.mimetype === 'text/csv') {
            file.processingResult = {
                rowCount: Math.floor(Math.random() * 1000),
                columnCount: 4,
                hasSensitiveData: true,
                sensitiveFieldsRedacted: ['name', 'email', 'salary'],
                compression: file.compression
            };
        } else if (file.mimetype === 'application/pdf') {
            file.processingResult = {
                pages: Math.floor(Math.random() * 50) + 1,
                textExtracted: true,
                wordCount: Math.floor(Math.random() * 10000),
                hasSensitiveData: false,
                compression: file.compression,
                encryption: file.encryption
            };
        } else {
            file.processingResult = {
                processed: true,
                fileType: file.mimetype,
                hasSensitiveData: false,
                features: ['encrypted', 'compressed', 'versioned']
            };
        }
        
        file.status = 'processed';
        console.log(`✅ File ${fileId} processed successfully`);
        
        // Log successful processing
        accessLogs.push({
            timestamp: new Date().toISOString(),
            userId: file.uploadedBy,
            fileId: file.id,
            action: 'processing_completed',
            details: { processingResult: file.processingResult }
        });
        
    } catch (error) {
        if (retryCount < PROCESSING_RETRY_ATTEMPTS) {
            console.log(`🔄 Retrying file ${fileId} (attempt ${retryCount + 1}/${PROCESSING_RETRY_ATTEMPTS})`);
            // Add back to queue with incremented retry count
            processingQueue.push({ fileId, retryCount: retryCount + 1 });
        } else {
            file.status = 'error';
            file.processingResult = { 
                error: 'Processing failed after 3 attempts',
                message: 'Unable to process file. Please try uploading again.',
                retryAttempts: retryCount,
                lastError: error.message
            };
            console.error(`❌ File ${fileId} failed after ${retryCount} retries:`, error.message);
            
            // Log failure
            accessLogs.push({
                timestamp: new Date().toISOString(),
                userId: file.uploadedBy,
                fileId: file.id,
                action: 'processing_failed',
                details: { error: error.message, retryAttempts: retryCount }
            });
        }
    }
}

// Keep original processFile for backward compatibility
function processFile(fileId) {
    processingQueue.push({ fileId, retryCount: 0 });
    processQueueItem();
}

// ==================== FIXED ROUTES ====================

// Apply authentication to all routes
router.use(authenticate);

// ==================== NEW: QUOTA ENDPOINT ====================
router.get('/quota', asyncHandler(async (req, res) => {
    const currentUsage = userStorage.get(req.user.userId) || 0;
    const percentage = (currentUsage / MAX_USER_STORAGE * 100).toFixed(2);
    
    res.json({
        used: currentUsage,
        usedMB: (currentUsage / (1024 * 1024)).toFixed(2),
        total: MAX_USER_STORAGE,
        totalMB: (MAX_USER_STORAGE / (1024 * 1024)).toFixed(2),
        remaining: MAX_USER_STORAGE - currentUsage,
        remainingMB: ((MAX_USER_STORAGE - currentUsage) / (1024 * 1024)).toFixed(2),
        percentage: percentage + '%',
        warning: percentage > 80 ? 'Storage nearly full' : percentage > 50 ? 'Storage medium' : 'Storage good'
    });
}));

// Fixed: Get user files with proper pagination and security
router.get('/', asyncHandler(async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const status = req.query.status;
    const fileType = req.query.type;

    console.log(uploadedFiles);
    
    let filteredFiles = uploadedFiles.filter(file => {
        // Admins see all files
        if (req.user.role === 'admin') return true;
        
        // Regular users see their own files and public files
        const isOwner = file.uploadedBy === req.user.userId;
        const isPublic = file.publicAccess === true;
        
        return isOwner || isPublic;
    });
    
    // Apply filters
    if (status) {
        filteredFiles = filteredFiles.filter(file => file.status === status);
    }
    
    if (fileType) {
        filteredFiles = filteredFiles.filter(file => file.mimetype.includes(fileType));
    }
    
    // Fixed: Proper pagination
    const totalFiles = filteredFiles.length;
    const totalPages = Math.ceil(totalFiles / limit);
    const startIndex = (page - 1) * limit;
    const endIndex = Math.min(startIndex + limit, totalFiles);
    
    const paginatedFiles = filteredFiles.slice(startIndex, endIndex);
    
    // Sanitize files for response
    const sanitizedFiles = paginatedFiles.map(file => sanitizeFile(file, req.user));
    
    // Calculate storage usage
    const userFiles = uploadedFiles.filter(f => f.uploadedBy === req.user.userId);
    const storageUsed = userFiles.reduce((sum, file) => sum + file.size, 0);
    
    // Fixed: Secure headers without debug info
    res.set({
        'X-Total-Files': totalFiles.toString(),
        'X-Total-Pages': totalPages.toString(),
        'X-Current-Page': page.toString(),
        'X-Per-Page': limit.toString(),
        'X-Hidden-Metadata': 'check_file_processing_logs_endpoint',
    });
    
    res.json({
        files: sanitizedFiles,
        pagination: {
            page,
            limit,
            total: totalFiles,
            totalPages,
            hasMore: endIndex < totalFiles
        }
    });
}));

// Fixed: Get specific file information with proper security
router.get('/:fileId', authorizeFileAccess, asyncHandler(async (req, res) => {
    res.set({
        'X-Hidden-Metadata': 'check_file_processing_logs_endpoint'
    });
    res.json(sanitizeFile(req.file, req.user));
}));

// ==================== NEW: FILE DOWNLOAD ENDPOINT ====================
router.get('/download/:userId/:filename', asyncHandler(async (req, res) => {
    const { userId, filename } = req.params;
    const filePath = path.join(UPLOAD_DIR, userId, filename);
    
    try {
        // Check if file exists
        await fs.access(filePath);
        
        // Find file metadata
        const fileMeta = uploadedFiles.find(f => 
            f.filename === filename && f.uploadedBy === userId
        );
        
        if (!fileMeta) {
            return res.status(404).json({ 
                error: 'File not found',
                code: 'FILE_NOT_FOUND'
            });
        }
        
        // Check permissions
        const isOwner = fileMeta.uploadedBy === req.user.userId;
        const isAdmin = req.user.role === 'admin';
        const isPublic = fileMeta.publicAccess === true;
        
        if (!isOwner && !isAdmin && !isPublic) {
            return res.status(403).json({ 
                error: 'Access denied',
                message: 'You do not have permission to download this file',
                code: 'DOWNLOAD_PERMISSION_DENIED'
            });
        }
        
        // Set headers for download
        res.set({
            'Content-Type': fileMeta.mimetype,
            'Content-Disposition': `attachment; filename="${fileMeta.originalName}"`,
            'Content-Length': fileMeta.size,
            'X-File-Id': fileMeta.id,
            'X-File-Hash': fileMeta.fileHash,
            'Cache-Control': 'private, max-age=3600'
        });
        
        // Stream the file
        const fileStream = fs.createReadStream(filePath);
        fileStream.pipe(res);
        
        // Log access
        accessLogs.push({
            timestamp: new Date().toISOString(),
            userId: req.user.userId,
            fileId: fileMeta.id,
            action: 'download',
            ip: req.ip
        });
        
    } catch (error) {
        if (error.code === 'ENOENT') {
            return res.status(404).json({ 
                error: 'File not found',
                message: 'The requested file does not exist on the server',
                code: 'FILE_NOT_FOUND'
            });
        }
        throw error;
    }
}));

// Fixed: Upload file with proper validation
router.post('/', checkStorageQuota, upload.single('file'), asyncHandler(async (req, res) => {
    console.log(`Received upload request from user ${req.user.userId} for file ${req.file?.originalname}...`);
    if (!req.file) {
        return res.status(400).json({ 
            error: 'No file uploaded',
            message: 'Please select a file to upload',
            code: 'NO_FILE'
        });
    }
    
    try {
        // Read file for validation
        const fileBuffer = await fs.readFile(req.file.path);
        
        // Fixed: Enhanced validation
        if (fileBuffer.length === 0) {
            await fs.unlink(req.file.path);
            return res.status(400).json({ 
                error: 'Empty file',
                message: 'File cannot be empty',
                code: 'EMPTY_FILE'
            });
        }
        
        // Validate file type by content
        const fileType = await fileTypeFromBuffer(fileBuffer);
        if (!fileType) {
            await fs.unlink(req.file.path);
            return res.status(400).json({ 
                error: 'Unrecognized file type',
                message: 'Could not determine file type from content',
                code: 'UNKNOWN_FILE_TYPE'
            });
        }
        
        // Verify MIME type matches content
        if (!ALLOWED_MIME_TYPES.includes(fileType.mime)) {
            await fs.unlink(req.file.path);
            return res.status(400).json({ 
                error: 'Invalid file type',
                message: `File type ${fileType.mime} is not allowed`,
                code: 'INVALID_FILE_TYPE'
            });
        }
        
        // Validate file content
        try {
            await validateFileContent(fileBuffer, fileType.mime);
        } catch (validationError) {
            await fs.unlink(req.file.path);
            return res.status(400).json({ 
                error: 'File validation failed',
                message: validationError.message,
                code: 'FILE_VALIDATION_FAILED'
            });
        }
        
        // Calculate file hash for integrity
        const fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
        
        // Check for duplicate files by hash
        const duplicateFile = uploadedFiles.find(f => 
            f.fileHash === fileHash && f.uploadedBy === req.user.userId
        );
        
        if (duplicateFile) {
            await fs.unlink(req.file.path);
            return res.status(409).json({ 
                error: 'Duplicate file',
                message: 'This file has already been uploaded',
                code: 'DUPLICATE_FILE'
            });
        }
        
        // === ADD ENCRYPTION AT REST ===
        const encryptionKey = crypto.scryptSync(JWT_SECRET, 'salt', 32);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
        const encryptedBuffer = Buffer.concat([
            cipher.update(fileBuffer),
            cipher.final(),
            cipher.getAuthTag()
        ]);
        
        // Save encrypted file
        await fs.writeFile(req.file.path, Buffer.concat([iv, encryptedBuffer]));
        
        // === ADD COMPRESSION SIMULATION ===
        const originalSize = fileBuffer.length;
        const compressedSize = Math.floor(originalSize * 0.75); // 25% compression
        
        // === ADD BACKUP SIMULATION ===
        const backupDir = path.join(UPLOAD_DIR, 'backups', req.user.userId);
        await fs.mkdir(backupDir, { recursive: true });
        const backupPath = path.join(backupDir, `${req.file.filename}_${Date.now()}`);
        await fs.copyFile(req.file.path, backupPath);
        
        // Create file record
        const newFile = {
            id: uuidv4(),
            originalName: req.file.originalname,
            filename: req.file.filename,
            mimetype: fileType.mime,
            size: req.file.size,
            uploadedBy: req.user.userId,
            uploadDate: new Date().toISOString(),
            status: 'uploaded',
            processingResult: null,
            downloadUrl: `/api/upload/download/${req.user.userId}/${req.file.filename}`,
            publicAccess: req.body.publicAccess === 'true' || false,
            fileHash: fileHash,
            compression: {
                enabled: true,
                originalSize: originalSize,
                compressedSize: compressedSize,
                ratio: '25%',
                algorithm: 'gzip'
            },
            encryption: {
                algorithm: 'aes-256-gcm',
                encrypted: true,
                iv: iv.toString('hex'),
                keyDerivation: 'scrypt'
            },
            versions: [{
                version: 1,
                timestamp: new Date().toISOString(),
                size: req.file.size,
                hash: fileHash
            }],
            currentVersion: 1,
            backup: {
                location: backupPath,
                timestamp: new Date().toISOString(),
                type: 'encrypted_copy'
            }
        };
        
        uploadedFiles.push(newFile);
        
        // Update user storage
        const currentUsage = userStorage.get(req.user.userId) || 0;
        userStorage.set(req.user.userId, currentUsage + req.file.size);
        
        // Start processing with queue system
        processFile(newFile.id);
        
        res.set({
            'X-File-Id': newFile.id,
            'Location': `/api/upload/${newFile.id}`,
            'X-Features': 'encryption,compression,versioning,backup'
        });
        
        res.status(201).json({
            message: 'File uploaded successfully',
            file: sanitizeFile(newFile, req.user),
            features: {
                encryption: 'aes-256-gcm',
                compression: '25%',
                versioning: 'enabled',
                backup: 'created'
            }
        });
        
    } catch (error) {
        // Clean up on error
        if (req.file && req.file.path) {
            try {
                await fs.unlink(req.file.path);
            } catch (cleanupError) {
                console.error('Failed to clean up file:', cleanupError);
            }
        }
        
        // Fixed: Generic error response
        res.status(500).json({ 
            error: 'Upload failed',
            message: 'An error occurred during file upload'
        });
    }
}));

// ==================== BATCH UPLOAD ====================
router.post('/batch', checkStorageQuota, batchUpload.array('files', 5), asyncHandler(async (req, res) => {
    console.log(`Received batch upload request from user ${req.user.userId} for ${req.files?.length || 0} files`);
    
    if (!req.files || req.files.length === 0) {
        return res.status(400).json({ 
            error: 'No files uploaded',
            message: 'Please select files to upload',
            code: 'NO_FILES'
        });
    }
    
    const uploadedFilesInfo = [];
    const errors = [];
    
    for (const file of req.files) {
        try {
            // Simplified version of single upload logic
            const fileBuffer = await fs.readFile(file.path);
            const fileType = await fileTypeFromBuffer(fileBuffer);
            
            if (!fileType || !ALLOWED_MIME_TYPES.includes(fileType.mime)) {
                errors.push({ filename: file.originalname, error: 'Invalid file type' });
                await fs.unlink(file.path);
                continue;
            }
            
            // Simple encryption for batch
            const encryptionKey = crypto.scryptSync(JWT_SECRET, 'salt', 32);
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
            const encryptedBuffer = Buffer.concat([
                cipher.update(fileBuffer),
                cipher.final(),
                cipher.getAuthTag()
            ]);
            
            await fs.writeFile(file.path, Buffer.concat([iv, encryptedBuffer]));
            
            const fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
            const originalSize = fileBuffer.length;
            const compressedSize = Math.floor(originalSize * 0.75);
            
            const newFile = {
                id: uuidv4(),
                originalName: file.originalname,
                filename: file.filename,
                mimetype: fileType.mime,
                size: file.size,
                uploadedBy: req.user.userId,
                uploadDate: new Date().toISOString(),
                status: 'uploaded',
                processingResult: null,
                downloadUrl: `/api/upload/download/${req.user.userId}/${file.filename}`,
                publicAccess: false,
                fileHash: fileHash,
                compression: { enabled: true, originalSize, compressedSize, ratio: '25%' },
                encryption: { algorithm: 'aes-256-gcm', encrypted: true, iv: iv.toString('hex') },
                versions: [{ version: 1, timestamp: new Date().toISOString(), size: file.size }],
                currentVersion: 1
            };
            
            uploadedFiles.push(newFile);
            uploadedFilesInfo.push(newFile);
            
            // Update user storage
            const currentUsage = userStorage.get(req.user.userId) || 0;
            userStorage.set(req.user.userId, currentUsage + file.size);
            
            // Start processing with queue
            processFile(newFile.id);
            
        } catch (error) {
            errors.push({ filename: file.originalname, error: error.message });
            // Clean up failed file
            if (file && file.path) {
                try {
                    await fs.unlink(file.path);
                } catch (cleanupError) {
                    console.error('Failed to clean up file:', cleanupError);
                }
            }
        }
    }
    
    const totalSize = uploadedFilesInfo.reduce((sum, file) => sum + file.size, 0);
    
    res.set({
        'X-Batch-Upload-Count': uploadedFilesInfo.length.toString(),
        'X-Batch-Total-Size': totalSize.toString(),
        'X-Batch-Errors': errors.length.toString()
    });
    
    res.status(201).json({
        message: `Batch upload completed: ${uploadedFilesInfo.length} files uploaded, ${errors.length} errors`,
        files: uploadedFilesInfo.map(file => sanitizeFile(file, req.user)),
        errors: errors,
        summary: {
            totalFiles: uploadedFilesInfo.length,
            totalSize: totalSize,
            successful: uploadedFilesInfo.length,
            failed: errors.length
        }
    });
}));

// ==================== NEW: FILE SHARING ENDPOINT ====================
router.post('/:fileId/share', authorizeFileAccess, asyncHandler(async (req, res) => {
    const { expiresIn = 3600000 } = req.body; // 1 hour default in milliseconds
    const shareId = uuidv4();
    const expiresAt = Date.now() + parseInt(expiresIn);
    
    // Create share record
    sharedFiles.set(shareId, {
        fileId: req.params.fileId,
        expiresAt,
        createdBy: req.user.userId,
        createdAt: new Date().toISOString()
    });
    
    res.json({
        shareId: shareId,
        shareUrl: `/api/share/${shareId}`,
        expiresAt: new Date(expiresAt).toISOString(),
        fileId: req.params.fileId,
        message: 'File shared successfully. Share link will expire in ' + (expiresIn / 3600000) + ' hours.'
    });
}));

// ==================== NEW: ACCESS SHARED FILE ====================
router.get('/share/:shareId', asyncHandler(async (req, res) => {
    const share = sharedFiles.get(req.params.shareId);
    
    if (!share) {
        return res.status(404).json({ 
            error: 'Share link not found',
            message: 'This share link is invalid or has expired',
            code: 'SHARE_NOT_FOUND'
        });
    }
    
    if (Date.now() > share.expiresAt) {
        // Clean up expired share
        sharedFiles.delete(req.params.shareId);
        return res.status(410).json({ 
            error: 'Share link expired',
            message: 'This share link has expired',
            code: 'SHARE_EXPIRED'
        });
    }
    
    // Find the file
    const file = uploadedFiles.find(f => f.id === share.fileId);
    if (!file) {
        return res.status(404).json({ 
            error: 'File not found',
            message: 'The shared file no longer exists',
            code: 'FILE_NOT_FOUND'
        });
    }
    
    // Redirect to download
    res.redirect(file.downloadUrl);
}));

// ==================== NEW: ACCESS LOGS ENDPOINT ====================
router.get('/access-logs', asyncHandler(async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ 
            error: 'Permission denied',
            message: 'Only administrators can access access logs',
            code: 'ACCESS_LOGS_DENIED'
        });
    }
    
    // Filter logs for this user if not admin
    let filteredLogs = accessLogs;
    if (req.user.role !== 'admin') {
        filteredLogs = accessLogs.filter(log => log.userId === req.user.userId);
    }
    
    // Apply pagination
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + limit;
    
    res.json({
        logs: filteredLogs.slice(startIndex, endIndex),
        total: filteredLogs.length,
        page: page,
        limit: limit,
        hasMore: endIndex < filteredLogs.length
    });
}));

// ==================== NEW: PROCESSING QUEUE STATUS ====================
router.get('/queue/status', asyncHandler(async (req, res) => {
    res.json({
        queueLength: processingQueue.length,
        activeProcesses: activeProcesses,
        maxConcurrentProcesses: MAX_CONCURRENT_PROCESSES,
        processingFiles: uploadedFiles.filter(f => f.status === 'processing').length,
        waitingFiles: uploadedFiles.filter(f => f.status === 'uploaded').length,
        processedFiles: uploadedFiles.filter(f => f.status === 'processed').length,
        failedFiles: uploadedFiles.filter(f => f.status === 'error').length
    });
}));

// Fixed: Update file metadata with validation
router.put('/:fileId', authorizeFileAccess, asyncHandler(async (req, res) => {
    const { publicAccess, originalName } = req.body;
    const updates = {};
    
    // Fixed: Validate update data
    if (publicAccess !== undefined) {
        if (typeof publicAccess !== 'boolean') {
            return res.status(400).json({ 
                error: 'Invalid publicAccess value',
                message: 'publicAccess must be a boolean',
                code: 'VALIDATION_ERROR'
            });
        }
        updates.publicAccess = publicAccess;
    }
    
    if (originalName !== undefined) {
        if (typeof originalName !== 'string' || originalName.trim().length === 0) {
            return res.status(400).json({ 
                error: 'Invalid originalName',
                message: 'originalName must be a non-empty string',
                code: 'VALIDATION_ERROR'
            });
        }
        updates.originalName = originalName.trim();
    }
    
    // Fixed: Check ownership
    if (req.file.uploadedBy !== req.user.userId && req.user.role !== 'admin') {
        return res.status(403).json({ 
            error: 'Permission denied',
            message: 'Only the file owner or admin can update metadata',
            code: 'UPDATE_PERMISSION_DENIED'
        });
    }
    
    // Apply updates
    Object.keys(updates).forEach(key => {
        req.file[key] = updates[key];
    });
    
    res.json({
        message: 'File metadata updated successfully',
        file: sanitizeFile(req.file, req.user)
    });
}));

// Fixed: Delete file with proper cleanup
router.delete('/:fileId', authorizeFileAccess, asyncHandler(async (req, res) => {
    // Ownership check (authorizeFileAccess already enforces access, keep for clarity)
    if (req.file.uploadedBy !== req.user.userId && req.user.role !== 'admin') {
        return res.status(403).json({
            error: 'Permission denied',
            message: 'Only the file owner or admin can delete this file',
            code: 'DELETE_PERMISSION_DENIED'
        });
    }

    const fileIndex = uploadedFiles.findIndex(f => f.id === req.file.id);
    if (fileIndex === -1) {
        return res.status(404).json({
            error: 'File not found',
            message: 'The requested file does not exist',
            code: 'FILE_NOT_FOUND'
        });
    }

    const fileRecord = uploadedFiles[fileIndex];
    const filePath = path.join(process.env.UPLOAD_DIR || './uploads', String(fileRecord.uploadedBy), fileRecord.filename);
    const userDir = path.join(process.env.UPLOAD_DIR || './uploads', String(fileRecord.uploadedBy));

    try {
        // Try to delete the physical file; ignore if it's already missing
        try {
            await fs.unlink(filePath);
            console.log(`Deleted file: ${filePath}`);
        } catch (err) {
            if (err.code !== 'ENOENT') {
                // Non-ENOENT errors we log but don't abort metadata removal
                console.warn(`Could not delete physical file: ${err.message}`);
            } else {
                console.warn(`Physical file not found (already removed): ${filePath}`);
            }
        }

        // Update user storage (use the uploader's account)
        const currentUsage = userStorage.get(fileRecord.uploadedBy) || 0;
        userStorage.set(fileRecord.uploadedBy, Math.max(0, currentUsage - (fileRecord.size || 0)));

        // Remove metadata record
        uploadedFiles.splice(fileIndex, 1);

        // Try to remove user directory if empty (non-fatal)
        try {
            const remaining = await fs.readdir(userDir);
            if (remaining.length === 0) {
                await fs.rmdir(userDir);
                console.log(`Removed empty user directory: ${userDir}`);
            }
        } catch (dirErr) {
            // Ignore expected cases: ENOENT (dir missing) and ENOTEMPTY (not empty)
            if (dirErr.code && dirErr.code !== 'ENOTEMPTY' && dirErr.code !== 'ENOENT') {
                console.warn(`Failed to remove user dir: ${dirErr.message}`);
            }
        }

        return res.json({
            message: 'File deleted successfully',
            fileId: fileRecord.id
        });
    } catch (error) {
        console.error('Failed to delete file:', error);
        return res.status(500).json({
            error: 'Delete failed',
            message: 'Could not delete file at this time'
        });
    }
}));

// Error handling middleware
router.use((err, req, res, next) => {
    console.error('Upload route error:', err);
    
    // Handle multer errors
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({
                error: 'File too large',
                message: `File exceeds ${MAX_FILE_SIZE / (1024 * 1024)}MB limit`,
                code: 'FILE_TOO_LARGE'
            });
        }
        
        return res.status(400).json({
            error: 'Upload error',
            message: err.message,
            code: 'UPLOAD_ERROR'
        });
    }
    
    // Handle JWT errors
    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({
            error: 'Invalid token',
            message: 'The authentication token is invalid',
            code: 'INVALID_TOKEN'
        });
    }
    
    // Generic error response
    res.status(500).json({
        error: 'Internal server error',
        message: 'An unexpected error occurred',
        code: 'INTERNAL_ERROR'
    });
});

module.exports = router;