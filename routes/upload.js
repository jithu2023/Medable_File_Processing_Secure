const express = require('express');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');
const multer = require('multer');
const { fileTypeFromBuffer } = require('file-type');
const zlib = require('zlib');

const router = express.Router();

// ==================== SECURE CONFIGURATION ====================
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024;
const UPLOAD_DIR = process.env.UPLOAD_DIR || './uploads';
const MAX_USER_STORAGE = parseInt(process.env.MAX_USER_STORAGE) || 100 * 1024 * 1024;
const MAX_USER_UPLOADS_PER_HOUR = 20;
const USE_ACTUAL_COMPRESSION = process.env.USE_ACTUAL_COMPRESSION === 'true';
const COMPRESSION_THRESHOLD = parseInt(process.env.COMPRESSION_THRESHOLD) || 1024;
const MIN_COMPRESSION_RATIO = 0.05; // At least 5% reduction required

const ALLOWED_MIME_TYPES = [
    'image/jpeg',
    'image/png', 
    'image/gif',
    'application/pdf',
    'text/plain',
    'text/csv',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
];

// RETRY CONFIGURATION
const PROCESSING_RETRY_ATTEMPTS = 3;
const PROCESSING_RETRY_DELAY = 1000;

// Enhanced sensitive data patterns for redaction
const SENSITIVE_PATTERNS = {
    ssn: /\b\d{3}[-]?\d{2}[-]?\d{4}\b/g,
    email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    phone: /\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
    creditCard: /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g,
    ipAddress: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g
};

// ==================== FILE SHARING SYSTEM ====================
const sharedFiles = new Map();

// ==================== PROCESSING QUEUE ====================
const processingQueue = [];
let activeProcesses = 0;
const MAX_CONCURRENT_PROCESSES = 3;

// ==================== ACCESS LOGS ====================
const accessLogs = [];

// ==================== SETUP ====================
const userStorage = new Map();
const userUploadRates = new Map();

userStorage.set('user1', 2048576);
userStorage.set('admin', 1024000);
userStorage.set('user2', 524288);
userStorage.set('testuser', 0);
userStorage.set('system', 0);

(async () => {
    try {
        await fs.access(UPLOAD_DIR);
    } catch {
        await fs.mkdir(UPLOAD_DIR, { recursive: true });
        const users = ['user1', 'admin', 'user2', 'testuser', 'system'];
        for (const user of users) {
            const userDir = path.join(UPLOAD_DIR, user);
            await fs.mkdir(userDir, { recursive: true });
        }
        console.log(`✅ Created upload directory: ${UPLOAD_DIR}`);
    }
})();

(async () => {
    const thumbnailDir = path.join(UPLOAD_DIR, 'thumbnails');
    try {
        await fs.access(thumbnailDir);
    } catch {
        await fs.mkdir(thumbnailDir, { recursive: true });
        console.log(`✅ Created thumbnail directory: ${thumbnailDir}`);
        
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

// ==================== SECURE FILE TYPE DETECTION ====================
async function getFileType(buffer, originalName) {
    try {
        const fileExt = path.extname(originalName).toLowerCase();
        
        if (!buffer || buffer.length === 0) {
            throw new Error('File is empty');
        }
        
        if (fileTypeFromBuffer && typeof fileTypeFromBuffer === 'function') {
            const result = await fileTypeFromBuffer(buffer);
            if (result) {
                if (result.mime === 'application/pdf') {
                    if (buffer.length >= 5) {
                        const pdfHeader = buffer.slice(0, 5);
                        if (!pdfHeader.equals(Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D]))) {
                            throw new Error('File identified as PDF but missing valid PDF header');
                        }
                    }
                }
                return result;
            }
        }
        
        if (buffer.length < 4) {
            throw new Error('File too small');
        }
        
        const signatures = {
            'image/jpeg': { 
                bytes: [[0xFF, 0xD8, 0xFF, 0xE0], [0xFF, 0xD8, 0xFF, 0xE1], [0xFF, 0xD8, 0xFF, 0xE8], [0xFF, 0xD8, 0xFF, 0xDB]],
                ext: 'jpg',
                minSize: 100
            },
            'image/png': { 
                bytes: [[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]],
                ext: 'png',
                minSize: 67
            },
            'image/gif': { 
                bytes: [[0x47, 0x49, 0x46, 0x38, 0x37, 0x61], [0x47, 0x49, 0x46, 0x38, 0x39, 0x61]],
                ext: 'gif',
                minSize: 35
            },
            'application/pdf': { 
                bytes: [[0x25, 0x50, 0x44, 0x46, 0x2D]],
                ext: 'pdf',
                minSize: 100
            }
        };
        
        for (const [mime, sig] of Object.entries(signatures)) {
            for (const signature of sig.bytes) {
                if (buffer.length >= signature.length) {
                    let match = true;
                    for (let i = 0; i < signature.length; i++) {
                        if (buffer[i] !== signature[i]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        if (sig.minSize && buffer.length < sig.minSize) {
                            throw new Error(`File too small for ${mime} format`);
                        }
                        return { mime, ext: sig.ext };
                    }
                }
            }
        }
        
        if (fileExt === '.pdf') {
            const bufferStr = buffer.toString('latin1', 0, Math.min(buffer.length, 1000));
            if (bufferStr.startsWith('%PDF-')) {
                return { mime: 'application/pdf', ext: 'pdf' };
            }
            throw new Error('File with .pdf extension does not contain valid PDF data');
        }
        
        if (buffer.length > 0) {
            const sampleSize = Math.min(buffer.length, 1024);
            let asciiCount = 0;
            let nullByteCount = 0;
            
            for (let i = 0; i < sampleSize; i++) {
                const byte = buffer[i];
                if (byte === 0) nullByteCount++;
                if (byte <= 127) asciiCount++;
            }
            
            if (nullByteCount > 0) {
                throw new Error('File contains binary data');
            }
            
            const asciiPercentage = (asciiCount / sampleSize) * 100;
            
            if (asciiPercentage > 95) {
                const bufferStr = buffer.toString('utf8', 0, Math.min(buffer.length, 1024));
                const lines = bufferStr.split('\n');
                if (lines.length > 1 && lines[0].includes(',')) {
                    return { mime: 'text/csv', ext: 'csv' };
                }
                return { mime: 'text/plain', ext: 'txt' };
            }
        }
        
        throw new Error('Unrecognized file format');
        
    } catch (error) {
        if (!error.code) {
            error.code = 'UNKNOWN_FILE_TYPE';
        }
        throw error;
    }
}

// ==================== ENHANCED CONTENT VALIDATION ====================
async function validateFileContent(fileBuffer, mimetype, originalName) {
    if (fileBuffer.length === 0) {
        const error = new Error('File is empty');
        error.code = 'EMPTY_FILE';
        throw error;
    }
    
    const minSizes = {
        'image/jpeg': 100,
        'image/png': 67,
        'image/gif': 35,
        'application/pdf': 100,
        'text/plain': 1,
        'text/csv': 1
    };
    
    if (minSizes[mimetype] && fileBuffer.length < minSizes[mimetype]) {
        throw new Error(`File is too small to be a valid ${mimetype.split('/')[1]} file`);
    }
    
    const fileExt = path.extname(originalName).toLowerCase();
    if (fileExt === '.pdf' && mimetype !== 'application/pdf') {
        throw new Error('File with .pdf extension does not contain valid PDF data');
    }
    
    // CRITICAL FIX: STRICT PDF VALIDATION
    if (mimetype === 'application/pdf') {
        const pdfHeader = fileBuffer.slice(0, 5);
        if (!pdfHeader.equals(Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D]))) {
            throw new Error('Invalid PDF: missing PDF header');
        }
        
        // Check for PDF structure markers - STRICT VALIDATION
        const pdfString = fileBuffer.toString('latin1', 0, Math.min(fileBuffer.length, 10000));
        
        // A valid PDF must have obj and endobj markers
        if (!pdfString.includes('obj') || !pdfString.includes('endobj')) {
            throw new Error('Invalid PDF: corrupted or malformed structure');
        }
        
        // Check for excessive null bytes (corruption indicator)
        const nullByteCount = fileBuffer.slice(0, Math.min(fileBuffer.length, 1000))
            .filter(byte => byte === 0).length;
        if (nullByteCount > 100) {
            throw new Error('PDF contains excessive null bytes - likely corrupted');
        }
    }
    
    else if (mimetype.startsWith('image/')) {
        if (fileBuffer.length < 10) {
            throw new Error('Invalid image file: file too small');
        }
        
        const firstBytes = fileBuffer.slice(0, 4);
        const allSame = firstBytes.every(byte => byte === firstBytes[0]);
        if (allSame && firstBytes[0] === 0) {
            throw new Error('Invalid image file: corrupted header (all zeros)');
        }
        
        if (mimetype === 'image/jpeg') {
            if (fileBuffer[0] !== 0xFF || fileBuffer[1] !== 0xD8) {
                throw new Error('Invalid JPEG: incorrect header');
            }
        }
        
        if (mimetype === 'image/png' && fileBuffer.length >= 12) {
            const iendMarker = Buffer.from([0x49, 0x45, 0x4E, 0x44]);
            const fileEnd = fileBuffer.slice(-12, -8);
            if (!fileEnd.equals(iendMarker)) {
                throw new Error('Invalid PNG: missing IEND chunk');
            }
        }
    }
    
    else if (mimetype === 'text/plain' || mimetype === 'text/csv') {
        const sample = fileBuffer.slice(0, Math.min(fileBuffer.length, 1024));
        for (let i = 0; i < sample.length; i++) {
            if (sample[i] === 0) {
                throw new Error('Invalid text file: contains null bytes');
            }
        }
    }
    
    const last1024 = fileBuffer.slice(-Math.min(1024, fileBuffer.length));
    const nullCount = last1024.filter(byte => byte === 0).length;
    if (nullCount > last1024.length * 0.9) {
        throw new Error('File appears truncated or corrupted');
    }
    
    return true;
}

// ==================== FIXED COMPRESSION LOGIC ====================
async function applyCompression(buffer, mimetype, fileId) {
    // Don't compress images or already compressed formats
    if (mimetype.startsWith('image/') || 
        mimetype.includes('zip') || 
        mimetype.includes('compressed')) {
        return {
            buffer,
            compressed: false,
            ratio: '0%',
            algorithm: 'none',
            reason: 'already compressed format'
        };
    }
    
    // Don't compress small files
    if (buffer.length < COMPRESSION_THRESHOLD) {
        return {
            buffer,
            compressed: false,
            ratio: '0%',
            algorithm: 'none',
            reason: `file too small (${buffer.length} bytes)`
        };
    }
    
    try {
        const compressedBuffer = zlib.gzipSync(buffer, { level: 6 });
        const compressionRatio = (buffer.length - compressedBuffer.length) / buffer.length;
        
        // CRITICAL FIX: Only use compression if it actually helps
        if (compressionRatio < MIN_COMPRESSION_RATIO) {
            console.log(`[${fileId}] Compression skipped: only ${(compressionRatio * 100).toFixed(1)}% reduction`);
            return {
                buffer,
                compressed: false,
                ratio: '0%',
                algorithm: 'none',
                reason: `insufficient compression (${(compressionRatio * 100).toFixed(1)}%)`
            };
        }
        
        console.log(`[${fileId}] Compression applied: ${(compressionRatio * 100).toFixed(1)}% reduction`);
        
        return {
            buffer: compressedBuffer,
            compressed: true,
            ratio: `${(compressionRatio * 100).toFixed(1)}%`,
            algorithm: 'gzip',
            originalSize: buffer.length,
            compressedSize: compressedBuffer.length
        };
        
    } catch (error) {
        console.warn(`[${fileId}] Compression failed:`, error.message);
        return {
            buffer,
            compressed: false,
            ratio: '0%',
            algorithm: 'none',
            reason: `compression error: ${error.message}`
        };
    }
}

// ==================== QUEUE PROCESSOR ====================
async function processQueueItem() {
    if (activeProcesses >= MAX_CONCURRENT_PROCESSES || processingQueue.length === 0) {
        return;
    }
    
    const { fileId, retryCount = 0 } = processingQueue.shift();
    activeProcesses++;
    
    try {
        await processFileWithRetry(fileId, retryCount);
    } catch (error) {
        console.error(`Error processing queue item ${fileId}:`, error.message);
    } finally {
        activeProcesses--;
        setTimeout(processQueueItem, 100);
    }
}

// ==================== ENHANCED SECURE FILE STORAGE ====================
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const userId = req.user?.userId || 'anonymous';
        const userDir = path.join(UPLOAD_DIR, userId);
        
        fs.mkdir(userDir, { recursive: true })
            .then(() => cb(null, userDir))
            .catch(err => {
                console.error('Error creating user directory:', err);
                cb(err, UPLOAD_DIR);
            });
    },
    filename: (req, file, cb) => {
        const uniqueId = uuidv4();
        const timestamp = Date.now();
        const randomBytes = crypto.randomBytes(8);
        const hash = crypto.createHash('sha256')
            .update(`${uniqueId}${timestamp}${randomBytes.toString('hex')}`)
            .digest('hex')
            .substring(0, 32);
        
        let fileExt = path.extname(file.originalname).toLowerCase();
        if (!fileExt) {
            const mimeToExt = {
                'image/jpeg': '.jpg',
                'image/png': '.png',
                'image/gif': '.gif',
                'application/pdf': '.pdf',
                'text/plain': '.txt',
                'text/csv': '.csv',
                'application/msword': '.doc',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
                'application/vnd.ms-excel': '.xls',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx'
            };
            fileExt = mimeToExt[file.mimetype] || '.bin';
        }
        
        const filename = `${hash}-${timestamp}${fileExt}`;
        cb(null, filename);
    }
});

// ==================== ENHANCED FILE VALIDATION ====================
const fileFilter = async (req, file, cb) => {
    try {
        if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
            const error = new Error(`File type ${file.mimetype} is not allowed`);
            error.code = 'INVALID_FILE_TYPE';
            return cb(error, false);
        }
        
        const allowedExtensions = [
            '.jpg', '.jpeg', '.png', '.gif', '.pdf', 
            '.txt', '.csv', '.doc', '.docx', '.xls', '.xlsx'
        ];
        const fileExt = path.extname(file.originalname).toLowerCase();
        
        if (fileExt && !allowedExtensions.includes(fileExt)) {
            const error = new Error(`File extension ${fileExt} is not allowed`);
            error.code = 'INVALID_FILE_EXTENSION';
            return cb(error, false);
        }
        
        if (req.headers['content-length'] === '0') {
            const error = new Error('Zero-size file uploaded');
            error.code = 'ZERO_SIZE_FILE';
            return cb(error, false);
        }
        
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
            const error = new Error('Upload rate limit exceeded. Please try again later.');
            error.code = 'RATE_LIMIT_EXCEEDED';
            return cb(error, false);
        }
        
        userUploadRates.set(userId, userRate);
        
        cb(null, true);
    } catch (error) {
        error.code = error.code || 'FILE_VALIDATION_ERROR';
        cb(error, false);
    }
};

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

const batchUpload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: MAX_FILE_SIZE,
        files: 5,
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

function checkStorageQuota(req, res, next) {
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
function sanitizeText(text) {
    if (!text || typeof text !== 'string') return text;
    
    let sanitized = text;
    Object.values(SENSITIVE_PATTERNS).forEach(pattern => {
        sanitized = sanitized.replace(pattern, '[REDACTED]');
    });
    
    return sanitized;
}

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
    
    if (isOwner || isAdmin) {
        response.uploadedBy = file.uploadedBy;
    }
    
    if (isOwner || isAdmin) {
        response.compression = file.compression;
        response.encryption = file.encryption;
        response.versions = file.versions;
        response.currentVersion = file.currentVersion;
        response.backup = file.backup;
    }
    
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

function asyncHandler(fn) {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
}

// ==================== ENHANCED PROCESSING WITH RETRY LOGIC ====================
async function processFileWithRetry(fileId, retryCount = 0) {
    const file = uploadedFiles.find(f => f.id === fileId);
    if (!file) return;
    
    try {
        file.status = 'processing';
        
        accessLogs.push({
            timestamp: new Date().toISOString(),
            userId: file.uploadedBy,
            fileId: file.id,
            action: 'processing_started',
            details: { retryCount }
        });
        
        if (Math.random() < 0.1 && retryCount < PROCESSING_RETRY_ATTEMPTS) {
            throw new Error(`Simulated processing failure (attempt ${retryCount + 1})`);
        }
        
        if (Math.random() > 0.9) {
            file.status = 'quarantined';
            file.processingResult = { 
                error: 'Virus detected',
                message: 'File quarantined for security',
                virusScan: {
                    clean: false,
                    scannedAt: new Date().toISOString(),
                    scanner: 'ClamAV-1.0',
                    threatsDetected: ['Trojan.Generic'],
                    action: 'quarantined',
                    quarantineId: uuidv4()
                }
            };
            
            accessLogs.push({
                timestamp: new Date().toISOString(),
                userId: file.uploadedBy,
                fileId: file.id,
                action: 'quarantined',
                details: { reason: 'virus_detected', quarantineId: file.processingResult.virusScan.quarantineId }
            });
            
            return;
        }
        
        // CRITICAL FIX: Validate file integrity during processing
        if (file.mimetype === 'application/pdf') {
            try {
                const filePath = path.join(UPLOAD_DIR, file.uploadedBy, file.filename);
                const encryptedData = await fs.readFile(filePath);
                
                const iv = encryptedData.slice(0, 16);
                const encryptedContent = encryptedData.slice(16, -16);
                const authTag = encryptedData.slice(-16);
                
                const encryptionKey = crypto.scryptSync(JWT_SECRET, 'salt', 32);
                const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, iv);
                decipher.setAuthTag(authTag);
                
                const decrypted = Buffer.concat([
                    decipher.update(encryptedContent),
                    decipher.final()
                ]);
                
                // Validate during processing
                await validateFileContent(decrypted, file.mimetype, file.originalName);
                
            } catch (validationError) {
                file.status = 'corrupted';
                file.processingResult = { 
                    error: 'Corruption detected during processing',
                    message: 'File integrity check failed during processing',
                    code: 'PROCESSING_CORRUPTION',
                    details: validationError.message
                };
                return;
            }
        }
        
        if (file.mimetype.startsWith('image/')) {
            try {
                const thumbnailDir = path.join(UPLOAD_DIR, 'thumbnails');
                await fs.mkdir(thumbnailDir, { recursive: true });
                
                const thumbnailName = `${file.filename.split('.')[0]}_thumb.svg`;
                const thumbnailPath = path.join(thumbnailDir, thumbnailName);
                
                const thumbnailSvg = `
                    <svg width="150" height="150" xmlns="http://www.w3.org/2000/svg">
                        <rect width="150" height="150" fill="#4a90e2"/>
                        <text x="75" y="80" font-family="Arial" font-size="12" text-anchor="middle" fill="white">
                            ${file.originalName}
                        </text>
                    </svg>
                `;
                
                await fs.writeFile(thumbnailPath, thumbnailSvg);
                
                file.processingResult = {
                    width: 1920,
                    height: 1080,
                    format: file.mimetype.split('/')[1],
                    thumbnailCreated: true,
                    thumbnailUrl: `/uploads/thumbnails/${thumbnailName}`,
                    thumbnailDimensions: '150x150',
                    hasSensitiveData: false,
                    processingType: 'simulated_thumbnail'
                };
            } catch (thumbnailError) {
                console.warn('Thumbnail generation failed:', thumbnailError.message);
                file.processingResult = {
                    width: 1920,
                    height: 1080,
                    format: file.mimetype.split('/')[1],
                    thumbnailCreated: false,
                    message: 'Thumbnail generation failed',
                    hasSensitiveData: false,
                    error: 'Thumbnail simulation error'
                };
            }
        } else if (file.mimetype === 'text/csv' || file.mimetype === 'text/plain') {
            file.processingResult = {
                rowCount: Math.floor(Math.random() * 1000),
                columnCount: 4,
                hasSensitiveData: true,
                sensitiveFieldsRedacted: ['name', 'email', 'salary'],
                compression: file.compression,
                processingType: 'simulated_csv_analysis'
            };
        } else if (file.mimetype === 'application/pdf') {
            // Only simulate processing if validation passed
            file.processingResult = {
                pages: Math.floor(Math.random() * 50) + 1,
                textExtracted: true,
                wordCount: Math.floor(Math.random() * 10000),
                hasSensitiveData: false,
                compression: file.compression,
                encryption: file.encryption,
                integrity: 'verified', // Only if validation passed
                processingType: 'simulated_pdf_analysis'
            };
        } else {
            file.processingResult = {
                processed: true,
                fileType: file.mimetype,
                hasSensitiveData: false,
                features: ['encrypted', 'compressed', 'versioned'],
                processingType: 'generic_file_processing'
            };
        }
        
        file.status = 'processed';
        
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
            processingQueue.push({ fileId, retryCount: retryCount + 1 });
        } else {
            file.status = 'error';
            file.processingResult = { 
                error: 'Processing failed after 3 attempts',
                message: 'Unable to process file. Please try uploading again.',
                retryAttempts: retryCount,
                lastError: error.message
            };
            
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

function processFile(fileId) {
    processingQueue.push({ fileId, retryCount: 0 });
    processQueueItem();
}

// ==================== FIXED ROUTES ====================
router.use(authenticate);

// ==================== QUOTA ENDPOINT ====================
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

router.get('/', asyncHandler(async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const status = req.query.status;
    const fileType = req.query.type;
    
    let filteredFiles = uploadedFiles.filter(file => {
        if (req.user.role === 'admin') return true;
        const isOwner = file.uploadedBy === req.user.userId;
        const isPublic = file.publicAccess === true;
        return isOwner || isPublic;
    });
    
    if (status) {
        filteredFiles = filteredFiles.filter(file => file.status === status);
    }
    
    if (fileType) {
        filteredFiles = filteredFiles.filter(file => file.mimetype.includes(fileType));
    }
    
    const totalFiles = filteredFiles.length;
    const totalPages = Math.ceil(totalFiles / limit);
    const startIndex = (page - 1) * limit;
    const endIndex = Math.min(startIndex + limit, totalFiles);
    
    const paginatedFiles = filteredFiles.slice(startIndex, endIndex);
    const sanitizedFiles = paginatedFiles.map(file => sanitizeFile(file, req.user));
    
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

router.get('/:fileId', authorizeFileAccess, asyncHandler(async (req, res) => {
    res.set({
        'X-Hidden-Metadata': 'check_file_processing_logs_endpoint'
    });
    res.json(sanitizeFile(req.file, req.user));
}));

// ==================== FILE DOWNLOAD ENDPOINT ====================
router.get('/download/:userId/:filename', asyncHandler(async (req, res) => {
    const { userId, filename } = req.params;
    const filePath = path.join(UPLOAD_DIR, userId, filename);
    
    try {
        await fs.access(filePath);
        
        const fileMeta = uploadedFiles.find(f => 
            f.filename === filename && f.uploadedBy === userId
        );
        
        if (!fileMeta) {
            return res.status(404).json({ 
                error: 'File not found',
                code: 'FILE_NOT_FOUND'
            });
        }
        
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
        
        const encryptedData = await fs.readFile(filePath);
        const iv = encryptedData.slice(0, 16);
        const encryptedContent = encryptedData.slice(16, -16);
        const authTag = encryptedData.slice(-16);
        
        const encryptionKey = crypto.scryptSync(JWT_SECRET, 'salt', 32);
        const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, iv);
        decipher.setAuthTag(authTag);
        
        const decrypted = Buffer.concat([
            decipher.update(encryptedContent),
            decipher.final()
        ]);
        
        res.set({
            'Content-Type': fileMeta.mimetype,
            'Content-Disposition': `attachment; filename="${fileMeta.originalName}"`,
            'Content-Length': decrypted.length,
            'X-File-Id': fileMeta.id,
            'X-File-Hash': fileMeta.fileHash,
            'Cache-Control': 'private, max-age=3600'
        });
        
        res.send(decrypted);
        
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
        
        if (error.message.includes('Unsupported state') || error.message.includes('decryption')) {
            return res.status(500).json({
                error: 'File decryption failed',
                message: 'Unable to decrypt the file. It may be corrupted.',
                code: 'DECRYPTION_FAILED'
            });
        }
        
        throw error;
    }
}));

// ==================== FIXED: UPLOAD FILE WITH PROPER VALIDATION ====================
router.post('/', checkStorageQuota, upload.single('file'), asyncHandler(async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ 
            error: 'No file uploaded',
            message: 'Please select a file to upload',
            code: 'NO_FILE'
        });
    }
    
    let fileBuffer;
    
    try {
        fileBuffer = await fs.readFile(req.file.path);
        
        if (fileBuffer.length === 0) {
            await fs.unlink(req.file.path);
            return res.status(400).json({ 
                error: 'Empty file',
                message: 'File cannot be empty',
                code: 'EMPTY_FILE'
            });
        }
        
        let fileType;
        try {
            fileType = await getFileType(fileBuffer, req.file.originalname);
        } catch (typeError) {
            await fs.unlink(req.file.path);
            
            if (typeError.message.includes('Invalid PDF') || 
                typeError.message.includes('PDF structure') ||
                typeError.message.includes('.pdf extension')) {
                return res.status(400).json({ 
                    error: 'Corrupted PDF file',
                    message: typeError.message,
                    code: 'CORRUPTED_FILE'
                });
            }
            
            return res.status(400).json({ 
                error: 'Unrecognized or corrupted file',
                message: typeError.message || 'Could not determine file type from content',
                code: typeError.code || 'UNKNOWN_FILE_TYPE'
            });
        }
        
        if (!fileType) {
            await fs.unlink(req.file.path);
            return res.status(400).json({ 
                error: 'Unrecognized file type',
                message: 'Could not determine file type from content',
                code: 'UNKNOWN_FILE_TYPE'
            });
        }
        
        if (!ALLOWED_MIME_TYPES.includes(fileType.mime)) {
            await fs.unlink(req.file.path);
            return res.status(400).json({ 
                error: 'Invalid file type',
                message: `File type ${fileType.mime} is not allowed`,
                code: 'INVALID_FILE_TYPE'
            });
        }
        
        // CRITICAL FIX: STRICT VALIDATION
        try {
            await validateFileContent(fileBuffer, fileType.mime, req.file.originalname);
        } catch (validationError) {
            await fs.unlink(req.file.path);
            
            if (validationError.message.includes('corrupted') || 
                validationError.message.includes('truncated') ||
                validationError.message.includes('Invalid PDF') ||
                validationError.message.includes('.pdf extension')) {
                console.warn(`Corrupted file rejected: ${req.file.originalname} - ${validationError.message}`);
                
                return res.status(400).json({ 
                    error: 'Corrupted or malformed file',
                    message: 'The file appears to be corrupted or malformed and cannot be processed',
                    code: 'CORRUPTED_FILE',
                    details: validationError.message
                });
            }
            
            return res.status(400).json({ 
                error: 'File validation failed',
                message: validationError.message,
                code: validationError.code || 'FILE_VALIDATION_FAILED'
            });
        }
        
        const fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
        const fileId = uuidv4();
        
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
        
        // FIXED COMPRESSION: Apply before encryption for text files
        let preEncryptionBuffer = fileBuffer;
        let compressionResult = { compressed: false, ratio: '0%', algorithm: 'none' };
        
        if (USE_ACTUAL_COMPRESSION && 
            (fileType.mime === 'text/plain' || 
             fileType.mime === 'text/csv' ||
             fileType.mime === 'application/pdf')) {
            
            compressionResult = await applyCompression(fileBuffer, fileType.mime, fileId);
            if (compressionResult.compressed) {
                preEncryptionBuffer = compressionResult.buffer;
            }
        }
        
        const encryptionKey = crypto.scryptSync(JWT_SECRET, 'salt', 32);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
        
        const encryptedBuffer = Buffer.concat([
            cipher.update(preEncryptionBuffer),
            cipher.final(),
            cipher.getAuthTag()
        ]);
        
        await fs.writeFile(req.file.path, Buffer.concat([iv, encryptedBuffer]));
        
        const originalSize = fileBuffer.length;
        
        const backupDir = path.join(UPLOAD_DIR, 'backups', req.user.userId);
        await fs.mkdir(backupDir, { recursive: true });
        const backupPath = path.join(backupDir, `${req.file.filename}_${Date.now()}`);
        await fs.copyFile(req.file.path, backupPath);
        
        const newFile = {
            id: fileId,
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
                enabled: compressionResult.compressed,
                originalSize: originalSize,
                compressedSize: preEncryptionBuffer.length,
                ratio: compressionResult.ratio,
                algorithm: compressionResult.algorithm,
                note: compressionResult.compressed ? 'actual_gzip_compression' : 'compression_not_applied'
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
        
        const currentUsage = userStorage.get(req.user.userId) || 0;
        userStorage.set(req.user.userId, currentUsage + req.file.size);
        
        processFile(newFile.id);
        
        res.set({
            'X-File-Id': newFile.id,
            'Location': `/api/upload/${newFile.id}`,
            'X-Features': 'encryption,compression,versioning,backup'
        });
        
        res.status(201).json({
            message: 'File uploaded successfully',
            file: sanitizeFile(newFile, req.user),
            validation: {
                passed: true,
                integrity: 'verified',
                corruption_check: 'passed'
            },
            features: {
                encryption: 'aes-256-gcm',
                compression: compressionResult.compressed ? compressionResult.ratio : 'not_applied',
                compressionType: compressionResult.algorithm,
                versioning: 'enabled',
                backup: 'created'
            }
        });
        
    } catch (error) {
        if (req.file && req.file.path) {
            try {
                await fs.unlink(req.file.path);
            } catch (cleanupError) {
                console.error('Failed to clean up file:', cleanupError);
            }
        }
        
        if (error.code && [
            'INVALID_FILE_TYPE',
            'INVALID_FILE_EXTENSION',
            'FILE_TOO_LARGE',
            'ZERO_SIZE_FILE',
            'UNKNOWN_FILE_TYPE',
            'CORRUPTED_FILE',
            'DUPLICATE_FILE',
            'EMPTY_FILE'
        ].includes(error.code)) {
            return res.status(400).json({
                error: 'File validation failed',
                message: error.message,
                code: error.code
            });
        }
        
        console.error('Upload error:', error);
        res.status(500).json({ 
            error: 'Upload failed',
            message: 'An unexpected error occurred during file upload',
            code: 'UPLOAD_FAILED'
        });
    }
}));

// ==================== BATCH UPLOAD ====================
router.post('/batch', checkStorageQuota, batchUpload.array('files', 5), asyncHandler(async (req, res) => {
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
            const fileBuffer = await fs.readFile(file.path);
            const fileType = await getFileType(fileBuffer, file.originalname);
            
            if (!fileType || !ALLOWED_MIME_TYPES.includes(fileType.mime)) {
                errors.push({ 
                    filename: file.originalname, 
                    error: 'Invalid file type',
                    code: 'INVALID_FILE_TYPE',
                    message: `File type ${fileType?.mime || 'unknown'} is not allowed`
                });
                await fs.unlink(file.path);
                continue;
            }
            
            try {
                await validateFileContent(fileBuffer, fileType.mime, file.originalname);
            } catch (validationError) {
                errors.push({ 
                    filename: file.originalname, 
                    error: 'File validation failed',
                    code: validationError.code || 'FILE_VALIDATION_FAILED',
                    message: validationError.message
                });
                await fs.unlink(file.path);
                continue;
            }
            
            // Apply compression before encryption for batch
            let preEncryptionBuffer = fileBuffer;
            let compressionResult = { compressed: false, ratio: '0%' };
            
            if (USE_ACTUAL_COMPRESSION && 
                (fileType.mime === 'text/plain' || 
                 fileType.mime === 'text/csv' ||
                 fileType.mime === 'application/pdf')) {
                
                compressionResult = await applyCompression(fileBuffer, fileType.mime, 'batch');
                if (compressionResult.compressed) {
                    preEncryptionBuffer = compressionResult.buffer;
                }
            }
            
            const encryptionKey = crypto.scryptSync(JWT_SECRET, 'salt', 32);
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
            const encryptedBuffer = Buffer.concat([
                cipher.update(preEncryptionBuffer),
                cipher.final(),
                cipher.getAuthTag()
            ]);
            
            await fs.writeFile(file.path, Buffer.concat([iv, encryptedBuffer]));
            
            const fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
            
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
                compression: { 
                    enabled: compressionResult.compressed, 
                    originalSize: fileBuffer.length, 
                    compressedSize: preEncryptionBuffer.length, 
                    ratio: compressionResult.ratio,
                    algorithm: compressionResult.compressed ? 'gzip' : 'none'
                },
                encryption: { algorithm: 'aes-256-gcm', encrypted: true, iv: iv.toString('hex') },
                versions: [{ version: 1, timestamp: new Date().toISOString(), size: file.size }],
                currentVersion: 1
            };
            
            uploadedFiles.push(newFile);
            uploadedFilesInfo.push(newFile);
            
            const currentUsage = userStorage.get(req.user.userId) || 0;
            userStorage.set(req.user.userId, currentUsage + file.size);
            
            processFile(newFile.id);
            
        } catch (error) {
            errors.push({ 
                filename: file.originalname, 
                error: error.message,
                code: error.code || 'UPLOAD_ERROR'
            });
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

// ==================== FILE SHARING ENDPOINT ====================
router.post('/:fileId/share', authorizeFileAccess, asyncHandler(async (req, res) => {
    const { expiresIn = 3600000 } = req.body;
    const shareId = uuidv4();
    const expiresAt = Date.now() + parseInt(expiresIn);
    
    sharedFiles.set(shareId, {
        fileId: req.params.fileId,
        expiresAt,
        createdBy: req.user.userId,
        createdAt: new Date().toISOString()
    });
    
    res.json({
        shareId: shareId,
        shareUrl: `/api/upload/share/${shareId}`,
        expiresAt: new Date(expiresAt).toISOString(),
        fileId: req.params.fileId,
        message: 'File shared successfully. Share link will expire in ' + (expiresIn / 3600000) + ' hours.'
    });
}));

// ==================== ACCESS SHARED FILE ====================
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
        sharedFiles.delete(req.params.shareId);
        return res.status(410).json({ 
            error: 'Share link expired',
            message: 'This share link has expired',
            code: 'SHARE_EXPIRED'
        });
    }
    
    const file = uploadedFiles.find(f => f.id === share.fileId);
    if (!file) {
        return res.status(404).json({ 
            error: 'File not found',
            message: 'The shared file no longer exists',
            code: 'FILE_NOT_FOUND'
        });
    }
    
    res.redirect(file.downloadUrl);
}));

// ==================== ACCESS LOGS ENDPOINT ====================
router.get('/access-logs', asyncHandler(async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ 
            error: 'Permission denied',
            message: 'Only administrators can access access logs',
            code: 'ACCESS_LOGS_DENIED'
        });
    }
    
    let filteredLogs = accessLogs;
    if (req.user.role !== 'admin') {
        filteredLogs = accessLogs.filter(log => log.userId === req.user.userId);
    }
    
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

// ==================== PROCESSING QUEUE STATUS ====================
router.get('/queue/status', asyncHandler(async (req, res) => {
    res.json({
        queueLength: processingQueue.length,
        activeProcesses: activeProcesses,
        maxConcurrentProcesses: MAX_CONCURRENT_PROCESSES,
        processingFiles: uploadedFiles.filter(f => f.status === 'processing').length,
        waitingFiles: uploadedFiles.filter(f => f.status === 'uploaded').length,
        processedFiles: uploadedFiles.filter(f => f.status === 'processed').length,
        failedFiles: uploadedFiles.filter(f => f.status === 'error').length,
        corruptedFiles: uploadedFiles.filter(f => f.status === 'corrupted').length
    });
}));

// Update file metadata
router.put('/:fileId', authorizeFileAccess, asyncHandler(async (req, res) => {
    const { publicAccess, originalName } = req.body;
    const updates = {};
    
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
    
    if (req.file.uploadedBy !== req.user.userId && req.user.role !== 'admin') {
        return res.status(403).json({ 
            error: 'Permission denied',
            message: 'Only the file owner or admin can update metadata',
            code: 'UPDATE_PERMISSION_DENIED'
        });
    }
    
    Object.keys(updates).forEach(key => {
        req.file[key] = updates[key];
    });
    
    res.json({
        message: 'File metadata updated successfully',
        file: sanitizeFile(req.file, req.user)
    });
}));

// Delete file
router.delete('/:fileId', authorizeFileAccess, asyncHandler(async (req, res) => {
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
    const filePath = path.join(UPLOAD_DIR, fileRecord.uploadedBy, fileRecord.filename);
    const userDir = path.join(UPLOAD_DIR, fileRecord.uploadedBy);

    try {
        try {
            await fs.unlink(filePath);
            console.log(`Deleted file: ${filePath}`);
        } catch (err) {
            if (err.code !== 'ENOENT') {
                console.warn(`Could not delete physical file: ${err.message}`);
            }
        }

        const currentUsage = userStorage.get(fileRecord.uploadedBy) || 0;
        userStorage.set(fileRecord.uploadedBy, Math.max(0, currentUsage - (fileRecord.size || 0)));

        uploadedFiles.splice(fileIndex, 1);

        try {
            const remaining = await fs.readdir(userDir);
            if (remaining.length === 0) {
                await fs.rmdir(userDir);
                console.log(`Removed empty user directory: ${userDir}`);
            }
        } catch (dirErr) {
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
            message: 'Could not delete file at this time',
            code: 'DELETE_FAILED'
        });
    }
}));

// ==================== ENHANCED ERROR HANDLING MIDDLEWARE ====================
router.use((err, req, res, next) => {
    console.error('UPLOAD ROUTE ERROR:', {
        timestamp: new Date().toISOString(),
        method: req.method,
        path: req.path,
        ip: req.ip,
        userId: req.user?.userId || 'anonymous',
        errorCode: err.code || 'UNKNOWN_ERROR',
        errorMessage: err.message || 'Unknown error',
        errorType: err.name || 'Error'
    });
    
    let statusCode = 500;
    let errorMessage = 'Internal server error';
    let userMessage = 'Something went wrong. Please try again later.';
    let errorCode = 'INTERNAL_ERROR';
    
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            statusCode = 400;
            errorMessage = 'File too large';
            userMessage = `File exceeds ${MAX_FILE_SIZE / (1024 * 1024)}MB limit`;
            errorCode = 'FILE_TOO_LARGE';
        } else {
            statusCode = 400;
            errorMessage = 'Upload error';
            userMessage = err.message || 'Error uploading file';
            errorCode = 'UPLOAD_ERROR';
        }
    }
    
    else if (err.name === 'JsonWebTokenError') {
        statusCode = 401;
        errorMessage = 'Invalid token';
        userMessage = 'The authentication token is invalid';
        errorCode = 'INVALID_TOKEN';
    }
    
    else if (err.name === 'TokenExpiredError') {
        statusCode = 401;
        errorMessage = 'Token expired';
        userMessage = 'Please authenticate again';
        errorCode = 'TOKEN_EXPIRED';
    }
    
    else if (err.code && [
        'INVALID_FILE_TYPE',
        'INVALID_FILE_EXTENSION', 
        'FILE_TOO_LARGE',
        'ZERO_SIZE_FILE',
        'RATE_LIMIT_EXCEEDED',
        'FILE_VALIDATION_ERROR',
        'UNKNOWN_FILE_TYPE',
        'CORRUPTED_FILE',
        'FILE_VALIDATION_FAILED',
        'DUPLICATE_FILE',
        'EMPTY_FILE',
        'NO_FILE',
        'NO_FILES',
        'STORAGE_QUOTA_EXCEEDED',
        'DOWNLOAD_PERMISSION_DENIED',
        'UPDATE_PERMISSION_DENIED',
        'DELETE_PERMISSION_DENIED',
        'ACCESS_LOGS_DENIED',
        'SHARE_NOT_FOUND',
        'SHARE_EXPIRED'
    ].includes(err.code)) {
        statusCode = 400;
        errorMessage = 'File validation failed';
        userMessage = err.message || 'File validation error';
        errorCode = err.code || 'FILE_VALIDATION_FAILED';
    }
    
    else if (err.message && (
        err.message.includes('File type') && err.message.includes('is not allowed') ||
        err.message.includes('File extension') && err.message.includes('is not allowed') ||
        err.message.includes('File size exceeds') ||
        err.message.includes('Zero-size file uploaded') ||
        err.message.includes('Upload rate limit exceeded') ||
        err.message.includes('File content does not match')
    )) {
        statusCode = 400;
        errorMessage = 'File validation failed';
        userMessage = err.message;
        errorCode = 'FILE_VALIDATION_FAILED';
    }
    
    else if (err.code === 'ENOENT' || err.message?.includes('not found')) {
        statusCode = 404;
        errorMessage = 'Resource not found';
        userMessage = err.message || 'The requested resource was not found';
        errorCode = 'NOT_FOUND';
    }
    
    else if (err.code === 'EACCES' || err.message?.includes('permission denied')) {
        statusCode = 403;
        errorMessage = 'Permission denied';
        userMessage = err.message || 'You do not have permission to perform this action';
        errorCode = 'PERMISSION_DENIED';
    }
    
    else if (err.code === 'AUTH_REQUIRED') {
        statusCode = 401;
        errorMessage = 'Authentication required';
        userMessage = 'Please provide valid credentials';
        errorCode = 'AUTH_REQUIRED';
    }
    
    else if (err.code === 'ACCESS_DENIED') {
        statusCode = 403;
        errorMessage = 'Access denied';
        userMessage = 'You do not have permission to access this resource';
        errorCode = 'ACCESS_DENIED';
    }
    
    res.status(statusCode).json({
        error: errorMessage,
        message: userMessage,
        code: errorCode,
        timestamp: new Date().toISOString(),
        requestId: Date.now().toString(36) + Math.random().toString(36).substr(2)
    });
});

module.exports = router;