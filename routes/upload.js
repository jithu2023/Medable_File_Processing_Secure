const express = require('express');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');
const multer = require('multer');
const { fileTypeFromBuffer } = require('file-type');

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

// ==================== SETUP ====================
// Track user storage and upload rates
const userStorage = new Map();
const userUploadRates = new Map();
const processingQueue = new Map();

// Ensure upload directory exists
(async () => {
    try {
        await fs.access(UPLOAD_DIR);
    } catch {
        await fs.mkdir(UPLOAD_DIR, { recursive: true });
        console.log(`✅ Created upload directory: ${UPLOAD_DIR}`);
    }
})();

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
        downloadUrl: '/uploads/user1/sample-document-123.pdf',
        publicAccess: false,
        fileHash: 'a1b2c3d4e5f678901234567890abcdef1234567890abcdef'
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
        downloadUrl: '/uploads/admin/company-data-456.csv',
        publicAccess: false, // FIXED: Sensitive data no longer public
        fileHash: 'b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1'
    },
    {
        id: 'file-003',
        originalName: 'product-image.jpg',
        filename: 'product-image-789.jpg',
        mimetype: 'image/jpeg',
        size: 524288, // FIXED: Non-zero size
        uploadedBy: 'user2',
        uploadDate: new Date('2024-01-03').toISOString(),
        status: 'processed',
        processingResult: {
            width: 1920,
            height: 1080,
            format: 'jpeg',
            size: 524288,
            thumbnailCreated: true,
            hasSensitiveData: false
        },
        downloadUrl: '/uploads/user2/product-image-789.jpg',
        publicAccess: true,
        fileHash: 'c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2'
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

// ==================== FIXED ROUTES ====================

// Apply authentication to all routes
router.use(authenticate);

// Fixed: Get user files with proper pagination and security
router.get('/', asyncHandler(async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 100); // Fixed: Reasonable default
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
        'X-Per-Page': limit.toString()
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
    res.json(sanitizeFile(req.file, req.user));
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
        
        // Create file record
        const newFile = {
            id: uuidv4(),
            originalName: req.file.originalname,
            filename: req.file.filename,
            mimetype: fileType.mime,
            size: req.file.size,
            uploadedBy: req.user.userId, // Fixed: No anonymous uploads
            uploadDate: new Date().toISOString(),
            status: 'uploaded',
            processingResult: null,
            downloadUrl: `/uploads/${req.user.userId}/${req.file.filename}`,
            publicAccess: req.body.publicAccess === 'true' || false, // Fixed: Configurable public access
            fileHash: fileHash
        };
        
        uploadedFiles.push(newFile);
        
        // Update user storage
        const currentUsage = userStorage.get(req.user.userId) || 0;
        userStorage.set(req.user.userId, currentUsage + req.file.size);
        
        // Start processing
        setTimeout(() => processFile(newFile.id), 100);
        
        res.set({
            'X-File-Id': newFile.id,
            'Location': `/api/upload/${newFile.id}`
        });
        
        res.status(201).json({
            message: 'File uploaded successfully',
            file: sanitizeFile(newFile, req.user)
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

// router.post("/", (req, res)=>{
//     res.send("success");
// })

// Fixed: Update file metadata with validation
router.put('/:fileId', authorizeFileAccess, asyncHandler(async (req, res) => {
     const updateData = req.body;

     const allowedFields = ['publicAccess', 'originalName'];
    const file = req.file;
    Object.keys(updateData).forEach(key => {
      if (allowedFields.includes(key)) {
        file[key] = updateData[key];
      } else {
        //fixed invalid field update attempt
        return res.status(400).json({ 
            error: 'Invalid field',
            message: `Field '${key}' is not allowed`,
            code: 'INVALID_FIELD'
        });
      }
    });


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

// router.delete('/:fileId', authorizeFileAccess, asyncHandler(async (req, res) => {
//     // Fixed: Check ownership
//     if (req.file.uploadedBy !== req.user.userId && req.user.role !== 'admin') {
//         return res.status(403).json({ 
//             error: 'Permission denied',
//             message: 'Only the file owner or admin can delete this file',
//             code: 'DELETE_PERMISSION_DENIED'
//         });
//     }
    
//     const fileIndex = uploadedFiles.findIndex(f => f.id === req.file.id);
    
//     try {
//         // Fixed: Delete physical file
//         const filePath = path.join(UPLOAD_DIR, req.file.uploadedBy, req.file.filename);
//         await fs.unlink(filePath);
        
//         // Update user storage
//         const currentUsage = userStorage.get(req.user.userId) || 0;
//         userStorage.set(req.user.userId, Math.max(0, currentUsage - req.file.size));

//         await fs.rmdir(userDir);
        
//     } catch (error) {
//         console.warn(`Could not delete physical file:`, error.message);
//     }
    
//     // Remove from array
//     uploadedFiles.splice(fileIndex, 1);
    
//     res.json({ 
//         message: 'File deleted successfully',
//         fileId: req.file.id
//     });
// }));

// Fixed: File processing function
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
  const filePath = path.join(process.env.UPLOAD_DIR, String(fileRecord.uploadedBy), fileRecord.filename);
  const userDir = path.join(process.env.UPLOAD_DIR, String(fileRecord.uploadedBy));

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


function processFile(fileId) {
    const file = uploadedFiles.find(f => f.id === fileId);
    if (!file) return;
    
    try {
        file.status = 'processing';
        
        // Simulate processing based on file type
        if (file.mimetype.startsWith('image/')) {
            if (file.size === 0) {
                throw new Error('Corrupted file header');
            }
            file.processingResult = {
                width: 1920,
                height: 1080,
                format: 'jpeg',
                thumbnailCreated: true,
                hasSensitiveData: false
            };
        } else if (file.mimetype === 'text/csv') {
            // Fixed: No exposure of sensitive data
            file.processingResult = {
                rowCount: Math.floor(Math.random() * 1000),
                columnCount: 4,
                hasSensitiveData: true,
                sensitiveFieldsRedacted: ['name', 'email', 'salary']
            };
        } else if (file.mimetype === 'application/pdf') {
            file.processingResult = {
                pages: Math.floor(Math.random() * 50) + 1,
                textExtracted: true,
                wordCount: Math.floor(Math.random() * 10000),
                hasSensitiveData: false
            };
        } else {
            file.processingResult = {
                processed: true,
                fileType: file.mimetype,
                hasSensitiveData: false
            };
        }
        
        file.status = 'processed';
    } catch (error) {
        file.status = 'error';
        file.processingResult = { 
            error: 'Processing failed',
            message: 'Unable to process file. The file may be corrupted or unsupported.'
        };
    }
}

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