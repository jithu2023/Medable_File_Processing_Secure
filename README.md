# 📁 Assessment 4: File Upload/Processing API

Welcome to the File Upload/Processing API assessment! This project simulates a file processing system with **critical file security vulnerabilities**, **broken error handling**, and **incomplete processing features** that you need to identify and fix.

## 🎯 Objective

Your mission is to:
1. **🔒 Fix file upload security** and validation vulnerabilities
2. **⚠️ Implement proper error handling** throughout the system
3. **⚡ Complete missing processing features** for various file types
4. **🧩 Solve the multi-layered puzzle chain** with encoding challenges

## 🚀 Getting Started

### Prerequisites
- Node.js (v18 or higher)
- npm or yarn
- Netlify CLI (for local development)

### Installation

```bash
npm install
npm run dev
```

The API will be available at `http://localhost:8888`

## 📚 API Documentation

### File Management Endpoints

#### GET /api/upload
Get user's uploaded files
```bash
curl "http://localhost:8888/api/upload?page=1&limit=20&status=processed"
```

#### GET /api/upload/:fileId
Get specific file information
```bash
curl http://localhost:8888/api/upload/file-001
```

#### POST /api/upload
Upload new file (mock implementation)
```bash
curl -X POST http://localhost:8888/api/upload \
  -H "Content-Type: multipart/form-data" \
  -F "file=@document.pdf"
```

#### PUT /api/upload/:fileId
Update file metadata
```bash
curl -X PUT http://localhost:8888/api/upload/file-001 \
  -H "Content-Type: application/json" \
  -d '{"publicAccess": true}'
```

#### DELETE /api/upload/:fileId
Delete uploaded file
```bash
curl -X DELETE http://localhost:8888/api/upload/file-001
```

## 📂 Sample Files for Testing

| File ID | Name | Type | Size | Status | Issues |
|---------|------|------|------|---------|---------|
| file-001 | sample-document.pdf | PDF | 2MB | processed | Exposes extracted text |
| file-002 | company-data.csv | CSV | 1MB | processing | Marked public, sensitive data |
| file-003 | corrupted-image.jpg | JPEG | 0 bytes | error | Zero-size file accepted |

## 🚨 Critical Security Vulnerabilities

### File Upload Security Issues
1. **No File Type Validation** - Any file type accepted
2. **Zero-Size Files Accepted** - Empty files processed successfully
3. **No Virus Scanning** - Malicious files could be uploaded
4. **Predictable Filenames** - Easy to guess file URLs
5. **No Size Limits Enforced** - Could accept enormous files
6. **Anonymous Uploads Allowed** - No authentication required
7. **No File Content Validation** - Files not checked for corruption

### Access Control Vulnerabilities
8. **Broken File Ownership** - Users can access others' files
9. **Public Access Bypass** - Public flag overrides security
10. **No Authentication for Listing** - Anyone can see all files
11. **Uploader Information Exposed** - User data leaked in responses
12. **Admin Escalation** - Admin users see all processing details

### Data Exposure Issues
13. **Processing Results Exposed** - Sensitive extracted data visible
14. **Internal Paths Revealed** - Server file paths in responses
15. **Error Details Leaked** - Stack traces and internal errors exposed
16. **Processing Server Info** - Infrastructure details revealed

## ⚠️ Error Handling Problems

### Critical Error Handling Issues
1. **Silent Authentication Failures** - Auth errors don't stop processing
2. **Processing Errors Exposed** - Internal errors visible to users
3. **Stack Traces in Development** - Full stack traces returned
4. **No Retry Mechanisms** - Failed processing not retried
5. **Incomplete Error Recovery** - Partial failures leave system in bad state
6. **No Error Logging** - Errors not properly logged for debugging
7. **Resource Cleanup Issues** - Failed uploads leave temp files

### Missing Error Validation
8. **No Input Sanitization** - User inputs not validated
9. **Missing Required Fields** - Required data not enforced
10. **Invalid File Format Handling** - Corrupted files crash processing
11. **Memory Limit Violations** - Large files can crash server
12. **Network Timeout Handling** - Long uploads timeout without recovery

## ⚡ Missing Features to Implement

### Core File Processing Features
1. **Actual File Storage** - Files aren't actually saved anywhere
2. **Virus Scanning Integration** - No malware detection
3. **File Type Detection** - Validate file types by content, not extension
4. **Thumbnail Generation** - Create previews for images and documents
5. **File Compression** - Optimize storage with compression
6. **Backup and Recovery** - Backup uploaded files
7. **File Versioning** - Track file updates and versions

### Processing Pipeline Features
8. **Queue Management** - Proper job queue for processing
9. **Progress Tracking** - Real-time processing status updates
10. **Batch Processing** - Process multiple files together
11. **Processing Retry Logic** - Retry failed processing jobs
12. **Resource Management** - Limit concurrent processing jobs

### Advanced Features
13. **File Encryption** - Encrypt stored files
14. **Access Logs** - Track file access and downloads
15. **File Sharing** - Secure file sharing with expiration
16. **API Rate Limiting** - Prevent API abuse
17. **Storage Quotas** - Per-user storage limits

## 🧩 Multi-Layered Puzzle Chain

### Puzzle 1: Header Discovery 🔍
Find the hidden hint in API response headers.
- **Location**: Check `X-Hidden-Metadata` header in `/api/upload` responses
- **Hint**: `"check_file_processing_logs_endpoint"`
- **Challenge**: Discover what this means and where to find it
- **Reward**: Access to hidden processing logs endpoint

### Puzzle 2: Processing Logs Access 📋
Find and access the secret processing logs system.
- **Endpoint**: `/api/processing-logs`
- **Access Method 1**: JWT Token (basic access to non-classified logs)
- **Access Method 2**: `?access=PROC_LOGS_ADMIN_2024` (admin access)
- **Access Method 3**: `X-System-Key: system-processing-key-2024` (full system access)
- **Log Levels**: `?level=basic|detailed|full`
- **Reward**: Sensitive processing information and next clue

### Puzzle 3: Base64 Decoding 🔐
Decode the Base64 message from system access logs.
- **Access Required**: System-level access to processing logs
- **Location**: `secretHint` field in system access response
- **Encoded Message**: `VGhlIGZpbmFsIHNlY3JldCBpcyBoaWRkZW4gaW4gdGhlIGFyY2hpdmUgZG93bmxvYWQgZW5kcG9pbnQgd2l0aCBrZXk6IEFSR0hJVkVfTUFTVEVSXzIwMjQ=`
- **Decoded Message**: "The final secret is hidden in the archive download endpoint with key: ARCHIVE_MASTER_2024"
- **Reward**: Location and key for final challenge

### Puzzle 4: Archive Master Access 🏆
Access the ultimate archive system with master privileges.
- **Endpoint**: `/api/archive`
- **Master Access Method 1**: `X-Archive-Key: ARCHIVE_MASTER_2024`
- **Master Access Method 2**: `?master_key=ARCHIVE_MASTER_2024`
- **Challenge**: XOR encrypted final message
- **Reward**: Ultimate achievement and system mastery recognition

## 🔧 Testing Your Solutions

### File Security Testing
```bash
# Test file upload with various file types
curl -X POST http://localhost:8888/api/upload \
  -H "Content-Type: multipart/form-data" \
  -F "file=@malicious.exe"

# Test zero-size file handling
touch empty.txt
curl -X POST http://localhost:8888/api/upload \
  -H "Content-Type: multipart/form-data" \
  -F "file=@empty.txt"

# Test unauthorized file access
curl http://localhost:8888/api/upload/file-001
```

### Error Handling Testing
```bash
# Test malformed JSON
curl -X PUT http://localhost:8888/api/upload/file-001 \
  -H "Content-Type: application/json" \
  -d '{"invalid": json}'

# Test non-existent file
curl http://localhost:8888/api/upload/nonexistent
```

### Processing Logs Testing
```bash
# Test basic access
curl http://localhost:8888/api/processing-logs

# Test admin access
curl "http://localhost:8888/api/processing-logs?access=PROC_LOGS_ADMIN_2024&level=detailed"

# Test system access
curl -H "X-System-Key: system-processing-key-2024" \
     "http://localhost:8888/api/processing-logs?level=full"
```

### Archive System Testing
```bash
# Test basic archive access
curl http://localhost:8888/api/archive

# Test master access
curl -H "X-Archive-Key: ARCHIVE_MASTER_2024" \
     http://localhost:8888/api/archive

# Test with master key in query
curl "http://localhost:8888/api/archive?master_key=ARCHIVE_MASTER_2024"
```

## 📝 Expected Solutions

### Security Fixes
1. **File Type Validation** - Check MIME types and file headers
2. **Size Limits** - Enforce maximum file sizes per type
3. **Virus Scanning** - Integrate malware detection
4. **Authentication Required** - All operations need valid tokens
5. **Access Control** - Proper ownership verification
6. **Input Sanitization** - Validate all user inputs
7. **Secure Filename Generation** - Use UUIDs instead of predictable names

### Error Handling Implementation
1. **Centralized Error Handling** - Consistent error responses
2. **Proper HTTP Status Codes** - Use appropriate codes for each error
3. **Error Logging** - Log errors for debugging without exposing details
4. **Graceful Degradation** - Handle failures without breaking system
5. **Resource Cleanup** - Clean up resources on errors
6. **Retry Logic** - Automatic retry for transient failures

### Feature Implementation
1. **Real File Storage** - Implement actual file saving (filesystem or cloud)
2. **Processing Queue** - Background job processing
3. **Progress Updates** - Real-time processing status
4. **File Validation** - Content-based file type detection
5. **Thumbnail Generation** - Create previews for supported file types

## 🏆 Puzzle Solutions Guide

### Complete Puzzle Walkthrough

#### Step 1: Header Discovery
```bash
curl http://localhost:8888/api/upload -I
# Look for X-Hidden-Metadata: check_file_processing_logs_endpoint
```

#### Step 2: Processing Logs
```bash
# Try the endpoint
curl http://localhost:8888/api/processing-logs

# Try admin access
curl "http://localhost:8888/api/processing-logs?access=PROC_LOGS_ADMIN_2024&level=detailed"

# System access for secret hint
curl -H "X-System-Key: system-processing-key-2024" \
     "http://localhost:8888/api/processing-logs?level=full"
```

#### Step 3: Base64 Decoding
```bash
# Decode the message from secretHint field
echo "VGhlIGZpbmFsIHNlY3JldCBpcyBoaWRkZW4gaW4gdGhlIGFyY2hpdmUgZG93bmxvYWQgZW5kcG9pbnQgd2l0aCBrZXk6IEFSR0hJVkVfTUFTVEVSXzIwMjQ=" | base64 -d
# Output: "The final secret is hidden in the archive download endpoint with key: ARCHIVE_MASTER_2024"
```

#### Step 4: Archive Master Access
```bash
# Use the discovered key
curl -H "X-Archive-Key: ARCHIVE_MASTER_2024" \
     http://localhost:8888/api/archive

# Achievement unlocked: FILE_PROCESSING_MASTER_2024
# XOR decrypted message: "SECRET_ARCHIVE_ACCESS_UNLOCKED_CONGRATULATIONS_FILE_MASTER_ACHIEVEMENT_2024"
```

## 🚨 Common Pitfalls

1. **Don't just remove vulnerabilities** - Implement secure alternatives
2. **Test with actual files** - Don't rely only on mock data
3. **Handle edge cases** - Empty files, huge files, corrupted files
4. **Implement proper cleanup** - Remove temp files and failed uploads
5. **Consider performance** - Large file uploads and processing
6. **Maintain API compatibility** - Don't break existing endpoints

## 📊 Evaluation Criteria

### Security Implementation (30%)
- All file upload vulnerabilities properly fixed
- Access control correctly implemented
- No new security issues introduced
- Secure file handling practices

### Error Handling (25%)
- Comprehensive error handling throughout
- Proper HTTP status codes and responses
- Resource cleanup on failures
- User-friendly error messages without data leakage

### Feature Implementation (25%)
- Missing processing features completed
- File storage actually implemented
- Processing pipeline working correctly
- Performance considerations addressed

### Problem Solving (20%)
- All puzzles solved correctly
- Understanding of encoding/encryption concepts
- Creative solutions to complex challenges
- System design knowledge demonstrated

## 🛠️ Development Tips

### File Processing Best Practices
```javascript
// Proper file validation
const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
const maxSize = 10 * 1024 * 1024; // 10MB

// Secure filename generation
const filename = `${uuidv4()}.${getFileExtension(originalName)}`;

// Error handling wrapper
try {
  await processFile(fileData);
} catch (error) {
  logger.error('Processing failed:', error);
  return sanitizeError(error);
}
```

### Security Considerations
- Always validate file contents, not just extensions
- Implement virus scanning before processing
- Use secure random filenames
- Store files outside web root
- Implement access logging
- Rate limit file uploads

### Performance Optimization
- Use streaming for large file uploads
- Implement background processing queues
- Add file compression
- Cache frequently accessed files
- Implement lazy loading for file lists

## 📞 Support

Document your approach to solving complex file processing challenges:
- File validation strategies
- Error handling patterns
- Security threat mitigation
- Processing pipeline design
- Performance optimization techniques

**Good luck building a secure, robust file processing system! 🚀📁**
