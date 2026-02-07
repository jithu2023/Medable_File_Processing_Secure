# 🚀 Railway Deployment Guide

## Quick Deploy
[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template?template=https://github.com/YOUR_USERNAME/assessment-4)

## Manual Deployment Steps

### 1. Create Railway Account
1. Go to [railway.app](https://railway.app)
2. Sign up with GitHub
3. Authorize Railway

### 2. Create New Project
1. Click "New Project"
2. Select "Deploy from GitHub repo"
3. Connect your repository
4. Click "Deploy Now"

### 3. Set Environment Variables
Add these variables in Railway dashboard:

| Variable | Value | Required |
|----------|-------|----------|
| `JWT_SECRET` | `generate-a-strong-secret-here` | ✅ Yes |
| `NODE_ENV` | `production` | ✅ Yes |
| `PORT` | `8888` | ✅ Yes |
| `MAX_FILE_SIZE` | `10485760` | ✅ Yes |
| `UPLOAD_DIR` | `./uploads` | ✅ Yes |

### 4. Generate JWT Secret
```bash
# Run this in terminal to generate a secret
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"