# 🚀 Railway Deployment Guide

## Quick Deploy
[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template?template=https://github.com/YOUR_USERNAME/file-upload-processing-api)

## Prerequisites
- GitHub account with the repository
- Railway account (free tier available)

## Manual Deployment Steps

### 1. Create Railway Account
1. Go to [railway.app](https://railway.app)
2. Click "Start a New Project"
3. Sign up with GitHub
4. Authorize Railway application

### 2. Create New Project
1. From Railway dashboard, click "New Project"
2. Select "Deploy from GitHub repo"
3. Search for your repository: `YOUR_USERNAME/file-upload-processing-api`
4. Click "Deploy Now"

### 3. Configure Environment Variables
In Railway dashboard, go to your project → **Variables** tab:

Add these required variables:

| Variable | Example Value | Description |
|----------|---------------|-------------|
| `JWT_SECRET` | `your-super-secret-jwt-key-32-chars-min` | Secret for JWT token signing |
| `PORT` | `3000` | Port for the application (Railway auto-assigns) |
| `NODE_ENV` | `production` | Environment mode |
| `MAX_FILE_SIZE` | `10485760` | Maximum file size in bytes (10MB) |
| `UPLOAD_DIR` | `/tmp/uploads` | Temporary upload directory |

### 4. Generate Strong JWT Secret (Optional but Recommended)
```bash
# Generate a secure 64-character hex string
openssl rand -hex 32

# Or use Node.js if you have it installed
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 5. Configure Deployment Settings
In Railway dashboard → **Settings** tab:

1. **Build Command:** (leave empty for automatic detection)
2. **Start Command:** `npm start`
3. **Health Check Path:** `/health`
4. **Root Directory:** `/`

### 6. Set Up Custom Domain (Optional)
1. Go to **Settings** → **Domains**
2. Click "Generate Domain" for a Railway subdomain
3. Or add your custom domain

### 7. Monitor Deployment
Check the **Deployments** tab:
- ✅ Green = Successfully deployed
- 🟡 Yellow = Building
- 🔴 Red = Failed (check logs)

## Post-Deployment Verification

### 1. Test API Endpoints
```bash
# Health check
curl https://your-app.railway.app/health

# Test authentication
curl -X POST https://your-app.railway.app/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

### 2. Check Logs
In Railway dashboard → **Logs** tab:
- Monitor application logs
- Debug any startup issues
- Check for error messages

### 3. File Upload Test
```bash
# Test file upload
curl -X POST https://your-app.railway.app/api/files/upload \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -F "file=@test.jpg"
```

## Important Notes for Railway

### 1. Ephemeral Storage
⚠️ **Warning:** Railway uses ephemeral storage. Uploaded files will be lost on redeploy. For production:
- Use external storage (S3, Cloudinary, etc.)
- Implement database for metadata
- Add cleanup cron jobs

### 2. Memory Limits
- Free tier: 512MB RAM
- Upgrade for larger file processing

### 3. Auto-Deploy
- Pushes to `main` branch trigger automatic redeploys
- Disable in **Settings** → **Git** if needed

## Troubleshooting

### Common Issues:

| Issue | Solution |
|-------|----------|
| "Application failed to start" | Check `PORT` variable matches Railway's assigned port |
| "JWT verification failed" | Ensure `JWT_SECRET` is the same across deployments |
| "File upload fails" | Check `MAX_FILE_SIZE` and disk space |
| "Cannot write to directory" | Use `/tmp` for temporary storage |

### View Detailed Logs:
```bash
# In Railway dashboard → Logs tab
# Or use Railway CLI
railway logs
```

### Restart Application:
1. Go to **Deployments** tab
2. Click "Redeploy" on latest deployment

## Updating Your Application

### Method 1: Git Push
```bash
git add .
git commit -m "Update application"
git push origin main
# Railway automatically deploys
```

### Method 2: Railway CLI
```bash
# Install Railway CLI
npm i -g @railway/cli

# Login and deploy
railway login
railway link
railway up
```

## Cost Management

### Free Tier Limits:
- 500 hours/month (about 20 days)
- 512MB RAM
- 1GB disk space
- Unlimited deploys

### Upgrade When:
- Need 24/7 uptime
- Processing large files
- High traffic volume

## Security Best Practices

1. **Rotate `JWT_SECRET`** periodically
2. **Use environment variables** for all secrets
3. **Enable monitoring** in Railway dashboard
4. **Set up alerts** for critical errors
5. **Regularly update** dependencies

## Support Resources

- [Railway Documentation](https://docs.railway.app/)
- [Discord Community](https://discord.gg/railway)
- [GitHub Issues](https://github.com/railwayapp/issues)

---

## 🎯 Quick Start Checklist
- [ ] Repository connected to Railway
- [ ] Environment variables set
- [ ] Application deployed successfully
- [ ] Health check passing
- [ ] File upload tested
- [ ] Monitoring configured

## 📞 Need Help?
1. Check Railway logs
2. Review application logs
3. Test locally first
4. Join Railway Discord

**Deployment Time:** Typically 2-5 minutes for initial deployment.

**Remember:** The free tier is great for testing and development. For production workloads with persistent file storage, consider upgrading or integrating with external storage services.