# 🚀 PhishGuard API Deployment Guide (Separate Repository)

Since you have the API in a **separate repository**, follow these steps:

---

## 📦 What You Need in Your API Repository

Your `api` folder should contain:
- ✅ `app.py` - Flask application
- ✅ `requirements.txt` - Python dependencies
- ✅ `render.yaml` - Render configuration
- ❗ `phishing_model.pkl` - ML model file (54 MB)

---

## 🔧 Step 1: Add Model File to API Repository

The model file is currently in the parent folder. Copy it to your API repository:

```powershell
# From the api folder
Copy-Item ..\phishing_model.pkl .
```

Or if you're in the parent folder:
```powershell
Copy-Item phishing_model.pkl api\
```

Then add to git:
```powershell
cd api
git add phishing_model.pkl
git commit -m "Add trained model file"
git push
```

**Note**: If the file is >100MB, use Git LFS:
```powershell
git lfs install
git lfs track "*.pkl"
git add .gitattributes phishing_model.pkl
git commit -m "Add model with Git LFS"
git push
```

---

## 🌐 Step 2: Deploy to Render

### Option A: Using render.yaml (Recommended)

1. Go to [Render Dashboard](https://dashboard.render.com)
2. Click **"New +"** → **"Blueprint"**
3. Connect your GitHub repository (the API repo)
4. Render will auto-detect `render.yaml`
5. Click **"Apply"**
6. Wait 3-5 minutes for deployment

### Option B: Manual Web Service

1. Go to [Render Dashboard](https://dashboard.render.com)
2. Click **"New +"** → **"Web Service"**
3. Connect your GitHub repository (the API repo)
4. Configure:
   - **Name**: `phishguard-api`
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
   - **Branch**: `main`

5. Add Environment Variables:
   - `PYTHON_VERSION` = `3.11.0`
   - `MODEL_PATH` = `phishing_model.pkl`

6. Click **"Create Web Service"**

---

## ✅ Step 3: Verify Deployment

After deployment completes, test your API:

### Health Check
```bash
curl https://phishguard-api.onrender.com/api/health
```

Expected response:
```json
{
  "status": "healthy",
  "model_loaded": true,
  "deep_mode_available": true
}
```

### Test Scan
```bash
curl -X POST https://phishguard-api.onrender.com/api/scan \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"facebook.com\", \"mode\": \"fast\"}"
```

Expected response:
```json
{
  "url": "facebook.com",
  "decision": "LEGITIMATE",
  "confidence": 87.5,
  ...
}
```

---

## 🎨 Step 4: Update Frontend Repository

If you have a separate frontend repository, update the API URL:

In your `web/script.js`:
```javascript
const API_URL = 'https://phishguard-api.onrender.com'; // Your Render URL
```

Then push:
```bash
git add web/script.js
git commit -m "Update API URL to production"
git push
```

Vercel will auto-deploy the frontend.

---

## 📂 Your Repository Structure

### API Repository (phish-ui or similar)
```
api/
├── .git/
├── app.py
├── requirements.txt
├── render.yaml
└── phishing_model.pkl  ← ADD THIS!
```

### Frontend Repository (separate)
```
web/
├── .git/
├── index.html
├── style.css
├── script.js
└── vercel.json
```

---

## 🐛 Troubleshooting

### Error: "Could not open requirements file"
**Cause**: `render.yaml` has wrong path (`api/requirements.txt`)  
**Solution**: Update `render.yaml`:
```yaml
buildCommand: pip install -r requirements.txt  # Not api/requirements.txt
startCommand: gunicorn app:app  # Not cd api && ...
```

### Error: "Model not loading"
**Cause**: `phishing_model.pkl` not in repository  
**Solution**: 
```powershell
cd api
Copy-Item ..\phishing_model.pkl .
git add phishing_model.pkl
git commit -m "Add model"
git push
```

### Error: "Module not found"
**Cause**: Missing dependencies in `requirements.txt`  
**Solution**: Check `requirements.txt` contains all:
- Flask==3.0.0
- flask-cors==4.0.0
- scikit-learn==1.3.2
- pandas==2.1.4
- numpy==1.26.2
- joblib==1.3.2
- tldextract==5.1.1
- requests==2.31.0
- beautifulsoup4==4.12.2
- gunicorn==21.2.0

---

## 📊 Deployment Checklist

- [ ] `phishing_model.pkl` copied to api folder
- [ ] All files committed and pushed to GitHub
- [ ] `render.yaml` paths are correct (no `api/` prefix)
- [ ] Render service created and deployed
- [ ] Health check returns `{"status": "healthy"}`
- [ ] Test scan returns correct results
- [ ] Frontend updated with API URL (if separate repo)

---

## 🎉 Success!

Once deployed, your API will be available at:
**`https://phishguard-api.onrender.com`**

Use this URL in your frontend's `script.js` API_URL variable.

---

## 💡 Quick Commands

```powershell
# Add model to API repo
cd api
Copy-Item ..\phishing_model.pkl .
git add phishing_model.pkl
git commit -m "Add model file"
git push

# Test locally before deploying
python app.py
# Open http://localhost:5000/api/health

# Test API after deployment
curl https://phishguard-api.onrender.com/api/health
```

---

**Need help?** Check the main `DEPLOYMENT.md` or Render documentation.
