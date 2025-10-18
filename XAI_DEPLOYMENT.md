# 🚀 PhishGuard XAI Deployment Guide

**Quick setup for XAI-enabled API**

---

## ✅ What's New in XAI Version

- ✅ LIME explanations for individual predictions
- ✅ SHAP (Shapley) values for game-theoretic feature importance
- ✅ Random Forest feature importance rankings
- ✅ New endpoint: `/api/explainability` for method overview
- ✅ Query parameter: `?explain=true` for detailed explanations
- ✅ Visualization report generator

---

## 📦 Updated Files

### API Changes

**Old**: `api/app.py`  
**New**: `api/app_xai.py` (with LIME & SHAP)

### Dependencies Added

```txt
lime==0.2.0
shap==0.43.0
```

---

## 🔧 Installation Steps

### Step 1: Update API

```bash
cd api

# Backup original
mv app.py app_original.py

# Use new XAI version
mv app_xai.py app.py
```

### Step 2: Update Dependencies

```bash
# requirements.txt already includes LIME and SHAP
# Just make sure it's up to date:
pip install -r requirements.txt
```

### Step 3: Commit to Git

```bash
git add app.py requirements.txt
git commit -m "Add XAI: LIME, SHAP, Feature Importance explanations"
git push
```

### Step 4: Render Auto-Deploys

- Render detects the changes
- Installs new dependencies (lime, shap)
- Restarts the API in 3-5 minutes
- Check logs for: `✅ LIME and SHAP explainers initialized`

---

## 🧪 Testing XAI Endpoints

### 1. Check Health (with XAI status)

```bash
curl https://phishguard-api-kwpg.onrender.com/api/health
```

Expected:
```json
{
  "status": "healthy",
  "model_loaded": true,
  "lime_enabled": true,
  "shap_enabled": true,
  "xai_available": true
}
```

### 2. Get Explainability Methods

```bash
curl https://phishguard-api-kwpg.onrender.com/api/explainability
```

Returns info about LIME, SHAP, and Feature Importance methods.

### 3. Scan WITHOUT Explanations (Fast)

```bash
curl -X POST https://phishguard-api-kwpg.onrender.com/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "facebook.com", "mode": "fast"}'
```

Response: Basic prediction in <1 second

### 4. Scan WITH Explanations (Detailed)

```bash
curl -X POST "https://phishguard-api-kwpg.onrender.com/api/scan?explain=true" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://192.168.1.1/paypal.php", "mode": "fast"}'
```

Response: Includes LIME, SHAP, and Feature Importance (2-5 seconds)

---

## 📊 Response Format

### Without Explanations (`?explain=false`)

```json
{
  "decision": "PHISHING",
  "confidence": 95.0,
  "score": 0.95,
  "model_votes": [1, 1, 1],
  "adjustments": ["⚠️ No HTTPS (+20%)"]
}
```

### With Explanations (`?explain=true`)

```json
{
  "decision": "PHISHING",
  "confidence": 95.0,
  "score": 0.95,
  "model_votes": [1, 1, 1],
  "adjustments": ["⚠️ No HTTPS (+20%)"],
  "explainability": {
    "lime": {
      "method": "LIME (Local Interpretable Model-agnostic Explanations)",
      "top_features": [
        {
          "feature": "is_https: False",
          "contribution": 0.35,
          "direction": "supports phishing"
        },
        {
          "feature": "has_ip_in_url: True",
          "contribution": 0.25,
          "direction": "supports phishing"
        }
      ],
      "explanation_score": 0.92
    },
    "shap": {
      "method": "SHAP (SHapley Additive exPlanations)",
      "top_features": [
        {
          "feature": "is_https",
          "shap_value": 0.25,
          "impact": "increases phishing score"
        },
        {
          "feature": "has_ip_in_url",
          "shap_value": 0.20,
          "impact": "increases phishing score"
        }
      ],
      "base_value": 0.15,
      "total_impact": 0.45
    },
    "feature_importance": {
      "method": "Random Forest Feature Importance",
      "top_features": [
        {
          "feature": "is_https",
          "importance": 0.185,
          "percentage": 18.5
        },
        {
          "feature": "url_length",
          "importance": 0.142,
          "percentage": 14.2
        }
      ]
    }
  }
}
```

---

## 📈 Generate Visualization Reports

### Create XAI Report Locally

```bash
# First, copy your model and dataset locally (if not already)
# Then run:
python generate_xai_report.py
```

Creates `xai_reports/` folder with:
- `1_feature_importance.png` - Top 15 features chart
- `2_model_comparison.png` - Model accuracy comparison
- `3_lime_1.png`, `13_shap_1.png` - Explanations for test URLs
- ... and more visualizations

### Use Reports for Presentations

Perfect for:
- ✅ Business presentations
- ✅ Technical demos
- ✅ Research papers
- ✅ Stakeholder reports

---

## ⚡ Performance Notes

### Speed Comparison

| Endpoint | Time | Use Case |
|----------|------|----------|
| `/api/scan` (no explain) | <1s | Real-time |
| `/api/scan?explain=true` | 2-5s | Batch/Demo |

### Optimization Tips

1. **Don't use `?explain=true`** for production scanning (slower)
2. **Cache results** for frequently scanned URLs
3. **Batch explanations** - collect 10 URLs, explain together
4. **Use reporting script** for offline analysis

---

## 🆘 Troubleshooting

### "LIME or SHAP not initialized"

**Cause**: Model or dataset not loaded  
**Solution**: Check Render logs:
```
✅ Model loaded successfully
✅ LIME and SHAP explainers initialized
```

If missing, restart the service in Render dashboard.

### "Explainability endpoint returns None"

**Cause**: Explainers not ready  
**Solution**: Wait 30 seconds after deployment for initialization

### "Slow response with ?explain=true"

**Cause**: SHAP is computing Shapley values  
**Expected**: 2-5 seconds is normal  
**Optimization**: Use without explain for real-time, or cache results

---

## 📚 Next Steps

1. **Read**: `XAI_GUIDE.md` for complete documentation
2. **Test**: Try endpoints with `?explain=true`
3. **Visualize**: Run `generate_xai_report.py` for charts
4. **Present**: Share visualization reports with stakeholders

---

## 🎯 API Endpoints Summary

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Service info |
| `/api/health` | GET | Health check (includes XAI status) |
| `/api/explainability` | GET | Explainability methods overview |
| `/api/scan` | POST | Scan URL (add `?explain=true` for XAI) |

---

**✅ Your API is now XAI-enabled!**

Use `?explain=true` to get detailed explanations with LIME, SHAP, and feature importance.

See `XAI_GUIDE.md` for comprehensive documentation.
