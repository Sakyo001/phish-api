"""
PhishGuard - XAI Enhanced API with LIME and SHAP Explanations
Provides detailed model interpretability for presentation
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import numpy as np
import re
import tldextract
from urllib.parse import urlparse
import os

# XAI Libraries
import lime
import lime.lime_tabular
import shap
import warnings
warnings.filterwarnings('ignore')

# Optional deep mode
try:
    import requests
    from bs4 import BeautifulSoup
    ENHANCED_AVAILABLE = True
except:
    ENHANCED_AVAILABLE = False

app = Flask(__name__)
CORS(app)

# Load model
MODEL_PATH = os.getenv('MODEL_PATH', 'phishing_model.pkl')
try:
    ensemble = joblib.load(MODEL_PATH)
    models = ensemble["models"]
    features = ensemble["feature_names"]
    print("✅ Model loaded successfully")
except Exception as e:
    print(f"❌ Error loading model: {e}")
    models = None
    features = None

# Initialize LIME explainer (will be set after loading data)
lime_explainer = None
shap_explainer = None

def initialize_explainers():
    """Initialize LIME and SHAP explainers with training data"""
    global lime_explainer, shap_explainer
    
    try:
        # Load dataset for training explainers
        df = pd.read_csv('phishing_site_urls.csv')
        sample = df.sample(n=min(5000, len(df)), random_state=42)
        
        # Extract features for sample
        sample_features = []
        for url in sample['URL']:
            sample_features.append(extract_url_features(url))
        
        X_sample = pd.DataFrame(sample_features)
        X_sample = X_sample[[f for f in features if f in X_sample.columns]]
        
        # Initialize LIME explainer
        lime_explainer = lime.lime_tabular.LimeTabularExplainer(
            X_sample.values,
            feature_names=X_sample.columns.tolist(),
            mode='classification',
            verbose=False
        )
        
        # Initialize SHAP explainer with the model
        rf_model = models.get("random_forest")
        if rf_model:
            shap_explainer = shap.TreeExplainer(rf_model)
            print("✅ LIME and SHAP explainers initialized")
        
    except Exception as e:
        print(f"⚠️  Could not initialize explainers: {e}")

# Feature extraction
def extract_url_features(url):
    """Extract 26 features from URL"""
    if not url.startswith(('http://', 'https://')):
        url_with_scheme = f'http://{url}'
    else:
        url_with_scheme = url
    
    parsed = urlparse(url_with_scheme)
    ext = tldextract.extract(url_with_scheme)
    
    suspicious_words = ["secure", "account", "login", "update", "verify", "bank", 
                       "paypal", "signin", "webscr", "cgi-bin", "cmd"]
    
    return {
        "url_length": len(url),
        "num_subdomains": len(ext.subdomain.split('.')) if ext.subdomain else 0,
        "has_ip_in_url": int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))),
        "has_at_symbol": int('@' in url),
        "has_dash": int('-' in ext.domain),
        "uses_shortener": int(any(s in url.lower() for s in ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"])),
        "contains_suspicious_words": int(any(w in url.lower() for w in suspicious_words)),
        "is_https": int(parsed.scheme == "https"),
        "has_ssl_cert": int(parsed.scheme == "https"),
        "num_dots": url.count('.'),
        "num_slashes": url.count('/'),
        "has_double_slash": int('//' in url.replace('http://', '').replace('https://', '')),
        "domain_length": len(ext.domain) if ext.domain else 0,
        "has_port": int(bool(parsed.port)),
        "num_special_chars": sum(c in url for c in ['?', '&', '=', '%', '#']),
        "ssl_expiry_days": 0,
        "domain_age_days": 0,
        "dns_record_exists": 1,
        "whois_private": 0,
        "num_forms": 0,
        "has_login_form": 0,
        "external_links_count": 0,
        "title_similarity_to_domain": 0.5,
        "ip_reputation_score": 0.5,
        "country_mismatch": 0,
        "hosting_provider_reputation": 0.5
    }

def get_lime_explanation(url, feature_df, prediction):
    """Get LIME explanation for the prediction"""
    if not lime_explainer:
        return None
    
    try:
        # Get Random Forest model
        rf_model = models.get("random_forest")
        
        # LIME needs predict_proba
        def predict_fn(X):
            return rf_model.predict_proba(X)
        
        # Get explanation
        exp = lime_explainer.explain_instance(
            feature_df.values[0],
            predict_fn,
            num_features=10
        )
        
        # Extract feature contributions
        contributions = []
        for feature, weight in exp.as_list():
            contributions.append({
                "feature": feature.split('<=')[0].strip() if '<=' in feature else feature,
                "contribution": float(weight),
                "direction": "supports phishing" if weight > 0 else "supports legitimate"
            })
        
        return {
            "method": "LIME (Local Interpretable Model-agnostic Explanations)",
            "top_features": contributions[:5],
            "explanation_score": float(exp.score)
        }
    except Exception as e:
        print(f"LIME error: {e}")
        return None

def get_shap_explanation(feature_df):
    """Get SHAP explanation for the prediction"""
    if not shap_explainer:
        return None
    
    try:
        # Get SHAP values
        shap_values = shap_explainer.shap_values(feature_df)
        
        # Handle multi-class output (take phishing class)
        if isinstance(shap_values, list):
            shap_vals = shap_values[1]  # Phishing class
        else:
            shap_vals = shap_values
        
        # Get feature importance
        feature_importance = []
        for idx, feature in enumerate(feature_df.columns):
            if idx < len(shap_vals[0]):
                feature_importance.append({
                    "feature": feature,
                    "shap_value": float(abs(shap_vals[0][idx])),
                    "impact": "increases phishing score" if shap_vals[0][idx] > 0 else "decreases phishing score"
                })
        
        # Sort by importance
        feature_importance.sort(key=lambda x: x["shap_value"], reverse=True)
        
        return {
            "method": "SHAP (SHapley Additive exPlanations)",
            "top_features": feature_importance[:5],
            "base_value": float(shap_explainer.expected_value),
            "total_impact": float(np.sum(shap_vals[0]))
        }
    except Exception as e:
        print(f"SHAP error: {e}")
        return None

def get_feature_importance():
    """Get feature importance from Random Forest"""
    try:
        rf_model = models.get("random_forest")
        importances = rf_model.feature_importances_
        
        feature_imp = []
        for feature, importance in zip(features, importances):
            feature_imp.append({
                "feature": feature,
                "importance": float(importance),
                "percentage": float(importance * 100)
            })
        
        feature_imp.sort(key=lambda x: x["importance"], reverse=True)
        
        return {
            "method": "Random Forest Feature Importance",
            "top_features": feature_imp[:10]
        }
    except Exception as e:
        print(f"Feature importance error: {e}")
        return None

def predict_phishing(url, deep=False, explain=False):
    """Predict if URL is phishing with optional explanations"""
    if not models:
        return {"error": "Model not loaded"}
    
    # Extract features
    url_features = extract_url_features(url)
    feature_df = pd.DataFrame([{k: url_features.get(k, 0) for k in features}])
    
    # Get predictions
    predictions = [int(m.predict(feature_df)[0]) for m in models.values()]
    
    # Get probabilities
    probabilities = {}
    for name, model in models.items():
        if hasattr(model, 'predict_proba'):
            prob = model.predict_proba(feature_df)[0]
            probabilities[name] = {
                'legitimate': float(prob[0]), 
                'phishing': float(prob[1])
            }
    
    base_score = sum(predictions) / len(predictions)
    final_score = base_score
    adjustments = []
    
    # Apply rules
    if not url_features['is_https']:
        suspicious_path = any(word in url.lower() for word in ['php', 'cgi-bin', 'verify', 'login', 'update', 'secure'])
        if suspicious_path:
            final_score += 0.35
            adjustments.append("⚠️ No HTTPS + suspicious path (+35%)")
        else:
            final_score += 0.20
            adjustments.append("⚠️ No HTTPS (+20%)")
    
    if url_features['has_ip_in_url']:
        final_score += 0.25
        adjustments.append("⚠️ IP address in URL (+25%)")
    
    final_score = max(0, min(1, final_score))
    decision = "PHISHING" if final_score >= 0.5 else "LEGITIMATE"
    confidence = max(final_score, 1 - final_score) * 100
    
    result = {
        'url': url,
        'decision': decision,
        'confidence': float(confidence),
        'score': float(final_score),
        'model_votes': predictions,
        'probabilities': probabilities,
        'adjustments': adjustments,
        'features': {k: int(v) if isinstance(v, (int, bool)) else float(v) 
                    for k, v in url_features.items()}
    }
    
    # Add explanations if requested
    if explain:
        result['explainability'] = {
            'lime': get_lime_explanation(url, feature_df, decision),
            'shap': get_shap_explanation(feature_df),
            'feature_importance': get_feature_importance()
        }
    
    return result

# Routes
@app.route('/')
def home():
    return jsonify({
        'service': 'PhishGuard API',
        'version': '2.0 (XAI Enhanced)',
        'features': ['LIME', 'SHAP', 'Feature Importance'],
        'endpoints': {
            '/api/scan': 'POST - Scan URL (add ?explain=true for XAI)',
            '/api/health': 'GET - Health check',
            '/api/explainability': 'GET - Model explainability overview'
        }
    })

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'healthy',
        'model_loaded': models is not None,
        'lime_enabled': lime_explainer is not None,
        'shap_enabled': shap_explainer is not None,
        'xai_available': True
    })

@app.route('/api/explainability')
def explainability():
    """Return overall model explainability information"""
    return jsonify({
        'methods': [
            {
                'name': 'LIME',
                'description': 'Local Interpretable Model-agnostic Explanations',
                'use_case': 'Explains individual predictions with local approximations'
            },
            {
                'name': 'SHAP',
                'description': 'SHapley Additive exPlanations',
                'use_case': 'Game-theoretic approach to feature importance'
            },
            {
                'name': 'Feature Importance',
                'description': 'Random Forest built-in importance scores',
                'use_case': 'Global model behavior across all predictions'
            }
        ],
        'usage': 'Add ?explain=true to /api/scan endpoint for detailed explanations'
    })

@app.route('/api/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url']
        mode = data.get('mode', 'fast')
        explain = request.args.get('explain', 'false').lower() == 'true'
        
        result = predict_phishing(url, deep=(mode == 'deep'), explain=explain)
        
        if 'error' in result:
            return jsonify(result), 500
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Initialize explainers on startup
    print("\n🔧 Initializing XAI explainers...")
    initialize_explainers()
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
