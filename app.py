"""
PhishGuard API - Flask Backend for Phishing Detection
Deploy to Render.com
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import re
import tldextract
from urllib.parse import urlparse
import os

# Optional imports for deep mode
try:
    import requests
    from bs4 import BeautifulSoup
    ENHANCED_AVAILABLE = True
except:
    ENHANCED_AVAILABLE = False

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

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

# Feature extraction functions
def extract_url_features(url):
    """Extract features from URL structure"""
    if not url.startswith(('http://', 'https://')):
        url_with_scheme = f'http://{url}'
    else:
        url_with_scheme = url
    
    parsed = urlparse(url_with_scheme)
    ext = tldextract.extract(url)
    
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

def analyze_html(url):
    """Analyze HTML content (deep mode)"""
    if not ENHANCED_AVAILABLE:
        return {}
    
    try:
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'
        
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Forms
        forms = soup.find_all('form')
        has_password = any(inp.get('type', '').lower() == 'password' 
                          for form in forms for inp in form.find_all('input'))
        
        # Links
        links = soup.find_all('a', href=True)
        external_links = sum(1 for link in links if link['href'].startswith(('http://', 'https://')))
        
        # Suspicious patterns
        scripts = soup.find_all('script')
        has_obfuscated = any('eval(' in s.get_text() or 'unescape(' in s.get_text() for s in scripts)
        has_hidden_iframe = any('display:none' in iframe.get('style', '').lower() for iframe in soup.find_all('iframe'))
        
        title = soup.find('title')
        title_text = title.get_text() if title else ""
        suspicious_titles = ['verify', 'update', 'confirm', 'suspended', 'locked', 'urgent']
        has_suspicious_title = any(word in title_text.lower() for word in suspicious_titles)
        
        return {
            'has_password_field': int(has_password),
            'external_links': external_links,
            'has_obfuscated_js': int(has_obfuscated),
            'has_hidden_iframe': int(has_hidden_iframe),
            'has_suspicious_title': int(has_suspicious_title),
            'num_forms': len(forms),
            'redirect_count': len(response.history)
        }
    except Exception as e:
        print(f"HTML analysis error: {e}")
        return {}

def predict_phishing(url, deep=False):
    """Predict if URL is phishing"""
    if not models:
        return {"error": "Model not loaded"}
    
    # Extract features
    url_features = extract_url_features(url)
    
    # Deep analysis
    html_info = {}
    adjustments = []
    
    if deep and ENHANCED_AVAILABLE:
        html_info = analyze_html(url)
        url_features['num_forms'] = html_info.get('num_forms', url_features['num_forms'])
    
    # Prepare for model
    feature_df = pd.DataFrame([{k: url_features.get(k, 0) for k in features}])
    
    # Get predictions
    predictions = [int(m.predict(feature_df)[0]) for m in models.values()]
    
    # Get probabilities
    probabilities = {}
    for name, model in models.items():
        if hasattr(model, 'predict_proba'):
            prob = model.predict_proba(feature_df)[0]
            probabilities[name] = {'legitimate': float(prob[0]), 'phishing': float(prob[1])}
    
    base_score = sum(predictions) / len(predictions)
    
    # Apply rule-based adjustments
    final_score = base_score
    
    # CRITICAL: No HTTPS
    if not url_features['is_https']:
        suspicious_path = any(word in url.lower() for word in ['php', 'cgi-bin', 'verify', 'login', 'update', 'secure'])
        if suspicious_path:
            final_score += 0.35
            adjustments.append("⚠️ No HTTPS + suspicious path (+35%)")
        else:
            final_score += 0.20
            adjustments.append("⚠️ No HTTPS (+20%)")
    
    # Deep mode adjustments
    if deep and html_info:
        if html_info.get('has_password_field'):
            if not url_features['is_https']:
                final_score += 0.25
                adjustments.append("🚨 Password form without HTTPS (+25%)")
            elif html_info.get('has_suspicious_title'):
                final_score += 0.15
                adjustments.append("Password form + suspicious title (+15%)")
        
        if html_info.get('has_hidden_iframe'):
            final_score += 0.20
            adjustments.append("Hidden iframe detected (+20%)")
        
        if html_info.get('has_obfuscated_js'):
            final_score += 0.15
            adjustments.append("Obfuscated JavaScript (+15%)")
    
    # Additional rules
    if url_features['has_ip_in_url']:
        final_score += 0.25
        adjustments.append("⚠️ IP address in URL (+25%)")
    
    if url_features['url_length'] > 75 and url_features['contains_suspicious_words']:
        final_score += 0.15
        adjustments.append("Long URL + suspicious words (+15%)")
    
    if url_features['num_subdomains'] >= 3:
        final_score += 0.10
        adjustments.append("Multiple subdomains (3+) (+10%)")
    
    final_score = max(0, min(1, final_score))
    
    decision = "PHISHING" if final_score >= 0.5 else "LEGITIMATE"
    confidence = max(final_score, 1 - final_score) * 100
    
    return {
        'url': url,
        'decision': decision,
        'confidence': float(confidence),
        'score': float(final_score),
        'model_votes': predictions,
        'probabilities': probabilities,
        'adjustments': adjustments,
        'features': {k: int(v) if isinstance(v, (int, bool)) else float(v) 
                    for k, v in url_features.items()},
        'html_analysis': html_info if deep else None
    }

# Routes
@app.route('/')
def home():
    return jsonify({
        'service': 'PhishGuard API',
        'version': '1.0',
        'status': 'running',
        'endpoints': {
            '/api/scan': 'POST - Scan URL for phishing',
            '/api/health': 'GET - Health check'
        }
    })

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'healthy',
        'model_loaded': models is not None,
        'deep_mode_available': ENHANCED_AVAILABLE
    })

@app.route('/api/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url']
        mode = data.get('mode', 'fast')
        deep = mode == 'deep'
        
        result = predict_phishing(url, deep=deep)
        
        if 'error' in result:
            return jsonify(result), 500
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
