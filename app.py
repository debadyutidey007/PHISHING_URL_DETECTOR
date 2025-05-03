import os
import logging
import json
import time
import datetime
from flask import Flask, render_template, request, jsonify
from utils.feature_extractor import extract_features_from_url
from utils.model import load_model, predict_url
import pandas as pd

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "phishing_detection_secret")

# Global variables
model = None
feature_names = None
feature_importances = None
analysis_stats = {
    "total_analyzed": 0,
    "phishing_detected": 0,
    "recent_analyses": []
}

# Initialize global variables
def initialize():
    global model, feature_names, feature_importances
    try:
        # Load the trained model
        model, feature_names, feature_importances = load_model()
        logger.info("Model loaded successfully")
    except Exception as e:
        logger.error(f"Error loading model: {str(e)}")
        model = None

# Initialize when the app starts up
with app.app_context():
    initialize()

@app.route('/')
def index():
    """Render the main page of the application."""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze a URL for phishing characteristics."""
    url = request.form.get('url', '')
    sensitivity = float(request.form.get('sensitivity', 75)) / 100.0  # Convert to 0-1 range
    advanced_features = request.form.get('advanced_features', '1') == '1'
    
    if not url:
        return jsonify({
            'error': 'Please provide a URL to analyze'
        }), 400
    
    # Add http:// if missing
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    
    try:
        # Extract features from the URL
        start_time = time.time()
        features_dict = extract_features_from_url(url)
        feature_extraction_time = time.time() - start_time
        
        # Check if model is loaded
        if model is None:
            return jsonify({
                'error': 'Model not loaded. Please try again later.'
            }), 500
        
        # Make prediction
        start_time = time.time()
        prediction, probability, features_df = predict_url(model, features_dict, feature_names)
        prediction_time = time.time() - start_time
        
        # Apply sensitivity adjustment (higher sensitivity means more likely to flag as phishing)
        if sensitivity > 0.75:  # High sensitivity - lower the threshold
            adjusted_threshold = 0.5 - ((sensitivity - 0.75) * 0.4)  # Can go as low as 0.3
            prediction = 1 if probability > adjusted_threshold else 0
        elif sensitivity < 0.75:  # Low sensitivity - raise the threshold
            adjusted_threshold = 0.5 + ((0.75 - sensitivity) * 0.4)  # Can go as high as 0.7
            prediction = 1 if probability > adjusted_threshold else 0
        
        # Get feature importance data
        feature_importance_data = []
        if feature_importances is not None and len(feature_importances) > 0:
            # Create a series of feature values
            feature_values = features_df.iloc[0]
            
            # Create a dataframe with feature names, importances, and values
            importance_df = pd.DataFrame({
                'feature': feature_names,
                'importance': feature_importances,
                'value': feature_values
            })
            
            # Sort by importance
            importance_df = importance_df.sort_values('importance', ascending=False)
            
            # Get top features (all of them for advanced mode, otherwise just top 5)
            top_features = importance_df if advanced_features else importance_df.head(5)
            
            # Convert to list of dictionaries for JSON
            feature_importance_data = top_features.to_dict('records')
        
        # Add additional domain information for advanced analysis
        domain_info = {}
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Simple domain info (since we can't access WHOIS API)
            domain_info = {
                "domain": domain,
                "creation_date": "Unknown",  # Would require WHOIS lookup
                "expiration_date": "Unknown",  # Would require WHOIS lookup
                "registrar": "Unknown",  # Would require WHOIS lookup
                "ssl_valid": url.startswith('https'),
                "last_updated": datetime.datetime.now().strftime("%Y-%m-%d")
            }
        except Exception as e:
            logger.warning(f"Error getting domain info: {str(e)}")
            domain_info = {"error": "Could not retrieve domain information"}
        
        # Update analytics
        analysis_stats["total_analyzed"] += 1
        if prediction == 1:
            analysis_stats["phishing_detected"] += 1
        
        # Add to recent analyses (keep only the last 100)
        analysis_stats["recent_analyses"].append({
            "url": url,
            "timestamp": datetime.datetime.now().isoformat(),
            "is_phishing": bool(prediction),
            "confidence": float(probability)
        })
        if len(analysis_stats["recent_analyses"]) > 100:
            analysis_stats["recent_analyses"] = analysis_stats["recent_analyses"][-100:]
        
        # Prepare response
        result = {
            'url': url,
            'is_phishing': bool(prediction),
            'confidence': float(probability),
            'features': features_dict,
            'top_features': feature_importance_data,
            'performance': {
                'feature_extraction_time': feature_extraction_time,
                'prediction_time': prediction_time,
                'total_time': feature_extraction_time + prediction_time
            },
            'domain_info': domain_info,
            'stats': {
                'total_analyzed': analysis_stats["total_analyzed"],
                'phishing_detected': analysis_stats["phishing_detected"],
                'detection_rate': analysis_stats["phishing_detected"] / analysis_stats["total_analyzed"] if analysis_stats["total_analyzed"] > 0 else 0
            }
        }
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error analyzing URL: {str(e)}")
        return jsonify({
            'error': f'Error analyzing URL: {str(e)}'
        }), 500

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get system statistics."""
    try:
        return jsonify({
            'total_analyzed': analysis_stats["total_analyzed"],
            'phishing_detected': analysis_stats["phishing_detected"],
            'detection_rate': analysis_stats["phishing_detected"] / analysis_stats["total_analyzed"] if analysis_stats["total_analyzed"] > 0 else 0,
            'recent_analyses': analysis_stats["recent_analyses"][-10:]  # Return only the last 10
        })
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        return jsonify({
            'error': f'Error getting stats: {str(e)}'
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'ok',
        'model_loaded': model is not None,
        'timestamp': datetime.datetime.now().isoformat(),
        'version': '2.0.0'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
