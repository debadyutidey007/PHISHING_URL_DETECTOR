import re
import urllib.parse
from urllib.parse import urlparse
import logging
import tldextract
import numpy as np

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def extract_features_from_url(url):
    """
    Extract features from a URL for phishing detection
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Dictionary of extracted features
    """
    features = {}
    
    try:
        # Basic URL properties
        features['url_length'] = len(url)
        
        # Parse the URL
        parsed_url = urlparse(url)
        
        # Extract domain information
        domain_info = tldextract.extract(url)
        domain = domain_info.domain
        suffix = domain_info.suffix
        subdomain = domain_info.subdomain
        
        # Domain features
        features['domain_length'] = len(domain) if domain else 0
        features['subdomain_length'] = len(subdomain) if subdomain else 0
        features['tld_length'] = len(suffix) if suffix else 0
        features['has_subdomain'] = 1 if subdomain else 0
        features['subdomain_count'] = subdomain.count('.') + 1 if subdomain else 0
        
        # URL structure features
        features['path_length'] = len(parsed_url.path)
        features['url_depth'] = parsed_url.path.count('/')
        features['has_query'] = 1 if parsed_url.query else 0
        features['query_length'] = len(parsed_url.query)
        features['fragment_length'] = len(parsed_url.fragment)
        features['num_params'] = len(urllib.parse.parse_qsl(parsed_url.query))
        
        # Character features
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_letters'] = sum(c.isalpha() for c in url)
        features['num_special_chars'] = sum(not c.isalnum() for c in url)
        features['digit_letter_ratio'] = features['num_digits'] / features['num_letters'] if features['num_letters'] > 0 else 0
        
        # Security indicators
        features['has_https'] = 1 if parsed_url.scheme == 'https' else 0
        features['has_ip_address'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
        features['has_at_symbol'] = 1 if '@' in url else 0
        features['has_double_slash'] = 1 if '//' in parsed_url.path else 0
        features['has_dash_in_domain'] = 1 if '-' in domain else 0
        
        # Suspicious terms
        suspicious_terms = ['login', 'signin', 'verify', 'bank', 'account', 'update', 'secure', 'ebay', 'paypal', 'password']
        features['suspicious_terms_count'] = sum(term in url.lower() for term in suspicious_terms)
        
        # URL encoding features
        features['url_encoded_chars'] = url.count('%')
        
        # Domain reputation features (simplified)
        features['domain_age_days'] = 0  # Would normally require external API
        
        # Additional suspicious patterns
        features['has_multiple_subdomains'] = 1 if features['subdomain_count'] >= 3 else 0
        features['has_suspicious_tld'] = 1 if suffix in ['tk', 'ml', 'ga', 'cf', 'gq'] else 0
        
        # Complex patterns
        features['domain_to_path_ratio'] = features['domain_length'] / features['path_length'] if features['path_length'] > 0 else 0
        features['special_char_ratio'] = features['num_special_chars'] / features['url_length'] if features['url_length'] > 0 else 0
        
    except Exception as e:
        logger.error(f"Error extracting features from URL {url}: {str(e)}")
        # Fill missing features with zeros to maintain compatibility with the model
        for key in [
            'url_length', 'domain_length', 'subdomain_length', 'tld_length', 
            'has_subdomain', 'subdomain_count', 'path_length', 'url_depth',
            'has_query', 'query_length', 'fragment_length', 'num_params',
            'num_digits', 'num_letters', 'num_special_chars', 'digit_letter_ratio',
            'has_https', 'has_ip_address', 'has_at_symbol', 'has_double_slash',
            'has_dash_in_domain', 'suspicious_terms_count', 'url_encoded_chars',
            'domain_age_days', 'has_multiple_subdomains', 'has_suspicious_tld',
            'domain_to_path_ratio', 'special_char_ratio'
        ]:
            if key not in features:
                features[key] = 0
    
    return features
