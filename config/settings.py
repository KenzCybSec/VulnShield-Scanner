"""
VulnShield Configuration Settings
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Scanning Configuration
SCAN_CONFIG = {
    # Request settings
    'request_timeout': 10,
    'max_redirects': 5,
    'verify_ssl': False,  # Set to True in production
    
    # Rate limiting
    'requests_per_minute': 30,
    'delay_between_requests': 0.2,
    
    # Scan intensity
    'scan_intensity': 'medium',  # low, medium, high
    'max_payloads_per_test': 50,
    
    # Reporting
    'report_format': 'console',  # console, html, json
    'output_directory': 'reports',
    
    # Security headers to check
    'required_headers': [
        'Content-Security-Policy',
        'X-Frame-Options', 
        'X-Content-Type-Options',
        'Strict-Transport-Security'
    ]
}

# SQL Injection Settings
SQL_CONFIG = {
    'test_parameters': ['id', 'page', 'category', 'search', 'user', 'product'],
    'advanced_tests': True,
    'time_based_detection': True,
    'boolean_based_detection': True
}

# XSS Settings  
XSS_CONFIG = {
    'test_parameters': ['q', 'search', 'query', 'name', 'message', 'comment'],
    'test_forms': True,
    'dom_based_detection': False,  # Requires browser automation
    'advanced_vectors': True
}

# Risk Assessment
RISK_LEVELS = {
    'CRITICAL': 9.0,
    'HIGH': 7.0,
    'MEDIUM': 4.0,
    'LOW': 1.0,
    'INFO': 0.0
}

# Logging Configuration
LOGGING_CONFIG = {
    'level': 'INFO',
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file': 'vulnshield.log'
}

def get_setting(key, default=None):
    """Get setting from environment or config"""
    return os.getenv(key.upper(), SCAN_CONFIG.get(key, default))

def update_config(new_config):
    """Update configuration settings"""
    SCAN_CONFIG.update(new_config)