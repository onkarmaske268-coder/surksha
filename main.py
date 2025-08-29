#!/usr/bin/env python3
"""
Surksha - Stay Safe, Delete Fake
A Python cybersecurity tool for detecting suspicious WhatsApp APK files
"""

import os
import logging
from flask import Flask, render_template, request, jsonify, send_from_directory, flash, redirect, url_for
from werkzeug.utils import secure_filename
import json
from pathlib import Path
import traceback
from datetime import datetime

from apk_scanner import APKScanner
from ml_classifier import MLClassifier

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'surksha_secure_key_2025')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'apk'}
SCAN_RESULTS_FILE = 'scan_results.json'

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize components
scanner = APKScanner()
classifier = MLClassifier()

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_scan_results():
    """Load previous scan results"""
    try:
        if os.path.exists(SCAN_RESULTS_FILE):
            with open(SCAN_RESULTS_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error loading scan results: {e}")
    return {"scans": [], "last_update": None}

def save_scan_results(results):
    """Save scan results to file"""
    try:
        with open(SCAN_RESULTS_FILE, 'w') as f:
            json.dump(results, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving scan results: {e}")

@app.route('/')
def index():
    """Main page with upload and scan options"""
    recent_results = load_scan_results()
    return render_template('index.html', recent_results=recent_results)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle APK file upload"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file selected'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Add timestamp to avoid conflicts
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{timestamp}_{filename}"
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            
            logger.info(f"File uploaded: {filepath}")
            return jsonify({'success': True, 'filename': filename, 'filepath': filepath})
        else:
            return jsonify({'error': 'Invalid file type. Only APK files are allowed.'}), 400
    
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@app.route('/scan_file', methods=['POST'])
def scan_file():
    """Scan a single uploaded APK file"""
    try:
        data = request.get_json()
        filepath = data.get('filepath')
        
        if not filepath or not os.path.exists(filepath):
            return jsonify({'error': 'File not found'}), 404
        
        # Scan the APK file
        logger.info(f"Starting scan of: {filepath}")
        scan_result = scanner.scan_apk(filepath)
        
        if scan_result['success']:
            # Classify the APK
            classification = classifier.classify_apk(scan_result['features'])
            scan_result['classification'] = classification
            
            # Save results
            results_data = load_scan_results()
            scan_entry = {
                'filename': os.path.basename(filepath),
                'filepath': filepath,
                'timestamp': datetime.now().isoformat(),
                'result': scan_result
            }
            results_data['scans'].append(scan_entry)
            results_data['last_update'] = datetime.now().isoformat()
            save_scan_results(results_data)
            
            logger.info(f"Scan completed: {scan_result['classification']['status']}")
            return jsonify(scan_result)
        else:
            return jsonify(scan_result), 400
    
    except Exception as e:
        logger.error(f"Scan error: {traceback.format_exc()}")
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500

@app.route('/scan_folder', methods=['POST'])
def scan_folder():
    """Scan all APK files in the uploads folder"""
    try:
        apk_files = []
        for filename in os.listdir(UPLOAD_FOLDER):
            if filename.lower().endswith('.apk'):
                apk_files.append(os.path.join(UPLOAD_FOLDER, filename))
        
        if not apk_files:
            return jsonify({'error': 'No APK files found in uploads folder'}), 404
        
        scan_results = []
        for filepath in apk_files:
            logger.info(f"Scanning: {filepath}")
            scan_result = scanner.scan_apk(filepath)
            
            if scan_result['success']:
                classification = classifier.classify_apk(scan_result['features'])
                scan_result['classification'] = classification
                scan_result['filename'] = os.path.basename(filepath)
                scan_results.append(scan_result)
            else:
                scan_results.append({
                    'filename': os.path.basename(filepath),
                    'success': False,
                    'error': scan_result.get('error', 'Unknown error')
                })
        
        # Save batch results
        results_data = load_scan_results()
        batch_entry = {
            'type': 'folder_scan',
            'timestamp': datetime.now().isoformat(),
            'results': scan_results,
            'total_files': len(apk_files)
        }
        results_data['scans'].append(batch_entry)
        results_data['last_update'] = datetime.now().isoformat()
        save_scan_results(results_data)
        
        return jsonify({
            'success': True,
            'results': scan_results,
            'total_scanned': len(apk_files)
        })
    
    except Exception as e:
        logger.error(f"Folder scan error: {traceback.format_exc()}")
        return jsonify({'error': f'Folder scan failed: {str(e)}'}), 500

@app.route('/delete_file', methods=['POST'])
def delete_file():
    """Delete a suspicious APK file"""
    try:
        data = request.get_json()
        filepath = data.get('filepath')
        
        if not filepath:
            return jsonify({'error': 'No filepath provided'}), 400
        
        # Security check - only allow deletion of files in uploads folder
        if not filepath.startswith(UPLOAD_FOLDER):
            return jsonify({'error': 'Unauthorized file deletion attempt'}), 403
        
        if os.path.exists(filepath):
            os.remove(filepath)
            logger.info(f"File deleted: {filepath}")
            return jsonify({'success': True, 'message': 'File deleted successfully'})
        else:
            return jsonify({'error': 'File not found'}), 404
    
    except Exception as e:
        logger.error(f"Delete error: {e}")
        return jsonify({'error': f'Delete failed: {str(e)}'}), 500

@app.route('/results')
def results():
    """Display scan results page"""
    results_data = load_scan_results()
    return render_template('results.html', results=results_data)

@app.route('/api/status')
def api_status():
    """API status endpoint"""
    try:
        # Check if classifier is loaded
        classifier_status = classifier.is_ready()
        scanner_status = True  # Scanner should always be available
        
        return jsonify({
            'status': 'operational',
            'classifier_ready': classifier_status,
            'scanner_ready': scanner_status,
            'upload_folder': UPLOAD_FOLDER,
            'supported_formats': list(ALLOWED_EXTENSIONS)
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error"""
    return jsonify({'error': 'File too large. Maximum size is 50MB.'}), 413

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template('index.html'), 404

if __name__ == '__main__':
    logger.info("Starting Surksha - Stay Safe, Delete Fake")
    logger.info("Cybersecurity APK Scanner")
    
    # Initialize ML classifier
    try:
        classifier.initialize()
        logger.info("ML Classifier initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize classifier: {e}")
    
    # Run Flask app
    port = int(os.getenv('PORT', 5000))
    debug_mode = os.getenv('DEBUG', 'False').lower() == 'true'
    
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
