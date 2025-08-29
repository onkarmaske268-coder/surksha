# Overview

Surksha is a Python-based cybersecurity web application designed to detect suspicious WhatsApp APK files using AI/ML technology. The application provides a Flask web interface for uploading, scanning, and analyzing APK files to identify potential malware or fake WhatsApp applications. It uses machine learning algorithms (Random Forest classifier) combined with static analysis techniques to assess the security risk of APK files and provides users with actionable recommendations.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
- **Web Framework**: Flask-based web application with Bootstrap 5 UI framework
- **Client-Side**: JavaScript-powered interactive interface with AJAX for real-time scanning
- **Templates**: Jinja2 templating engine with responsive HTML templates
- **Styling**: Custom CSS with Font Awesome icons and Bootstrap components
- **User Interface**: Drag-and-drop file upload, progress indicators, and real-time results display

## Backend Architecture
- **Core Framework**: Python Flask web server
- **Modular Design**: Separated concerns across multiple Python modules:
  - `apk_scanner.py`: APK file detection and basic analysis
  - `feature_extractor.py`: Feature extraction from APK files for ML classification
  - `ml_classifier.py`: Machine learning classifier using scikit-learn
  - `main.py`: Flask application entry point and route handlers

## Data Processing Pipeline
- **APK Analysis**: ZIP file validation, AndroidManifest.xml parsing, and certificate examination
- **Feature Extraction**: 20+ characteristics including permissions, file structure, entropy calculation, and string analysis
- **ML Classification**: Random Forest algorithm with StandardScaler for feature normalization
- **Risk Assessment**: Confidence scoring and risk level categorization (LOW/MEDIUM/HIGH)

## File Management
- **Upload Handling**: Secure file upload with size limits (50MB) and extension validation
- **Storage**: Local file system storage in `uploads/` directory
- **Results Persistence**: JSON-based scan results storage for history tracking
- **File Operations**: Safe deletion capabilities with confirmation prompts

## Security Features
- **Permission Analysis**: Detection of suspicious Android permissions vs legitimate WhatsApp permissions
- **Package Validation**: Verification against known WhatsApp package names and variants
- **Certificate Verification**: APK certificate analysis for authenticity checks
- **String Analysis**: Suspicious string pattern detection within APK contents

# External Dependencies

## Python Libraries
- **Flask**: Web framework for HTTP server and routing
- **scikit-learn**: Machine learning library for Random Forest classifier and preprocessing
- **numpy**: Numerical computing for feature processing
- **werkzeug**: WSGI utilities for secure filename handling
- **pathlib**: Modern path handling utilities

## Frontend Dependencies
- **Bootstrap 5.1.3**: CSS framework for responsive UI components
- **Font Awesome 6.0.0**: Icon library for user interface elements
- **CDN-hosted**: External CSS and JavaScript libraries loaded from CDNs

## File Format Support
- **APK Files**: Android Package Kit files (ZIP-based archives)
- **XML Parsing**: AndroidManifest.xml processing using Python's xml.etree.ElementTree
- **ZIP Archive**: APK file structure analysis using Python's zipfile module

## Development Tools
- **Logging**: Python's built-in logging module for application monitoring
- **JSON**: Results serialization and configuration storage
- **Datetime**: Timestamp tracking for scan history
- **Hashlib**: File integrity and signature verification