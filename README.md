# Surksha - Stay Safe, Delete Fake

## Project Overview

**Surksha** is a Python-based cybersecurity tool designed to detect suspicious WhatsApp APK files using AI/ML technology. The application provides a web-based interface for uploading, scanning, and analyzing APK files to identify potential security threats.

### Problem
Fake WhatsApp APK files pose significant security risks to users, including malware infections, data theft, and privacy breaches. Users often download APK files from untrusted sources, making them vulnerable to malicious applications disguised as legitimate WhatsApp installations.

### Solution
Surksha uses machine learning algorithms to analyze APK files and identify suspicious characteristics that may indicate malicious intent. The tool combines static analysis techniques with AI-powered classification to provide accurate threat detection.

### Objective
Provide users with a reliable, easy-to-use tool to:
- Identify potentially malicious WhatsApp APK files
- Make informed decisions about APK installations
- Safely remove suspicious files from their systems

## Features

### 🔍 **APK Scanning**
- **Single File Scan**: Upload and analyze individual APK files
- **Folder Scan**: Batch scan all APK files in the uploads directory
- **Real-time Analysis**: Immediate feedback on file safety

### 🤖 **AI/ML Detection**
- **Machine Learning Classifier**: Uses scikit-learn Random Forest algorithm
- **Feature Extraction**: Analyzes 20+ APK characteristics including:
  - Permission analysis
  - File structure examination
  - Certificate validation
  - String content analysis
  - Entropy calculation

### 🚨 **Smart Alerts**
- **Risk Classification**: Files categorized as SAFE, SUSPICIOUS with confidence scores
- **Detailed Recommendations**: Clear guidance on next steps
- **Risk Level Assessment**: LOW, MEDIUM, HIGH risk categorization

### 🗑️ **Safe Deletion**
- **One-click Removal**: Easy deletion of suspicious files
- **Confirmation Prompts**: Prevents accidental deletions
- **Audit Trail**: Track all scan results and actions

### 🌐 **Web Interface**
- **Modern UI**: Bootstrap-powered responsive design
- **Real-time Updates**: AJAX-based scanning with progress indicators
- **Result History**: View and manage previous scan results
- **Detailed Analysis**: Comprehensive file analysis reports

## Tech Stack

### Backend
- **Python 3.7+**: Core programming language
- **Flask**: Web framework for API and UI
- **scikit-learn**: Machine learning library for classification
- **androguard**: APK analysis and feature extraction (with fallback)
- **pandas**: Data manipulation and analysis
- **numpy**: Numerical computing
- **pathlib**: File system operations

### Frontend
- **HTML5/CSS3/JavaScript**: Core web technologies
- **Bootstrap 5**: UI framework and components
- **Font Awesome**: Icon library
- **AJAX**: Asynchronous operations

### Data Processing
- **joblib**: Model serialization and loading
- **pickle**: Data persistence
- **JSON**: Configuration and result storage

## AI Workflow

