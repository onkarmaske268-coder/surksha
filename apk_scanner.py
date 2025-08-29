#!/usr/bin/env python3
"""
APK Scanner Module
Handles APK file detection and basic analysis
"""

import os
import zipfile
import hashlib
import logging
from pathlib import Path
import xml.etree.ElementTree as ET
from feature_extractor import FeatureExtractor

logger = logging.getLogger(__name__)

class APKScanner:
    """APK file scanner and analyzer"""
    
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.whatsapp_package_names = [
            'com.whatsapp',
            'com.whatsapp.w4b',  # WhatsApp Business
            'com.gbwhatsapp',    # Common fake WhatsApp variant
            'com.fmwhatsapp',    # Another variant
            'com.yowhatsapp',    # YOWhatsApp variant
        ]
    
    def is_apk_file(self, filepath):
        """Check if file is a valid APK"""
        try:
            if not filepath.lower().endswith('.apk'):
                return False
            
            # Check if it's a valid ZIP file (APK is a ZIP)
            with zipfile.ZipFile(filepath, 'r') as apk_zip:
                # Check for AndroidManifest.xml
                if 'AndroidManifest.xml' in apk_zip.namelist():
                    return True
            return False
        except:
            return False
    
    def scan_apk(self, filepath):
        """Main APK scanning function"""
        try:
            logger.info(f"Scanning APK: {filepath}")
            
            if not os.path.exists(filepath):
                return {'success': False, 'error': 'File does not exist'}
            
            if not self.is_apk_file(filepath):
                return {'success': False, 'error': 'Invalid APK file'}
            
            # Extract basic file info
            file_info = self._get_file_info(filepath)
            
            # Extract APK features
            features = self.feature_extractor.extract_features(filepath)
            
            # Check if it claims to be WhatsApp
            is_whatsapp_related = self._is_whatsapp_related(features)
            
            result = {
                'success': True,
                'filepath': filepath,
                'filename': os.path.basename(filepath),
                'file_info': file_info,
                'features': features,
                'is_whatsapp_related': is_whatsapp_related,
                'scan_timestamp': file_info['scan_time']
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error scanning APK {filepath}: {e}")
            return {
                'success': False,
                'error': f'Scan failed: {str(e)}',
                'filepath': filepath
            }
    
    def _get_file_info(self, filepath):
        """Extract basic file information"""
        try:
            stat_info = os.stat(filepath)
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(filepath)
            
            return {
                'size': stat_info.st_size,
                'size_mb': round(stat_info.st_size / (1024 * 1024), 2),
                'modified_time': stat_info.st_mtime,
                'sha256': file_hash,
                'scan_time': Path(filepath).stat().st_mtime
            }
        except Exception as e:
            logger.error(f"Error getting file info: {e}")
            return {'error': str(e)}
    
    def _calculate_file_hash(self, filepath):
        """Calculate SHA256 hash of the file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash: {e}")
            return None
    
    def _is_whatsapp_related(self, features):
        """Check if APK claims to be WhatsApp or related"""
        try:
            package_name = features.get('package_name', '').lower()
            app_name = features.get('app_name', '').lower()
            
            # Check package name
            for whatsapp_pkg in self.whatsapp_package_names:
                if whatsapp_pkg.lower() in package_name:
                    return True
            
            # Check app name for WhatsApp keywords
            whatsapp_keywords = ['whatsapp', 'whats app', 'wa messenger']
            for keyword in whatsapp_keywords:
                if keyword in app_name:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking WhatsApp relation: {e}")
            return False
    
    def scan_directory(self, directory_path):
        """Scan directory for APK files"""
        try:
            apk_files = []
            directory = Path(directory_path)
            
            if not directory.exists():
                return {'success': False, 'error': 'Directory does not exist'}
            
            # Find all APK files
            for file_path in directory.rglob('*.apk'):
                if self.is_apk_file(str(file_path)):
                    apk_files.append(str(file_path))
            
            logger.info(f"Found {len(apk_files)} APK files in {directory_path}")
            return {'success': True, 'apk_files': apk_files}
            
        except Exception as e:
            logger.error(f"Error scanning directory: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_apk_metadata(self, filepath):
        """Extract metadata from APK manifest"""
        try:
            metadata = {}
            
            with zipfile.ZipFile(filepath, 'r') as apk_zip:
                # Try to read AndroidManifest.xml
                if 'AndroidManifest.xml' in apk_zip.namelist():
                    manifest_data = apk_zip.read('AndroidManifest.xml')
                    # Note: AndroidManifest.xml is binary encoded
                    # We'll extract basic info through feature extractor
                    metadata['has_manifest'] = True
                else:
                    metadata['has_manifest'] = False
                
                # Get file list
                metadata['file_count'] = len(apk_zip.namelist())
                metadata['files'] = apk_zip.namelist()[:10]  # First 10 files
                
                # Check for common directories
                metadata['has_classes_dex'] = 'classes.dex' in apk_zip.namelist()
                metadata['has_resources'] = 'resources.arsc' in apk_zip.namelist()
                metadata['has_assets'] = any(f.startswith('assets/') for f in apk_zip.namelist())
                metadata['has_lib'] = any(f.startswith('lib/') for f in apk_zip.namelist())
            
            return metadata
            
        except Exception as e:
            logger.error(f"Error extracting APK metadata: {e}")
            return {'error': str(e)}
