#!/usr/bin/env python3
"""
Feature Extractor Module
Extracts features from APK files for ML classification
"""

import os
import zipfile
import logging
from pathlib import Path
import re
import hashlib

logger = logging.getLogger(__name__)

class FeatureExtractor:
    """Extract features from APK files for machine learning"""
    
    def __init__(self):
        self.suspicious_permissions = [
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.RECORD_AUDIO',
            'android.permission.CAMERA',
            'android.permission.READ_PHONE_STATE',
            'android.permission.CALL_PHONE',
            'android.permission.READ_CALL_LOG',
            'android.permission.WRITE_CALL_LOG',
            'android.permission.GET_ACCOUNTS',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ]
        
        self.whatsapp_permissions = [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.WAKE_LOCK',
            'android.permission.VIBRATE',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS'
        ]
    
    def extract_features(self, apk_path):
        """Extract comprehensive features from APK file"""
        try:
            features = {}
            
            # Basic file features
            features.update(self._extract_file_features(apk_path))
            
            # APK structure features
            features.update(self._extract_structure_features(apk_path))
            
            # Manifest features (simplified)
            features.update(self._extract_manifest_features(apk_path))
            
            # Certificate features
            features.update(self._extract_certificate_features(apk_path))
            
            # String analysis features
            features.update(self._extract_string_features(apk_path))
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features from {apk_path}: {e}")
            return {'error': str(e)}
    
    def _extract_file_features(self, apk_path):
        """Extract basic file-level features"""
        try:
            features = {}
            stat_info = os.stat(apk_path)
            
            features['file_size'] = stat_info.st_size
            features['file_size_mb'] = stat_info.st_size / (1024 * 1024)
            
            # Calculate entropy (measure of randomness)
            with open(apk_path, 'rb') as f:
                data = f.read(1024 * 1024)  # Read first 1MB
                features['entropy'] = self._calculate_entropy(data)
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting file features: {e}")
            return {}
    
    def _extract_structure_features(self, apk_path):
        """Extract APK structure features"""
        try:
            features = {}
            
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                file_list = apk_zip.namelist()
                
                features['total_files'] = len(file_list)
                features['has_classes_dex'] = 'classes.dex' in file_list
                features['has_resources_arsc'] = 'resources.arsc' in file_list
                
                # Count different file types
                features['dex_files'] = sum(1 for f in file_list if f.endswith('.dex'))
                features['so_files'] = sum(1 for f in file_list if f.endswith('.so'))
                features['png_files'] = sum(1 for f in file_list if f.endswith('.png'))
                features['xml_files'] = sum(1 for f in file_list if f.endswith('.xml'))
                
                # Directory structure
                features['has_assets'] = any(f.startswith('assets/') for f in file_list)
                features['has_lib'] = any(f.startswith('lib/') for f in file_list)
                features['has_res'] = any(f.startswith('res/') for f in file_list)
                features['has_meta_inf'] = any(f.startswith('META-INF/') for f in file_list)
                
                # Suspicious file patterns
                features['suspicious_files'] = self._count_suspicious_files(file_list)
                
            return features
            
        except Exception as e:
            logger.error(f"Error extracting structure features: {e}")
            return {}
    
    def _extract_manifest_features(self, apk_path):
        """Extract features from AndroidManifest.xml (simplified approach)"""
        try:
            features = {}
            
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                if 'AndroidManifest.xml' in apk_zip.namelist():
                    manifest_data = apk_zip.read('AndroidManifest.xml')
                    
                    # Since AndroidManifest.xml is binary, we'll do basic pattern matching
                    manifest_str = str(manifest_data)
                    
                    # Extract package name pattern
                    features['package_name'] = self._extract_package_name(manifest_str)
                    features['app_name'] = self._extract_app_name(manifest_str)
                    
                    # Count permissions (rough estimate)
                    features['permission_count'] = manifest_str.count('permission')
                    
                    # Check for suspicious permissions
                    features['suspicious_permissions'] = 0
                    for perm in self.suspicious_permissions:
                        if perm in manifest_str:
                            features['suspicious_permissions'] += 1
                    
                    # Check for legitimate WhatsApp permissions
                    features['whatsapp_permissions'] = 0
                    for perm in self.whatsapp_permissions:
                        if perm in manifest_str:
                            features['whatsapp_permissions'] += 1
                    
                    # Activity and service count (rough estimate)
                    features['activity_count'] = manifest_str.count('activity')
                    features['service_count'] = manifest_str.count('service')
                    features['receiver_count'] = manifest_str.count('receiver')
                    
                else:
                    features['has_manifest'] = False
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting manifest features: {e}")
            return {}
    
    def _extract_certificate_features(self, apk_path):
        """Extract certificate-related features"""
        try:
            features = {}
            
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                cert_files = [f for f in apk_zip.namelist() if f.startswith('META-INF/') and f.endswith('.RSA')]
                
                features['has_certificate'] = len(cert_files) > 0
                features['certificate_count'] = len(cert_files)
                
                if cert_files:
                    # Get certificate file info
                    cert_info = apk_zip.getinfo(cert_files[0])
                    features['cert_file_size'] = cert_info.file_size
                
            return features
            
        except Exception as e:
            logger.error(f"Error extracting certificate features: {e}")
            return {}
    
    def _extract_string_features(self, apk_path):
        """Extract string-based features"""
        try:
            features = {}
            
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Look for strings.xml or other text files
                text_content = ""
                
                for file_path in apk_zip.namelist():
                    if file_path.endswith('.xml') or file_path.endswith('.txt'):
                        try:
                            content = apk_zip.read(file_path).decode('utf-8', errors='ignore')
                            text_content += content
                        except:
                            continue
                
                # Analyze text content
                features['total_text_length'] = len(text_content)
                
                # Look for suspicious strings
                suspicious_keywords = [
                    'password', 'credit', 'bank', 'paypal', 'bitcoin',
                    'hack', 'crack', 'mod', 'premium', 'unlock'
                ]
                
                features['suspicious_strings'] = 0
                for keyword in suspicious_keywords:
                    features['suspicious_strings'] += text_content.lower().count(keyword)
                
                # Look for WhatsApp-related strings
                whatsapp_keywords = ['whatsapp', 'chat', 'message', 'status', 'call']
                features['whatsapp_strings'] = 0
                for keyword in whatsapp_keywords:
                    features['whatsapp_strings'] += text_content.lower().count(keyword)
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting string features: {e}")
            return {}
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        try:
            if not data:
                return 0
            
            # Count byte frequencies
            frequency = {}
            for byte in data:
                frequency[byte] = frequency.get(byte, 0) + 1
            
            # Calculate entropy
            entropy = 0
            data_len = len(data)
            for count in frequency.values():
                prob = count / data_len
                if prob > 0:
                    entropy -= prob * (prob).bit_length()
            
            return entropy
            
        except Exception as e:
            logger.error(f"Error calculating entropy: {e}")
            return 0
    
    def _count_suspicious_files(self, file_list):
        """Count files with suspicious names or extensions"""
        suspicious_patterns = [
            r'.*\.exe$',
            r'.*\.bat$',
            r'.*\.sh$',
            r'.*password.*',
            r'.*crack.*',
            r'.*hack.*',
            r'.*\.db$'
        ]
        
        count = 0
        for file_path in file_list:
            for pattern in suspicious_patterns:
                if re.match(pattern, file_path.lower()):
                    count += 1
                    break
        
        return count
    
    def _extract_package_name(self, manifest_str):
        """Extract package name from manifest string"""
        try:
            # Simple pattern matching for package name
            if 'com.whatsapp' in manifest_str:
                return 'com.whatsapp'
            elif 'whatsapp' in manifest_str.lower():
                return 'unknown_whatsapp_variant'
            else:
                return 'unknown'
        except:
            return 'unknown'
    
    def _extract_app_name(self, manifest_str):
        """Extract app name from manifest string"""
        try:
            if 'whatsapp' in manifest_str.lower():
                return 'WhatsApp'
            else:
                return 'Unknown App'
        except:
            return 'Unknown App'
