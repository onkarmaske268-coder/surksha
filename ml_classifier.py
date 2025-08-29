#!/usr/bin/env python3
"""
ML Classifier Module
Machine Learning classifier for APK malware detection
"""

import os
import pickle
import logging
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score
import joblib
from datetime import datetime

logger = logging.getLogger(__name__)

class MLClassifier:
    """Machine Learning classifier for APK malware detection"""
    
    def __init__(self, model_path='models/classifier_model.pkl'):
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.is_trained = False
        
        # Ensure models directory exists
        os.makedirs('models', exist_ok=True)
        
        # Feature importance weights for scoring
        self.feature_weights = {
            'suspicious_permissions': 0.15,
            'whatsapp_permissions': -0.1,  # Legitimate WhatsApp permissions reduce suspicion
            'file_size_mb': 0.05,
            'entropy': 0.1,
            'suspicious_files': 0.2,
            'suspicious_strings': 0.15,
            'whatsapp_strings': -0.05,
            'certificate_count': -0.05,
            'has_certificate': -0.1
        }
    
    def initialize(self):
        """Initialize the classifier"""
        try:
            if os.path.exists(self.model_path):
                self.load_model()
                logger.info("Loaded existing ML model")
            else:
                self.create_default_model()
                logger.info("Created default ML model")
            
            return True
            
        except Exception as e:
            logger.error(f"Error initializing classifier: {e}")
            self.create_fallback_classifier()
            return False
    
    def create_default_model(self):
        """Create a default trained model with synthetic training data"""
        try:
            logger.info("Creating default ML model...")
            
            # Generate synthetic training data based on common APK patterns
            X_train, y_train = self._generate_training_data()
            
            # Initialize and train the model
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                class_weight='balanced'
            )
            
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X_train)
            
            self.model.fit(X_scaled, y_train)
            self.is_trained = True
            
            # Save the model
            self.save_model()
            
            logger.info("Default ML model created and saved")
            
        except Exception as e:
            logger.error(f"Error creating default model: {e}")
            raise
    
    def _generate_training_data(self):
        """Generate synthetic training data for APK classification"""
        np.random.seed(42)
        
        # Features: [suspicious_permissions, whatsapp_permissions, file_size_mb, entropy,
        #           suspicious_files, suspicious_strings, whatsapp_strings, certificate_count, has_certificate]
        
        # Legitimate WhatsApp APK patterns
        legitimate_samples = []
        for _ in range(100):
            sample = [
                np.random.randint(2, 8),    # suspicious_permissions (moderate)
                np.random.randint(6, 10),   # whatsapp_permissions (high - legitimate)
                np.random.uniform(50, 150), # file_size_mb (normal size)
                np.random.uniform(6, 8),    # entropy (normal)
                np.random.randint(0, 2),    # suspicious_files (very low)
                np.random.randint(0, 3),    # suspicious_strings (low)
                np.random.randint(10, 50),  # whatsapp_strings (high - legitimate)
                1,                          # certificate_count (signed)
                1                           # has_certificate (true)
            ]
            legitimate_samples.append(sample)
        
        # Suspicious/Fake APK patterns
        suspicious_samples = []
        for _ in range(100):
            sample = [
                np.random.randint(8, 15),   # suspicious_permissions (high)
                np.random.randint(0, 5),    # whatsapp_permissions (low - fake)
                np.random.uniform(5, 200),  # file_size_mb (variable)
                np.random.uniform(4, 10),   # entropy (variable)
                np.random.randint(3, 10),   # suspicious_files (high)
                np.random.randint(5, 20),   # suspicious_strings (high)
                np.random.randint(0, 5),    # whatsapp_strings (low - fake)
                np.random.randint(0, 1),    # certificate_count (often unsigned)
                np.random.randint(0, 1)     # has_certificate (often false)
            ]
            suspicious_samples.append(sample)
        
        # Combine data
        X = np.array(legitimate_samples + suspicious_samples)
        y = np.array([0] * len(legitimate_samples) + [1] * len(suspicious_samples))  # 0=safe, 1=suspicious
        
        # Feature names for reference
        self.feature_names = [
            'suspicious_permissions', 'whatsapp_permissions', 'file_size_mb', 'entropy',
            'suspicious_files', 'suspicious_strings', 'whatsapp_strings', 
            'certificate_count', 'has_certificate'
        ]
        
        return X, y
    
    def classify_apk(self, features):
        """Classify APK as safe or suspicious"""
        try:
            if not self.is_trained or self.model is None or self.scaler is None:
                return self._fallback_classification(features)
            
            # Extract relevant features for classification
            feature_vector = self._extract_feature_vector(features)
            
            if feature_vector is None:
                return self._fallback_classification(features)
            
            # Scale features
            feature_vector_scaled = self.scaler.transform([feature_vector])
            
            # Make prediction
            prediction = self.model.predict(feature_vector_scaled)[0]
            probability = self.model.predict_proba(feature_vector_scaled)[0]
            
            # Calculate confidence score
            confidence = float(max(probability))
            
            # Determine risk level
            if prediction == 0:  # Safe
                status = "SAFE"
                risk_level = "LOW"
                recommendation = "This APK appears to be legitimate WhatsApp."
            else:  # Suspicious
                status = "SUSPICIOUS"
                if confidence > 0.8:
                    risk_level = "HIGH"
                    recommendation = "This APK shows multiple suspicious characteristics. Strongly recommend deletion."
                else:
                    risk_level = "MEDIUM"
                    recommendation = "This APK has some suspicious features. Consider verifying its source."
            
            result = {
                'status': status,
                'risk_level': risk_level,
                'confidence': round(confidence * 100, 2),
                'recommendation': recommendation,
                'prediction_score': prediction,
                'probability_safe': round(probability[0] * 100, 2),
                'probability_suspicious': round(probability[1] * 100, 2),
                'classification_time': datetime.now().isoformat()
            }
            
            # Add detailed analysis
            result['detailed_analysis'] = self._generate_detailed_analysis(features, feature_vector)
            
            return result
            
        except Exception as e:
            logger.error(f"Error in classification: {e}")
            return self._fallback_classification(features)
    
    def _extract_feature_vector(self, features):
        """Extract feature vector from APK features"""
        try:
            vector = [
                features.get('suspicious_permissions', 0),
                features.get('whatsapp_permissions', 0),
                features.get('file_size_mb', 0),
                features.get('entropy', 0),
                features.get('suspicious_files', 0),
                features.get('suspicious_strings', 0),
                features.get('whatsapp_strings', 0),
                features.get('certificate_count', 0),
                int(features.get('has_certificate', False))
            ]
            
            return vector
            
        except Exception as e:
            logger.error(f"Error extracting feature vector: {e}")
            return None
    
    def _fallback_classification(self, features):
        """Fallback classification using rule-based approach"""
        try:
            score = 0
            reasons = []
            
            # Check suspicious permissions
            suspicious_perms = features.get('suspicious_permissions', 0)
            if suspicious_perms > 10:
                score += 30
                reasons.append(f"High number of suspicious permissions ({suspicious_perms})")
            elif suspicious_perms > 5:
                score += 15
                reasons.append(f"Moderate suspicious permissions ({suspicious_perms})")
            
            # Check legitimate WhatsApp permissions
            whatsapp_perms = features.get('whatsapp_permissions', 0)
            if whatsapp_perms < 3:
                score += 20
                reasons.append(f"Low WhatsApp permissions for claimed WhatsApp app ({whatsapp_perms})")
            
            # Check file size
            file_size = features.get('file_size_mb', 0)
            if file_size < 10:
                score += 25
                reasons.append(f"Unusually small file size ({file_size:.1f} MB)")
            elif file_size > 200:
                score += 15
                reasons.append(f"Unusually large file size ({file_size:.1f} MB)")
            
            # Check suspicious files
            suspicious_files = features.get('suspicious_files', 0)
            if suspicious_files > 0:
                score += suspicious_files * 10
                reasons.append(f"Contains {suspicious_files} suspicious files")
            
            # Check certificate
            if not features.get('has_certificate', True):
                score += 25
                reasons.append("APK is not properly signed")
            
            # Check suspicious strings
            suspicious_strings = features.get('suspicious_strings', 0)
            if suspicious_strings > 5:
                score += 15
                reasons.append(f"Contains {suspicious_strings} suspicious text strings")
            
            # Check if it claims to be WhatsApp but lacks WhatsApp strings
            is_whatsapp = features.get('package_name', '').lower().find('whatsapp') != -1
            whatsapp_strings = features.get('whatsapp_strings', 0)
            if is_whatsapp and whatsapp_strings < 5:
                score += 20
                reasons.append("Claims to be WhatsApp but lacks typical WhatsApp content")
            
            # Determine final classification
            if score >= 60:
                status = "SUSPICIOUS"
                risk_level = "HIGH"
                recommendation = "This APK shows multiple suspicious characteristics. Strongly recommend deletion."
            elif score >= 30:
                status = "SUSPICIOUS"
                risk_level = "MEDIUM"
                recommendation = "This APK has some suspicious features. Consider verifying its source."
            else:
                status = "SAFE"
                risk_level = "LOW"
                recommendation = "This APK appears to be legitimate WhatsApp."
            
            return {
                'status': status,
                'risk_level': risk_level,
                'confidence': min(score * 1.5, 95),
                'recommendation': recommendation,
                'suspicion_score': score,
                'reasons': reasons,
                'method': 'rule_based_fallback',
                'classification_time': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in fallback classification: {e}")
            return {
                'status': 'UNKNOWN',
                'risk_level': 'UNKNOWN',
                'confidence': 0,
                'recommendation': 'Unable to analyze APK file.',
                'error': str(e)
            }
    
    def _generate_detailed_analysis(self, features, feature_vector):
        """Generate detailed analysis of the APK"""
        analysis = {
            'permissions_analysis': f"Found {features.get('suspicious_permissions', 0)} suspicious permissions and {features.get('whatsapp_permissions', 0)} legitimate WhatsApp permissions",
            'file_analysis': f"File size: {features.get('file_size_mb', 0):.1f} MB, Entropy: {features.get('entropy', 0):.2f}",
            'structure_analysis': f"Contains {features.get('suspicious_files', 0)} suspicious files",
            'content_analysis': f"Found {features.get('suspicious_strings', 0)} suspicious strings and {features.get('whatsapp_strings', 0)} WhatsApp-related strings",
            'certificate_analysis': f"Certificate present: {features.get('has_certificate', False)}, Count: {features.get('certificate_count', 0)}"
        }
        
        return analysis
    
    def save_model(self):
        """Save the trained model"""
        try:
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names,
                'is_trained': self.is_trained,
                'created_at': datetime.now().isoformat()
            }
            
            joblib.dump(model_data, self.model_path)
            logger.info(f"Model saved to {self.model_path}")
            
        except Exception as e:
            logger.error(f"Error saving model: {e}")
    
    def load_model(self):
        """Load a trained model"""
        try:
            model_data = joblib.load(self.model_path)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']
            self.is_trained = model_data['is_trained']
            
            logger.info(f"Model loaded from {self.model_path}")
            
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            raise
    
    def create_fallback_classifier(self):
        """Create a simple fallback classifier"""
        logger.warning("Using fallback rule-based classifier")
        self.is_trained = False
    
    def is_ready(self):
        """Check if classifier is ready"""
        return self.model is not None or not self.is_trained
    
    def retrain_model(self, new_features, new_labels):
        """Retrain model with new data"""
        try:
            if not self.is_trained:
                logger.error("No base model to retrain")
                return False
            
            # Prepare data
            X_new = np.array([self._extract_feature_vector(f) for f in new_features])
            y_new = np.array(new_labels)
            
            # Scale features
            if self.scaler is None:
                return False
            X_new_scaled = self.scaler.transform(X_new)
            
            # Retrain model (partial fit or full retrain)
            if self.model is not None:
                self.model.fit(X_new_scaled, y_new)
            
            # Save updated model
            self.save_model()
            
            logger.info(f"Model retrained with {len(new_features)} new samples")
            return True
            
        except Exception as e:
            logger.error(f"Error retraining model: {e}")
            return False
