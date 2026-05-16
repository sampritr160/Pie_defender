# =============================================================================
# BEHAVIORAL ML ENGINE MODULE
# Loads XGBoost model and predicts probability for behavioral analysis
# ML only provides probability. Trust adjustment is applied by Trust Engine.
# =============================================================================

import os
import time
import numpy as np
import joblib
import warnings
from config import *

# Suppress XGBoost feature name warning
warnings.filterwarnings("ignore", message="X does not have valid feature names")

class BehavioralMLEngine:
    
    def __init__(self, logger):
        self.logger = logger
        self.model = None
        self.scaler = None
        self.feature_columns = None
        self.trust_config = None
        self.model_loaded = False
        
        base_dir = os.path.dirname(os.path.abspath(__file__))
        ml_dir = os.path.join(base_dir, "..", "ml", "current")
        
        model_path = os.path.join(ml_dir, "piedefender_model.pkl")
        try:
            self.logger.info("LOADING ML MODEL FILE = %s", model_path)
            self.model = joblib.load(model_path)
            self.logger.info("ML MODEL LOADED SUCCESSFULLY | type=%s", type(self.model).__name__)
        except Exception as e:
            self.logger.error("FAILED TO LOAD ML MODEL | %s", e)
            return
        
        features_path = os.path.join(ml_dir, "piedefender_features.pkl")
        try:
            self.logger.info("LOADING FEATURE FILE = %s", features_path)
            self.feature_columns = joblib.load(features_path)
            self.logger.info("EXPECTED FEATURE COUNT = %d", len(self.feature_columns))
        except Exception as e:
            self.logger.error("FAILED TO LOAD FEATURES | %s", e)
            return
        
        scaler_path = os.path.join(ml_dir, "piedefender_scaler.pkl")
        try:
            self.logger.info("LOADING SCALER FILE = %s", scaler_path)
            self.scaler = joblib.load(scaler_path)
            self.logger.info("SCALER LOADED SUCCESSFULLY")
        except Exception as e:
            self.logger.error("FAILED TO LOAD SCALER | %s", e)
            return
        
        config_path = os.path.join(ml_dir, "piedefender_trust_config.pkl")
        try:
            self.logger.info("LOADING TRUST CONFIG FILE = %s", config_path)
            self.trust_config = joblib.load(config_path)
        except Exception as e:
            self.logger.error("FAILED TO LOAD TRUST CONFIG | %s", e)
        
        self.model_loaded = True
        self.logger.info("PIEDEFENDER ML MODEL FULLY LOADED")
    
    def _safe_value(self, profile, key, default=0.0):
        try:
            value = profile.get(key, default)
            if value is None:
                return float(default)
            if isinstance(value, set):
                return float(len(value))
            return float(value)
        except Exception:
            return float(default)
    
    def build_feature_vector(self, profile, is_new_destination):
        try:
            if profile is None or not isinstance(profile, dict):
                return None
            
            now = time.time()
            host_age = max(1.0, now - profile.get("first_seen", now))
            
            successful_replies = self._safe_value(profile, "successful_replies")
            failed_requests = self._safe_value(profile, "failed_requests")
            total_requests = successful_replies + failed_requests
            reply_ratio = successful_replies / total_requests if total_requests > 0 else 0.0
            
            unique_destinations = float(len(profile.get("unique_destinations", set())))
            destination_growth_rate = unique_destinations / host_age if host_age > 0 else 0.0
            destination_entropy = self._safe_value(profile, "destination_entropy")
            
            ml_history = profile.get("ml_probability_history", [])
            if len(ml_history) >= 2:
                recent = ml_history[-5:] if len(ml_history) >= 5 else ml_history
                x = np.arange(len(recent))
                y = np.array(recent)
                slope = np.polyfit(x, y, 1)[0]
                ml_probability_trend = max(-0.5, min(0.5, slope))
            else:
                ml_probability_trend = 0.0
            
            time_since_last_seen = max(0.001, now - profile.get("last_seen", now))
            syn_ratio = self._safe_value(profile, "syn_ratio", 0.2)
            icmp_ratio = self._safe_value(profile, "icmp_ratio", 0.05)
            udp_ratio = self._safe_value(profile, "udp_ratio", 0.2)
            
            feature_map = {
                "host_age": host_age,
                "reply_ratio": reply_ratio,
                "unique_destinations": unique_destinations,
                "destination_growth_rate": destination_growth_rate,
                "destination_entropy": destination_entropy,
                "ml_probability_trend": ml_probability_trend,
                "is_new_destination": is_new_destination,
                "time_since_last_seen": time_since_last_seen,
                "syn_ratio": syn_ratio,
                "icmp_ratio": icmp_ratio,
                "udp_ratio": udp_ratio
            }
            
            feature_vector = []
            for feature in self.feature_columns:
                feature_vector.append(float(feature_map.get(feature, 0.0)))
            
            return feature_vector
            
        except Exception as e:
            self.logger.error("BUILD FEATURE VECTOR FAILED | %s", e)
            return None
    
    def predict_risk(self, feature_vector):
        if feature_vector is None or not self.model_loaded or self.scaler is None:
            return 0.0
        
        try:
            X = np.array([feature_vector], dtype=np.float32)
            X_scaled = self.scaler.transform(X)
            probability = float(self.model.predict(X_scaled)[0])
            probability = max(0.0, min(1.0, probability))
            return probability
        except Exception as e:
            self.logger.error("ML PREDICTION FAILED | %s", e)
            return 0.0
    
    def predict_behavior(self, profile, is_new_destination):
        if not self.model_loaded:
            return {"probability": 0.0}
        
        try:
            self.logger.info("RUNNING ML ANALYSIS | mac=%s", profile.get("mac", "unknown"))
            
            feature_vector = self.build_feature_vector(profile, is_new_destination)
            if feature_vector is None:
                self.logger.error("FEATURE VECTOR IS NONE")
                return {"probability": 0.0}
            
            probability = self.predict_risk(feature_vector)
            self.logger.info("ML ANALYSIS | probability=%.4f", probability)
            return {"probability": probability}
            
        except Exception as e:
            self.logger.error("PREDICT BEHAVIOR FAILED | %s", e)
            return {"probability": 0.0}