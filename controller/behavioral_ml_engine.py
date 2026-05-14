import os
import time
import joblib
import numpy as np

from config import *


class BehavioralMLEngine:

    def __init__(self, logger):

        self.logger = logger

        self.model_loaded = False

        base_dir = os.path.dirname(__file__)

        self.model_path = os.path.join(
            base_dir,
            "..",
            "ml",
            "piedefender_model.pkl"
        )

        self.features_path = os.path.join(
            base_dir,
            "..",
            "ml",
            "piedefender_features.pkl"
        )

        try:

            self.logger.info(
                "LOADING ML MODEL FILE = %s",
                self.model_path
            )

            self.model = joblib.load(
                self.model_path
            )

            self.logger.info(
                "LOADING FEATURE FILE = %s",
                self.features_path
            )

            self.feature_columns = joblib.load(
                self.features_path
            )

            self.logger.info(
                "EXPECTED FEATURE COUNT = %s",
                len(self.feature_columns)
            )

            self.logger.info(
                "EXPECTED FEATURES = %s",
                self.feature_columns
            )

            self.model_loaded = True

            self.logger.info(
                "PIEDEFENDER ML MODEL LOADED SUCCESSFULLY"
            )

        except Exception as e:

            self.logger.error(
                "FAILED TO LOAD ML MODEL | %s",
                e
            )

    # =====================================================
    # SAFE VALUE
    # =====================================================

    def _safe_value(self, profile, key):

        try:

            value = profile.get(key, 0)

            if value is None:
                return 0.0

            if isinstance(value, set):
                return float(len(value))

            if isinstance(value, dict):
                return float(len(value))

            return float(value)

        except Exception:

            return 0.0

    # =====================================================
    # BUILD FEATURE VECTOR
    # =====================================================

    def build_feature_vector(self, profile):

        try:

            if profile is None:

                self.logger.error(
                    "PROFILE IS NONE"
                )

                return None

            if not isinstance(profile, dict):

                self.logger.error(
                    "PROFILE IS NOT DICT | type=%s",
                    type(profile)
                )

                return None

            now = time.time()

            host_age = max(
                1,
                now - profile.get("first_seen", now)
            )

            successful_replies = self._safe_value(
                profile,
                "successful_replies"
            )

            failed_requests = self._safe_value(
                profile,
                "failed_requests"
            )

            total_requests = (
                successful_replies
                + failed_requests
            )

            reply_ratio = 0.0

            if total_requests > 0:

                reply_ratio = (
                    successful_replies
                    / total_requests
                )

            unique_destinations = float(
                len(
                    profile.get(
                        "unique_destinations",
                        set()
                    )
                )
            )

            packets_per_second = self._safe_value(
                profile,
                "packets_per_second"
            )

            bytes_per_second = self._safe_value(
                profile,
                "bytes_per_second"
            )

            destination_entropy = self._safe_value(
                profile,
                "destination_entropy"
            )

            mac_churn_rate = self._safe_value(
                profile,
                "mac_churn_rate"
            )

            controller_load_impact = (
                packets_per_second
                * max(1.0, unique_destinations)
            )

            flow_miss_rate = failed_requests

            feature_map = {

                "host_age":
                    host_age,

                "packet_count":
                    self._safe_value(
                        profile,
                        "packet_count"
                    ),

                "failed_requests":
                    failed_requests,

                "reply_ratio":
                    reply_ratio,

                "unique_destinations":
                    unique_destinations,

                "packets_per_second":
                    packets_per_second,

                "bytes_per_second":
                    bytes_per_second,

                "avg_packet_size":
                    self._safe_value(
                        profile,
                        "avg_packet_size"
                    ),

                "interarrival_mean":
                    self._safe_value(
                        profile,
                        "interarrival_mean"
                    ),

                "interarrival_std":
                    self._safe_value(
                        profile,
                        "interarrival_std"
                    ),

                "burstiness":
                    self._safe_value(
                        profile,
                        "burstiness"
                    ),

                "destination_growth_rate":
                    self._safe_value(
                        profile,
                        "destination_growth_rate"
                    ),

                "destination_entropy":
                    destination_entropy,

                "flow_miss_rate":
                    flow_miss_rate,

                "mac_churn_rate":
                    mac_churn_rate,

                "controller_load_impact":
                    controller_load_impact,

                "syn_ratio":
                    self._safe_value(
                        profile,
                        "syn_ratio"
                    ),

                "icmp_ratio":
                    self._safe_value(
                        profile,
                        "icmp_ratio"
                    ),

                "udp_ratio":
                    self._safe_value(
                        profile,
                        "udp_ratio"
                    )
            }

            # =================================================
            # LOG FEATURES
            # =================================================

            feature_map["log_packet_count"] = np.log1p(
                feature_map["packet_count"]
            )

            feature_map["log_bytes_per_second"] = np.log1p(
                feature_map["bytes_per_second"]
            )

            feature_map["log_flow_miss_rate"] = np.log1p(
                feature_map["flow_miss_rate"]
            )

            feature_map["log_mac_churn_rate"] = np.log1p(
                feature_map["mac_churn_rate"]
            )

            feature_map["log_controller_load"] = np.log1p(
                feature_map["controller_load_impact"]
            )

            feature_map["log_destination_entropy"] = np.log1p(
                feature_map["destination_entropy"]
            )

            vector = []

            self.logger.info(
                "BUILDING ML FEATURE VECTOR"
            )

            for feature in self.feature_columns:

                value = feature_map.get(
                    feature,
                    0.0
                )

                vector.append(float(value))

                self.logger.info(
                    "ML FEATURE | %s = %.4f",
                    feature,
                    float(value)
                )

            self.logger.info(
                "FEATURE VECTOR CREATED | length=%s",
                len(vector)
            )

            return vector

        except Exception as e:

            self.logger.error(
                "FEATURE VECTOR BUILD FAILED | %s",
                e
            )

            return None

    # =====================================================
    # RAW RISK PREDICTION
    # =====================================================

    def predict_risk(self, feature_vector):

        if feature_vector is None:

            self.logger.error(
                "FEATURE VECTOR IS NONE"
            )

            return 0.0

        if not self.model_loaded:

            self.logger.error(
                "MODEL NOT LOADED"
            )

            return 0.0

        try:

            X = np.array(
                [feature_vector],
                dtype=np.float32
            )

            self.logger.info(
                "RUNNING ML INFERENCE"
            )

            probability = float(
                self.model.predict_proba(X)[0][1]
            )

            self.logger.info(
                "ML RISK SCORE = %.4f",
                probability
            )

            return probability

        except Exception as e:

            self.logger.error(
                "ML INFERENCE FAILED | %s",
                e
            )

            return 0.0

    # =====================================================
    # FULL BEHAVIOR PREDICTION
    # =====================================================

    def predict_behavior(self, profile):

        if not self.model_loaded:

            return {

                "probability": 0.0,

                "state": STATE_OBSERVATION
            }

        try:

            self.logger.info(
                "RUNNING ML ANALYSIS"
            )

            feature_vector = self.build_feature_vector(
                profile
            )

            probability = self.predict_risk(
                feature_vector
            )

            # =============================================
            # ML STATE DECISION
            # =============================================

            if probability >= ML_BLOCK_THRESHOLD:

                state = STATE_BLOCKED

            elif probability >= ML_SUSPICIOUS_THRESHOLD:

                state = STATE_SUSPICIOUS

            elif probability <= ML_OBSERVATION_THRESHOLD:

                state = STATE_TRUSTED

            else:

                state = STATE_OBSERVATION

            self.logger.info(
                "ML DECISION | probability=%.4f state=%s",
                probability,
                state
            )

            return {

                "probability": probability,

                "state": state
            }

        except Exception as e:

            self.logger.error(
                "ML PREDICTION FAILED | %s",
                e
            )

            return {

                "probability": 0.0,

                "state": STATE_OBSERVATION
            }