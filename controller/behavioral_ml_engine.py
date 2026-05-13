import os
import joblib


class BehavioralMLEngine:

    def __init__(self, logger):

        self.logger = logger

        self.model_loaded = False

        base_dir = os.path.dirname(__file__)

        self.model_path = os.path.join(
            base_dir,
            "..",
            "ml",
            "behavioral_rf_model.pkl"
        )

        self.scaler_path = os.path.join(
            base_dir,
            "..",
            "ml",
            "behavioral_scaler.pkl"
        )

        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):

            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)

            self.model_loaded = True

            self.logger.info("BEHAVIORAL ML MODEL LOADED")

        else:
            self.logger.warning(
                "BEHAVIORAL ML MODEL NOT FOUND | placeholder mode enabled"
            )

    # =====================================================
    # ML RISK PREDICTION
    # =====================================================

    def predict_risk(self, feature_vector):

        if feature_vector is None:
            return 0.0

        if not self.model_loaded:
            self.logger.info(
                "ML PLACEHOLDER ACTIVE | returning low risk"
            )
            return 0.1

        X = self.scaler.transform([feature_vector])

        risk = float(self.model.predict_proba(X)[0][1])

        self.logger.info(
            "ML RISK GENERATED | risk=%.4f",
            risk
        )

        return risk