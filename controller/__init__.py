self.dos_detector = DoSFeatureExtractor()
self.scaler = joblib.load("ml/piedefender_scaler.pkl")
self.svm = joblib.load("ml/piedefender_svm_model.pkl")
