# Isolation Forest Primary Detector Module for Objective 2
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

FEATURE_SCHEMA = [
    'event_frequency',
    'sequence_length',
    'error_count',
    'error_pattern',
    'login_attempts',
    'failed_login_attempts',
    'warning_count',
    'unknown_events'
]


class IsolationForestPrimaryDetector:
    """
    Objective 2 Primary Model:
    Implements behavior-based unsupervised Isolation Forest anomaly detection.
    Evaluates 8 behavioral features and maps decision tree isolation path lengths
    to continuous normalized anomaly scores in range [0.0, 1.0].
    """

    def __init__(self, n_estimators=100, contamination=0.0293, max_samples='auto', random_state=42):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.max_samples = max_samples
        self.random_state = random_state
        self.feature_columns = FEATURE_SCHEMA
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            max_samples=self.max_samples,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.is_fitted = False

    def fit(self, X_train):
        """Fits Isolation Forest purely unsupervised on feature matrix X (no labels)."""
        X_mat = X_train[self.feature_columns] if isinstance(X_train, pd.DataFrame) else X_train
        self.model.fit(X_mat)
        self.is_fitted = True
        return self

    def load_pretrained(self, model_path=None):
        """Loads existing verified HDFS Isolation Forest model artifact."""
        if model_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(base_dir, '..', '..', 'backend', 'models', 'hdfs_isolation_forest_model.pkl')

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model artifact not found at {model_path}")

        self.model = joblib.load(model_path)
        self.n_estimators = len(self.model.estimators_)
        self.contamination = getattr(self.model, 'contamination', self.contamination)
        self.is_fitted = True
        return self

    def predict(self, X):
        """
        Predicts anomaly status and normalized continuous scores for feature matrix X.
        Higher normalized score indicates higher anomaly likelihood.
        Threshold: 0.50 (score >= 0.50 -> Anomaly).
        """
        X_mat = X[self.feature_columns] if isinstance(X, pd.DataFrame) else X
        raw_preds = self.model.predict(X_mat)
        raw_scores = self.model.decision_function(X_mat)

        is_anomaly = np.where(raw_preds == -1, 1, 0)
        norm_scores = np.clip(1.0 - (raw_scores + 0.5), 0.0, 1.0)

        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': np.round(norm_scores, 4),
            'raw_scores': raw_scores,
            'detected_anomalies': int(np.sum(is_anomaly)),
            'total_samples': len(is_anomaly),
            'anomaly_percentage': round((np.sum(is_anomaly) / len(is_anomaly)) * 100.0, 2)
        }
