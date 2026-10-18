# One-Class SVM Secondary Validator Module for Objective 2
import numpy as np
import pandas as pd
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.exceptions import NotFittedError

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


class OneClassSVMValidator:
    """
    Objective 2 Validation Model:
    Implements One-Class SVM with RBF kernel and training-isolated feature scaling
    as an independent secondary validator to cross-verify Isolation Forest detections.
    """

    def __init__(self, kernel='rbf', gamma='scale', nu=0.03):
        self.kernel = kernel
        self.gamma = gamma
        self.nu = nu
        self.feature_columns = FEATURE_SCHEMA
        self.scaler = StandardScaler()
        self.model = OneClassSVM(kernel=self.kernel, gamma=self.gamma, nu=self.nu)
        self.is_fitted = False

    def fit(self, X_train):
        """Fits One-Class SVM purely unsupervised on feature matrix X (no labels).
        Scales features using StandardScaler fitted strictly on training data."""
        X_mat = X_train[self.feature_columns] if isinstance(X_train, pd.DataFrame) else X_train
        X_scaled = self.scaler.fit_transform(X_mat)
        self.model.fit(X_scaled)
        self.is_fitted = True
        return self

    def predict(self, X):
        """Predicts anomaly status using One-Class SVM decision boundary."""
        if not self.is_fitted:
            raise NotFittedError(
                "OneClassSVMValidator is not fitted yet. Call 'fit(X_train)' with training data before 'predict()'."
            )

        X_mat = X[self.feature_columns] if isinstance(X, pd.DataFrame) else X
        X_scaled = self.scaler.transform(X_mat)

        raw_preds = self.model.predict(X_scaled)
        raw_scores = self.model.decision_function(X_scaled)

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

    @staticmethod
    def compare_predictions(if_preds, ocsvm_preds):
        """
        Compares Isolation Forest and One-Class SVM predictions.
        Produces 4 consensus states:
        1. Consensus Normal (Both say Normal)
        2. Consensus Anomaly (Both say Anomaly)
        3. Disagreement: Isolation Forest only
        4. Disagreement: One-Class SVM only
        """
        if_anom = if_preds['is_anomaly']
        oc_anom = ocsvm_preds['is_anomaly']
        total = len(if_anom)

        agreements = int(np.sum(if_anom == oc_anom))
        disagreements = total - agreements
        agreement_rate = round((agreements / total) * 100.0, 2)

        consensus_normal = int(np.sum((if_anom == 0) & (oc_anom == 0)))
        consensus_anomaly = int(np.sum((if_anom == 1) & (oc_anom == 1)))
        disagree_if_only = int(np.sum((if_anom == 1) & (oc_anom == 0)))
        disagree_oc_only = int(np.sum((if_anom == 0) & (oc_anom == 1)))

        return {
            'total_events': total,
            'agreements': agreements,
            'disagreements': disagreements,
            'agreement_rate_percent': agreement_rate,
            'consensus_counts': {
                'Consensus Normal (High Confidence Normal)': consensus_normal,
                'Consensus Anomaly (High Confidence Threat)': consensus_anomaly,
                'Disagreement (Flagged by IF Only)': disagree_if_only,
                'Disagreement (Flagged by OCSVM Only)': disagree_oc_only
            }
        }
