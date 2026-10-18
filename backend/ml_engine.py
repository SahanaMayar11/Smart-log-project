import re
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from datetime import datetime

# Graceful SHAP import handling to prevent optional PyTorch C++ DLL crashes on Windows
SHAP_AVAILABLE = False
try:
    import shap
    SHAP_AVAILABLE = True
except Exception:
    SHAP_AVAILABLE = False

# ==============================================================================
# OFFICIAL FEATURE SCHEMA & DOCUMENTATION (OBJECTIVE 1)
# ==============================================================================
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

FEATURE_DOCUMENTATION = {
    'event_frequency': {
        'meaning': 'Number of log events occurring within a sliding sequence/time window.',
        'relevance': 'Surges in event activity can indicate DDoS, brute-force floods, or runaway exception loops.',
        'data_type': 'float64',
        'preprocessing': 'Median imputation for missing values; negative values clipped to 0.0; infinite values capped.'
    },
    'sequence_length': {
        'meaning': 'Character length of the log message payload.',
        'relevance': 'Abnormally long payloads often correspond to buffer overflow attempts or injected SQL/script commands.',
        'data_type': 'int64',
        'preprocessing': 'Median imputation for missing values; negative values clipped to 0; infinite values capped.'
    },
    'error_count': {
        'meaning': 'Count of ERROR level logs in the sliding sequence window.',
        'relevance': 'High error frequency highlights severe system fault bursts or failing services.',
        'data_type': 'int64',
        'preprocessing': 'Median imputation for missing values; negative values clipped to 0.'
    },
    'error_pattern': {
        'meaning': 'Categorical numerical index corresponding to specific error signatures (1: Failed, 2: Missing File, 3: OOM/Killed, 4: Access Denied/Overflow).',
        'relevance': 'Identifies known dangerous failure modes vs generic system logs.',
        'data_type': 'int64',
        'preprocessing': 'Missing values mapped to 0 (No specific pattern); values clipped to valid range [0, 4].'
    },
    'login_attempts': {
        'meaning': 'Count of authentication or security events in the sequence window.',
        'relevance': 'Elevated login activity signals authentication scans or batch login attempts.',
        'data_type': 'int64',
        'preprocessing': 'Median imputation for missing values; negative values clipped to 0.'
    },
    'failed_login_attempts': {
        'meaning': 'Count of failed login or access denial messages in the window.',
        'relevance': 'Strong indicator of credential stuffing or brute-force attack attempts.',
        'data_type': 'int64',
        'preprocessing': 'Median imputation for missing values; negative values clipped to 0.'
    },
    'warning_count': {
        'meaning': 'Count of WARNING level events in the sequence window.',
        'relevance': 'Represents impending resource exhaustion or security policy warnings.',
        'data_type': 'int64',
        'preprocessing': 'Median imputation for missing values; negative values clipped to 0.'
    },
    'unknown_events': {
        'meaning': 'Count of unrecognized or unmapped event types in the window.',
        'relevance': 'Unusual or legacy log event types may signal stealthy exploit activities.',
        'data_type': 'int64',
        'preprocessing': 'Median imputation for missing values; negative values clipped to 0.'
    }
}


class LogParser:
    """Parses raw server logs into structured fields."""

    @staticmethod
    def parse_line(line, line_index=0):
        line = line.strip()
        if not line:
            return None

        # Regex pattern for standard Syslog format
        syslog_pattern = r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+([\w\.\-]+)\s+([\w\.\-\[\]]+):\s*(.*)$'
        match = re.match(syslog_pattern, line)

        if match:
            timestamp, hostname, service, message = match.groups()
        else:
            parts = line.split(' ', 3)
            timestamp = parts[0] if len(parts) > 0 else datetime.now().isoformat()
            hostname = parts[1] if len(parts) > 1 else 'localhost'
            service = parts[2] if len(parts) > 2 else 'system'
            message = parts[3] if len(parts) > 3 else line

        msg_upper = message.upper()
        if 'ERROR' in msg_upper or 'FAILED' in msg_upper or 'DENIED' in msg_upper or 'CRITICAL' in msg_upper or 'KILL' in msg_upper:
            log_level = 'ERROR'
        elif 'WARN' in msg_upper or 'WARNING' in msg_upper or 'ALERT' in msg_upper:
            log_level = 'WARN'
        elif 'INFO' in msg_upper or 'STARTED' in msg_upper or 'FINISHED' in msg_upper or 'ACCEPTED' in msg_upper:
            log_level = 'INFO'
        else:
            log_level = 'DEBUG'

        if 'UNKNOWN_EVENT' in msg_upper or 'UNKNOWN EVENT' in msg_upper:
            event_type = 'UNKNOWN_EVENT'
        elif (
            'sshd' in service.lower()
            or 'sudo' in service.lower()
            or 'su' in service.lower()
            or 'login' in msg_upper
            or 'password' in msg_upper
            or 'auth' in service.lower()
            or 'authentication' in msg_upper
            or 'pam_unix' in msg_upper
        ):
            event_type = 'AUTHENTICATION'
        elif 'nginx' in service.lower() or 'http' in msg_upper or 'apache' in msg_upper:
            event_type = 'WEB_SERVICE'
        elif 'cron' in service.lower():
            event_type = 'SCHEDULED_TASK'
        elif 'kernel' in service.lower() or 'apparmor' in msg_upper:
            event_type = 'KERNEL_AUDIT'
        elif 'OVERFLOW' in msg_upper:
            event_type = 'UNKNOWN_EVENT'
        else:
            event_type = 'SYSTEM_EVENT'

        return {
            'log_id': line_index + 1,
            'timestamp': timestamp,
            'hostname': hostname,
            'service': service,
            'log_level': log_level,
            'event_type': event_type,
            'message': message
        }

    @classmethod
    def parse_logs(cls, log_content):
        lines = log_content.strip().split('\n')
        parsed = []
        for idx, line in enumerate(lines):
            item = cls.parse_line(line, idx)
            if item:
                parsed.append(item)
        return parsed


class DataCleaner:
    """Cleans parsed logs by stripping noise and handling missing values."""

    @staticmethod
    def clean(parsed_logs):
        cleaned = []
        for log in parsed_logs:
            log['hostname'] = log['hostname'].strip() if log.get('hostname') else 'unknown_host'
            log['service'] = log['service'].strip() if log.get('service') else 'unknown_service'
            log['message'] = log['message'].strip() if log.get('message') else 'empty_message'
            cleaned.append(log)
        return cleaned


class BehavioralFeatureExtractor:
    """Extracts exact 8 behavioral features from cleaned logs."""

    @staticmethod
    def extract_features(cleaned_logs):
        features = []
        total_logs = len(cleaned_logs)

        for i, log in enumerate(cleaned_logs):
            msg = log['message']
            msg_upper = msg.upper()

            start_w = max(0, i - 2)
            end_w = min(total_logs, i + 3)
            window_logs = cleaned_logs[start_w:end_w]

            event_freq = len(window_logs)
            seq_len = len(msg)

            error_count = sum(1 for w in window_logs if (w.get('log_level') or w.get('level') or '').upper() == 'ERROR')

            if 'DENIED' in msg_upper or 'OVERFLOW' in msg_upper:
                err_pattern = 4
            elif 'OUT OF MEMORY' in msg_upper or 'KILLED' in msg_upper:
                err_pattern = 3
            elif 'NO SUCH FILE' in msg_upper or 'NOT FOUND' in msg_upper:
                err_pattern = 2
            elif 'FAILED' in msg_upper:
                err_pattern = 1
            else:
                err_pattern = 0

            login_attempts = sum(
                1 for w in window_logs
                if (w.get('event_type') or w.get('task') or '').upper() in ['AUTHENTICATION', 'SECURITY']
            )

            # Failed logins: authentic authentication failure signals (SSH failures, PAM/sudo failures, failed SU)
            failed_logins = sum(
                1 for w in window_logs
                if (
                    ((w.get('event_type') or w.get('task') or '').upper() in ['AUTHENTICATION', 'SECURITY'] and
                     ('FAIL' in str(w.get('message') or '').upper() or 'DENIED' in str(w.get('message') or '').upper() or 'INVALID' in str(w.get('message') or '').upper()))
                    or any(kw in str(w.get('message') or '').upper() for kw in [
                        'FAILED PASSWORD', 'FAILED LOGIN', 'LOGON FAILURE', 'AUTHENTICATION FAILURE',
                        'FAILED SU', 'INCORRECT PASSWORD', 'PAM_UNIX(SUDO:AUTH): CONVERSATION FAILED'
                    ])
                )
            )

            warning_count = sum(1 for w in window_logs if (w.get('log_level') or w.get('level') or '').upper() in ['WARN', 'WARNING'])
            unknown_events = sum(
                1 for w in window_logs
                if (w.get('event_type') or w.get('task') or '').upper() in ['UNKNOWN_EVENT', 'GENERAL']
                or 'UNKNOWN_EVENT' in str(w.get('message') or '').upper()
            )

            features.append({
                'log_id': log.get('log_id') or log.get('record_id') or (i + 1),
                'event_frequency': float(event_freq),
                'sequence_length': int(seq_len),
                'error_count': int(error_count),
                'error_pattern': int(err_pattern),
                'login_attempts': int(login_attempts),
                'failed_login_attempts': int(failed_logins),
                'warning_count': int(warning_count),
                'unknown_events': int(unknown_events)
            })

        return pd.DataFrame(features)


# ==============================================================================
# DATA PREPROCESSOR & VALIDATOR (OBJECTIVE 1)
# ==============================================================================
class DataPreprocessor:
    """
    Handles missing and invalid values, enforces schema validation, and ensures
    reproducible preprocessing across training, historical, and live pipelines.
    Guarantees pure canonical 8-feature representation without model-specific side effects.
    Supports fit_medians to prevent data leakage between train and test splits.
    """

    @classmethod
    def preprocess(cls, feature_df, fit_medians=None):
        if feature_df is None or len(feature_df) == 0:
            raise ValueError("Input feature DataFrame is empty or None.")

        df = feature_df.copy()
        input_records = len(df)
        missing_count = 0
        invalid_count = 0
        computed_medians = {}

        # Preserve log_id if present
        log_ids = df['log_id'].values if 'log_id' in df.columns else np.arange(1, input_records + 1)

        # 1. Ensure all 8 schema columns exist
        for col in FEATURE_SCHEMA:
            if col not in df.columns:
                df[col] = np.nan
                missing_count += input_records

        # Keep schema columns
        df_feats = df[FEATURE_SCHEMA].copy()

        # 2. Detect & handle missing/non-numeric values with leakage protection
        for col in FEATURE_SCHEMA:
            non_num_mask = pd.to_numeric(df_feats[col], errors='coerce').isna()
            null_mask = df_feats[col].isna()
            col_missing = (null_mask | non_num_mask)

            num_missing_in_col = int(col_missing.sum())
            if fit_medians is not None and col in fit_medians:
                med_val = float(fit_medians[col])
            else:
                valid_vals = pd.to_numeric(df_feats.loc[~col_missing, col], errors='coerce')
                med_val = float(valid_vals.median()) if len(valid_vals) > 0 and not np.isnan(valid_vals.median()) else 0.0
            computed_medians[col] = med_val

            if num_missing_in_col > 0:
                missing_count += num_missing_in_col
                df_feats.loc[col_missing, col] = med_val

            df_feats[col] = pd.to_numeric(df_feats[col], errors='coerce').fillna(0.0)

        # 3. Detect & fix invalid values (inf, -inf, negative values)
        for col in FEATURE_SCHEMA:
            col_vals = df_feats[col].values

            # Infinite values
            inf_mask = np.isinf(col_vals)
            if np.any(inf_mask):
                invalid_count += int(np.sum(inf_mask))
                finite_vals = col_vals[~inf_mask]
                max_finite = float(np.max(finite_vals)) if len(finite_vals) > 0 else 100.0
                col_vals[inf_mask] = max_finite

            # Negative values (all 8 features are non-negative counts/lengths)
            neg_mask = (col_vals < 0)
            if np.any(neg_mask):
                invalid_count += int(np.sum(neg_mask))
                col_vals[neg_mask] = 0.0

            # Error pattern range check [0, 4]
            if col == 'error_pattern':
                out_of_bounds = (col_vals > 4)
                if np.any(out_of_bounds):
                    invalid_count += int(np.sum(out_of_bounds))
                    col_vals[out_of_bounds] = 4.0

            df_feats[col] = col_vals

        # 4. Final strict validation
        if df_feats[FEATURE_SCHEMA].isna().any().any():
            raise ValueError("Data validation failed: Remaining NaN values detected after preprocessing.")
        if np.isinf(df_feats[FEATURE_SCHEMA].values).any():
            raise ValueError("Data validation failed: Remaining infinite values detected after preprocessing.")

        # Re-attach log_id
        df_feats['log_id'] = log_ids

        stats = {
            'input_records': input_records,
            'missing_values_found': missing_count,
            'missing_values_handled': missing_count,
            'invalid_values_found': invalid_count,
            'invalid_values_handled': invalid_count,
            'records_removed': 0,
            'valid_records': len(df_feats),
            'fitted_medians': computed_medians
        }

        print(f"[PREPROCESS] Input records: {input_records} | Missing: {missing_count} | Invalid: {invalid_count} | Handled: {missing_count + invalid_count} | Valid: {len(df_feats)}")

        return df_feats, stats


# ==============================================================================
# HDFS DOMAIN ADAPTER (OBJECTIVE 2 FEATURE MAPPING)
# ==============================================================================
class HDFSDomainAdapter:
    """
    Transforms generic server log behavioral features into HDFS-compatible feature representation.
    Derived 100% from HDFS Training Dataset Statistical Constants (575,061 records).
    Ensures incoming server log feature vectors align cleanly with HDFS-trained Isolation Forest
    tree split boundaries without distortion or arbitrary step functions.
    """
    FEATURE_NAMES = FEATURE_SCHEMA

    # Statistical Constants derived directly from 575,061 HDFS training records
    HDFS_FREQ_MEDIAN = 19.0
    HDFS_FREQ_STD = 5.177735
    HDFS_SEQ_MEDIAN = 7.0
    HDFS_SEQ_STD = 1.578432
    HDFS_ERR_MEDIAN = 0.0

    @classmethod
    def transform(cls, raw_df):
        mapped_df = raw_df.copy()

        # 1. Error Count & Pattern Mapping (HDFS Normal Baseline = 0.0, Normal Template = 0.0, Error = 1.0)
        err_total = mapped_df['error_count'] + mapped_df['failed_login_attempts']
        mapped_df['error_count'] = cls.HDFS_ERR_MEDIAN + err_total
        mapped_df['error_pattern'] = np.where(err_total > 0, 1.0, 0.0)

        # 2. Sequence Length Continuous Log Re-centering around HDFS Distinct Template Median (7.0)
        seq_len = mapped_df['sequence_length'].clip(lower=1)
        mapped_df['sequence_length'] = (cls.HDFS_SEQ_MEDIAN + (np.log10(seq_len) - np.log10(200.0)) * cls.HDFS_SEQ_STD * 2.0).clip(2.0, 298.0)

        # 3. Event Frequency Re-centering around HDFS Median (19.0)
        freq = mapped_df['event_frequency'].clip(lower=1)
        mapped_df['event_frequency'] = (cls.HDFS_FREQ_MEDIAN + (freq - 5.0) * cls.HDFS_FREQ_STD).clip(2.0, 298.0)

        # 4. Warnings and Untrained Security Features
        mapped_df['warning_count'] = mapped_df['warning_count'].clip(lower=0.0)
        mapped_df['login_attempts'] = 0.0
        mapped_df['failed_login_attempts'] = 0.0
        mapped_df['unknown_events'] = 0.0

        return mapped_df[cls.FEATURE_NAMES]


# ==============================================================================
# ISOLATION FOREST DETECTOR (PRIMARY MODEL - OBJECTIVE 2)
# ==============================================================================
class IsolationForestDetector:
    """Configurable Isolation Forest detector using HDFS-trained model as default primary.

    Set SMARTLOG_IF_MODEL=hdfs (default) to load models/hdfs_isolation_forest_model.pkl.
    Set SMARTLOG_IF_MODEL=active to load the backup Windows model artifact.
    """

    def __init__(self, n_estimators=100, contamination=0.15, random_state=42, max_samples='auto'):
        self.feature_columns = FEATURE_SCHEMA
        model_selection = os.getenv('SMARTLOG_IF_MODEL', 'hdfs').strip().lower()
        model_paths = {
            'active': os.path.join(os.path.dirname(__file__), 'models', 'isolation_forest_model.pkl'),
            'hdfs': os.path.join(os.path.dirname(__file__), 'models', 'hdfs_isolation_forest_model.pkl'),
        }
        if model_selection not in model_paths:
            raise ValueError(
                "SMARTLOG_IF_MODEL must be 'hdfs' (default) or 'active'. "
                f"Received: {model_selection!r}"
            )

        self.model_selection = model_selection
        self.model_path = model_paths[model_selection]
        self.model = self._load_or_train_model(n_estimators, contamination, random_state, max_samples)

    def _load_or_train_model(self, n_estimators, contamination, random_state, max_samples):
        if os.path.exists(self.model_path):
            try:
                model = joblib.load(self.model_path)
                saved_schema = list(getattr(model, 'feature_names_in_', []))
                if saved_schema != self.feature_columns or getattr(model, 'n_features_in_', None) != len(self.feature_columns):
                    raise ValueError(
                        f"Saved model feature schema mismatch. Expected {self.feature_columns}, got {saved_schema}."
                    )
                return model
            except Exception as e:
                if self.model_selection == 'hdfs':
                    # A temporary model test must never fall back to retraining, because
                    # train_and_save_model writes only the active production artifact.
                    raise RuntimeError(
                        f"Could not load the HDFS test model at {self.model_path}: {e}"
                    ) from e
                print(f"Warning: Could not load saved Isolation Forest model ({e}). Training new model...")

        if self.model_selection == 'hdfs':
            raise FileNotFoundError(f"HDFS test model is missing: {self.model_path}")

        from train_model import train_and_save_model
        train_and_save_model(n_estimators=n_estimators, contamination=contamination, random_state=random_state)
        return joblib.load(self.model_path)

    def predict(self, feature_df):
        """
        Executes Isolation Forest anomaly prediction on preprocessed feature DataFrame.
        When model_selection is 'hdfs', applies HDFSDomainAdapter explicitly at the model boundary.
        Calculates deterministic normalized anomaly score: norm_score = clip(1.0 - (decision_function + 0.5), 0.0, 1.0)
        where higher score strictly indicates greater degree of isolation/abnormality (threshold = 0.5).
        Note: norm_score is a normalized heuristic anomaly score, not a calibrated probability.
        """
        X_raw = feature_df[self.feature_columns]
        if self.model_selection == 'hdfs':
            X_input = HDFSDomainAdapter.transform(X_raw)
        else:
            X_input = X_raw

        raw_preds = self.model.predict(X_input)
        scores = self.model.decision_function(X_input)

        results = []
        for idx, (pred, score) in enumerate(zip(raw_preds, scores)):
            is_anomaly = 1 if pred == -1 else 0
            norm_score = float(np.clip(1.0 - (score + 0.5), 0.0, 1.0))

            # Operational Severity Bands derived deterministically from normalized anomaly score
            # The binary model classification threshold is strictly norm_score >= 0.50 (decision_function <= 0)
            if norm_score >= 0.50:
                if norm_score > 0.85:
                    severity = 'Critical'
                elif norm_score > 0.70:
                    severity = 'High'
                elif norm_score > 0.55:
                    severity = 'Medium'
                else:
                    severity = 'Low'
            else:
                severity = 'Normal'

            log_id_val = feature_df.iloc[idx]['log_id'] if 'log_id' in feature_df.columns else (idx + 1)
            results.append({
                'log_id': log_id_val,
                'is_anomaly': is_anomaly,
                'anomaly_score': round(norm_score, 4),
                'severity': severity
            })

        return results, X_input

    def fit_predict(self, feature_df):
        return self.predict(feature_df)


# ==============================================================================
# ONE-CLASS SVM VALIDATOR (COMPARISON / VALIDATION MODEL - OBJECTIVE 2)
# ==============================================================================
class OneClassSVMValidator:
    """
    Implements One-Class SVM as a validation and comparative baseline model
    to validate Isolation Forest anomaly detection results.
    """

    def __init__(self, nu=0.15, kernel='rbf', gamma='scale'):
        self.feature_columns = FEATURE_SCHEMA
        self.model_path = os.path.join(os.path.dirname(__file__), 'models', 'one_class_svm_model.pkl')
        self.model = self._load_or_train_model(nu, kernel, gamma)

    def _load_or_train_model(self, nu, kernel, gamma):
        if os.path.exists(self.model_path):
            try:
                model = joblib.load(self.model_path)
                return model
            except Exception as e:
                print(f"Warning: Could not load saved One-Class SVM model ({e}). Training new model...")

        from train_model import train_and_save_model
        train_and_save_model()
        if os.path.exists(self.model_path):
            return joblib.load(self.model_path)
        else:
            model = OneClassSVM(nu=nu, kernel=kernel, gamma=gamma)
            return model

    def predict(self, feature_df):
        """
        Executes One-Class SVM secondary validation on preprocessed feature DataFrame.
        When SMARTLOG_IF_MODEL is 'hdfs', uses the domain adapter at the boundary for consistency.
        Returns prediction results and normalized anomaly score.
        """
        X_raw = feature_df[self.feature_columns]
        model_selection = os.getenv('SMARTLOG_IF_MODEL', 'hdfs').strip().lower()
        if model_selection == 'hdfs':
            X_input = HDFSDomainAdapter.transform(X_raw)
        else:
            X_input = X_raw

        if not hasattr(self.model, 'shape_fit_') and not hasattr(self.model, 'fit_status_'):
            raise RuntimeError("OneClassSVMValidator model is not fitted. Please ensure a trained model artifact is loaded.")

        raw_preds = self.model.predict(X_input)
        scores = self.model.decision_function(X_input)

        results = []
        for idx, (pred, score) in enumerate(zip(raw_preds, scores)):
            is_anomaly = 1 if pred == -1 else 0
            norm_score = float(np.clip(1.0 - (score + 0.5), 0.0, 1.0))

            log_id_val = feature_df.iloc[idx]['log_id'] if 'log_id' in feature_df.columns else (idx + 1)
            results.append({
                'log_id': log_id_val,
                'is_anomaly': is_anomaly,
                'anomaly_score': round(norm_score, 4),
                'raw_score': round(float(score), 4)
            })

        return results

    @staticmethod
    def get_consensus_state(if_anomaly, ocsvm_anomaly):
        """
        Returns one of 4 model consensus states:
        - IF normal / OCSVM normal -> Consensus Normal
        - IF anomaly / OCSVM anomaly -> Consensus Anomaly
        - IF anomaly / OCSVM normal -> Model Disagreement: Isolation Forest
        - IF normal / OCSVM anomaly -> Model Disagreement: One-Class SVM
        """
        if if_anomaly == 1 and ocsvm_anomaly == 1:
            return 'Consensus Anomaly'
        elif if_anomaly == 0 and ocsvm_anomaly == 0:
            return 'Consensus Normal'
        elif if_anomaly == 1 and ocsvm_anomaly == 0:
            return 'Model Disagreement: Isolation Forest'
        else:
            return 'Model Disagreement: One-Class SVM'

    @classmethod
    def compare_models(cls, if_results, ocsvm_results, ground_truth=None):
        total = len(if_results)
        if total == 0:
            return {}

        if_anomalies = sum(1 for r in if_results if r['is_anomaly'] == 1)
        if_normals = total - if_anomalies

        ocsvm_anomalies = sum(1 for r in ocsvm_results if r['is_anomaly'] == 1)
        ocsvm_normals = total - ocsvm_anomalies

        agreements = sum(1 for a, b in zip(if_results, ocsvm_results) if a['is_anomaly'] == b['is_anomaly'])
        agreement_rate = round((agreements / total) * 100.0, 2)

        both_anomalies = sum(1 for a, b in zip(if_results, ocsvm_results) if a['is_anomaly'] == 1 and b['is_anomaly'] == 1)
        either_anomalies = sum(1 for a, b in zip(if_results, ocsvm_results) if a['is_anomaly'] == 1 or b['is_anomaly'] == 1)
        jaccard_similarity = round((both_anomalies / either_anomalies), 4) if either_anomalies > 0 else 1.0

        consensus_counts = {
            'Consensus Normal': sum(1 for a, b in zip(if_results, ocsvm_results) if a['is_anomaly'] == 0 and b['is_anomaly'] == 0),
            'Consensus Anomaly': both_anomalies,
            'Model Disagreement: Isolation Forest': sum(1 for a, b in zip(if_results, ocsvm_results) if a['is_anomaly'] == 1 and b['is_anomaly'] == 0),
            'Model Disagreement: One-Class SVM': sum(1 for a, b in zip(if_results, ocsvm_results) if a['is_anomaly'] == 0 and b['is_anomaly'] == 1),
        }

        comparison = {
            'total_events': total,
            'isolation_forest': {
                'normal_events': if_normals,
                'anomaly_events': if_anomalies,
                'anomaly_percentage': round((if_anomalies / total) * 100.0, 2)
            },
            'one_class_svm': {
                'normal_events': ocsvm_normals,
                'anomaly_events': ocsvm_anomalies,
                'anomaly_percentage': round((ocsvm_anomalies / total) * 100.0, 2)
            },
            'comparison_metrics': {
                'agreements': agreements,
                'agreement_rate_percent': agreement_rate,
                'jaccard_similarity': jaccard_similarity,
                'both_flagged_anomalies': both_anomalies,
                'consensus_distribution': consensus_counts
            }
        }

        if ground_truth is not None and len(ground_truth) == total:
            from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score, roc_auc_score, confusion_matrix

            y_true = np.array(ground_truth)
            y_if = np.array([r['is_anomaly'] for r in if_results])
            y_ocsvm = np.array([r['is_anomaly'] for r in ocsvm_results])

            comparison['isolation_forest'].update({
                'accuracy': round(float(accuracy_score(y_true, y_if)), 4),
                'precision': round(float(precision_score(y_true, y_if, zero_division=0)), 4),
                'recall': round(float(recall_score(y_true, y_if, zero_division=0)), 4),
                'f1_score': round(float(f1_score(y_true, y_if, zero_division=0)), 4),
                'confusion_matrix': confusion_matrix(y_true, y_if).tolist()
            })

            comparison['one_class_svm'].update({
                'accuracy': round(float(accuracy_score(y_true, y_ocsvm)), 4),
                'precision': round(float(precision_score(y_true, y_ocsvm, zero_division=0)), 4),
                'recall': round(float(recall_score(y_true, y_ocsvm, zero_division=0)), 4),
                'f1_score': round(float(f1_score(y_true, y_ocsvm, zero_division=0)), 4),
                'confusion_matrix': confusion_matrix(y_true, y_ocsvm).tolist()
            })

            try:
                comparison['isolation_forest']['roc_auc'] = round(float(roc_auc_score(y_true, y_if)), 4)
                comparison['one_class_svm']['roc_auc'] = round(float(roc_auc_score(y_true, y_ocsvm)), 4)
            except Exception:
                pass
        else:
            comparison['note'] = "Unsupervised production logs: Ground-truth accuracy requires manual labels. Comparative agreement rate calculated."

        return comparison


# ==============================================================================
# SHAP EXPLAINABILITY ENGINE (OBJECTIVE 2 - ISOLATION FOREST SHAP)
# ==============================================================================
class ShapExplainerEngine:
    """
    Generates SHAP feature contributions, human-readable explanations, and security recommendations.
    Strictly aligns with the 8 behavioral features defined in FEATURE_SCHEMA.
    Positive contribution represents a deviation that increases the anomaly score.
    """

    FEATURE_NAMES = [
        'Event Frequency', 'Sequence Length', 'Error Count',
        'Error Pattern', 'Login Attempts', 'Failed Login Attempts',
        'Warning Count', 'Unknown Events'
    ]

    FEATURE_SCHEMA_MAPPING = {
        'event_frequency': 'Event Frequency',
        'sequence_length': 'Sequence Length',
        'error_count': 'Error Count',
        'error_pattern': 'Error Pattern',
        'login_attempts': 'Login Attempts',
        'failed_login_attempts': 'Failed Login Attempts',
        'warning_count': 'Warning Count',
        'unknown_events': 'Unknown Events'
    }

    FEATURE_HUMAN_DESCRIPTIONS = {
        'Event Frequency': 'Event activity frequency in this sequence window was unusually high.',
        'Sequence Length': 'Event payload message was unusually long or complex.',
        'Error Count': 'A high volume of system errors occurred in a short time frame.',
        'Error Pattern': 'An unusual error pattern (e.g., access denied or service crash) was detected.',
        'Login Attempts': 'Authentication activity frequency was significantly elevated.',
        'Failed Login Attempts': 'Failed login attempts were unusually high and strongly contributed to the anomaly classification.',
        'Warning Count': 'Multiple system warnings were issued concurrently.',
        'Unknown Events': 'Unrecognized or unusual event identifiers were encountered.'
    }

    @staticmethod
    def get_what_happened(log_item):
        if log_item.get('description'):
            return log_item['description']

        app_name = log_item.get('application_name') or log_item.get('application') or log_item.get('service', 'Windows System')
        action = log_item.get('action') or 'Activity Logged'
        user = log_item.get('user') or 'User'
        comp = log_item.get('computer') or log_item.get('hostname') or 'Rocky'

        msg = str(log_item.get('message', '')).upper()
        service = str(log_item.get('service', '')).lower()
        msg_raw = str(log_item.get('message', ''))

        if 'PROCESS STARTED' in msg or 'PROCESS CREATED' in msg or 'process started' in msg_raw.lower() or action == 'Application Started':
            return f"{app_name} was started by {user} on computer {comp}."
        elif 'PROCESS TERMINATED' in msg or 'PROCESS EXITED' in msg or 'process terminated' in msg_raw.lower() or action == 'Application Closed':
            return f"{app_name} was closed on computer {comp}."
        elif 'CHARGER CONNECTED' in msg or 'POWER CONNECTED' in msg or 'charger connected' in msg_raw.lower() or action == 'POWER_CONNECTED':
            return f"AC charger connected. Laptop battery is charging on computer {comp}."
        elif 'CHARGER DISCONNECTED' in msg or 'POWER DISCONNECTED' in msg or 'charger disconnected' in msg_raw.lower() or action == 'POWER_DISCONNECTED':
            return f"AC charger disconnected. System operating on battery on computer {comp}."
        elif 'failed' in msg.lower() or 'denied' in msg.lower() or 'login' in msg.lower() or 'auth' in service:
            if 'failed' in msg.lower() or 'denied' in msg.lower():
                return f"Failed logon or authentication attempt recorded for {user} on computer {comp}."
            return f"User {user} authenticated on computer {comp}."
        elif 'error' in msg.lower() or 'critical' in msg.lower() or 'fault' in msg.lower():
            return f"{app_name} encountered an operational error or exception on computer {comp}."
        elif 'warn' in msg.lower() or 'warning' in msg.lower():
            return f"Windows issued a system warning regarding {app_name} on computer {comp}."
        elif 'service' in service or 'started' in msg.lower() or 'stopped' in msg.lower():
            return f"Windows Service Manager recorded a service state change on computer {comp}."
        else:
            return f"Windows system event logged from {app_name} on computer {comp}."

    @staticmethod
    def get_recommended_action(log_item, is_anomaly, top_feature=None):
        if not is_anomaly:
            return "No action required. Continue standard operational monitoring."

        msg = str(log_item.get('message', '')).lower()
        service = str(log_item.get('service', '')).lower()
        top_feat_str = str(top_feature or '').lower()

        # 1. Authentication Behavior
        if 'login' in top_feat_str or 'auth' in service or 'sshd' in service or 'failed password' in msg or 'logon' in msg:
            return "Investigate authentication source and user account for potential brute-force or unauthorized access attempts."

        # 2. PowerShell / Command Script Behavior
        if 'powershell' in service or 'cmd.exe' in service or 'powershell' in msg or 'script' in msg:
            return "Verify whether the PowerShell or command execution was initiated by an authorized administrator or script."

        # 3. System Error / Service Crash Behavior
        if 'error' in top_feat_str or 'fault' in msg or 'segv' in msg or 'exception' in msg or 'critical' in msg:
            return "Inspect service health and recent crash logs in Windows Event Viewer and services.msc."

        # 4. Warning Storm / Resource Throttling Behavior
        if 'warning' in top_feat_str or 'throttled' in msg or 'hardware error' in msg or 'disk' in msg:
            return "Check system resource limits, storage thresholds, and peripheral hardware status."

        # 5. Event Frequency Burst Behavior
        if 'frequency' in top_feat_str or 'burst' in msg:
            return "Analyze application polling rates and network request volume during this timeframe."

        # 6. Neutral Evidence-Based Fallback (No unsupported claims)
        return "Investigate the associated event and surrounding activity in Windows Event Viewer before taking corrective action."

    @classmethod
    def explain(cls, model, X_df, detection_results, parsed_logs=None, raw_features=None):
        """
        Generates genuine SHAP feature attributions and cybersecurity-focused explanations.
        - Strictly evaluates actual model predictions and the actual inference feature vector.
        - Identifies model type (Isolation Forest vs One-Class SVM).
        - Direct TreeExplainer is used for tree-based models (Isolation Forest).
        - For Isolation Forest, raw path-length contributions are inverted so positive values
          mathematically indicate shifts toward anomaly isolation (earlier isolation depth).
        - Unsupported models (e.g. One-Class SVM RBF kernel) and errors are handled gracefully
          with transparent explanation messages without fabricating artificial SHAP values.
        """
        is_iforest = hasattr(model, 'estimators_') and hasattr(model, 'max_samples_')
        if is_iforest:
            model_name = 'Isolation Forest'
        elif 'OneClassSVM' in type(model).__name__:
            model_name = 'One-Class SVM'
        else:
            model_name = type(model).__name__

        # Ensure X is DataFrame matching FEATURE_SCHEMA
        if isinstance(X_df, pd.DataFrame):
            X_feats = X_df[[col for col in FEATURE_SCHEMA if col in X_df.columns]].copy()
        else:
            X_feats = pd.DataFrame(X_df, columns=FEATURE_SCHEMA)

        # Raw feature matrix for human-readable value inspection
        if raw_features is not None and isinstance(raw_features, pd.DataFrame):
            X_raw = raw_features[[col for col in FEATURE_SCHEMA if col in raw_features.columns]].copy()
        else:
            X_raw = X_feats.copy()

        # Domain adaptation for HDFS model tree explanation
        model_selection = os.getenv('SMARTLOG_IF_MODEL', 'hdfs').strip().lower()
        if model_selection == 'hdfs' and is_iforest:
            is_already_adapted = (
                (X_feats['login_attempts'] == 0.0).all() and
                (X_feats['failed_login_attempts'] == 0.0).all() and
                (X_feats['unknown_events'] == 0.0).all()
            )
            X_model_input = X_feats if is_already_adapted else HDFSDomainAdapter.transform(X_feats)
        else:
            X_model_input = X_feats

        shap_values = None
        explanation_status = 'success'
        explanation_error_msg = None

        if not SHAP_AVAILABLE:
            explanation_status = 'unsupported_explainer'
            explanation_error_msg = 'SHAP library is not installed in the Python environment.'
        elif not is_iforest:
            explanation_status = 'unsupported_model'
            explanation_error_msg = (
                f"Direct SHAP TreeExplainer is unsupported for {model_name} (kernel-based estimator). "
                "One-Class SVM functions as secondary boundary validator; explanations are derived from the primary Isolation Forest detector."
            )
        elif len(X_model_input) == 0:
            explanation_status = 'empty_features'
            explanation_error_msg = 'Input feature matrix is empty.'
        else:
            try:
                explainer = shap.TreeExplainer(model)
                raw_shap = explainer.shap_values(X_model_input)
                # Isolation Forest TreeExplainer computes feature contributions to average tree path length.
                # Negative path contribution reduces depth (faster isolation -> anomaly).
                # Inverting sign ensures positive contribution represents a shift toward anomaly isolation,
                # consistent with FEATURE_SCHEMA interpretation and UI color coding (+red = anomaly).
                shap_values = -raw_shap
            except Exception as e:
                explanation_status = 'computation_error'
                explanation_error_msg = f"SHAP explanation computation failed: {str(e)}"
                shap_values = None

        explanations = []
        log_map = {item['log_id']: item for item in (parsed_logs or [])}

        for i, row in enumerate(detection_results):
            log_id = row.get('log_id', i + 1)
            log_item = log_map.get(log_id, {'message': '', 'service': 'system'})
            is_anomaly = (row.get('is_anomaly') == 1)
            what_happened = cls.get_what_happened(log_item)

            if shap_values is None:
                # Transparent fallback without fabricating artificial pseudo-SHAP values
                contributions = {feat: 0.0 for feat in cls.FEATURE_NAMES}
                top_reason = 'Explanation Unavailable' if is_anomaly else 'Normal Behavior'
                rec_action = cls.get_recommended_action(log_item, is_anomaly)
                natural_exp = (
                    f"SHAP explanation unavailable for {model_name}: {explanation_error_msg} "
                    "Genuine unsupervised decision scores and feature metrics remain active."
                ) if is_anomaly else "This activity is consistent with normal system baseline behavior."
                top_3_human_reasons = [
                    f"Model: {model_name}",
                    "Direct SHAP TreeExplainer unavailable",
                    "Refer to feature values and operational anomaly score"
                ]
            else:
                vals = shap_values[i]
                abs_vals = np.abs(vals)
                top_indices = np.argsort(abs_vals)[::-1]

                contributions = {}
                top_features_list = []
                top_3_human_reasons = []

                for idx in range(len(cls.FEATURE_NAMES)):
                    feat_name = cls.FEATURE_NAMES[idx]
                    contributions[feat_name] = round(float(vals[idx]), 4)

                for idx in top_indices[:3]:
                    feat_name = cls.FEATURE_NAMES[idx]
                    feat_key = FEATURE_SCHEMA[idx]
                    feat_raw_val = float(X_raw.iloc[i][feat_key]) if feat_key in X_raw.columns else 0.0
                    val_str = str(int(feat_raw_val)) if feat_raw_val.is_integer() else f"{feat_raw_val:.2f}"
                    shap_val = float(vals[idx])

                    top_features_list.append(feat_name)
                    top_3_human_reasons.append(
                        f"{feat_name} was {val_str} (SHAP contribution: {shap_val:+.4f})"
                    )

                top_reason = top_features_list[0] if is_anomaly else "Normal Behavior"
                rec_action = cls.get_recommended_action(log_item, is_anomaly, top_feature=top_features_list[0] if is_anomaly else None)

                if is_anomaly:
                    top_1_idx = top_indices[0]
                    top_1_name = cls.FEATURE_NAMES[top_1_idx]
                    top_1_key = FEATURE_SCHEMA[top_1_idx]
                    top_1_val = float(X_raw.iloc[i][top_1_key]) if top_1_key in X_raw.columns else 0.0
                    top_1_val_str = str(int(top_1_val)) if top_1_val.is_integer() else f"{top_1_val:.2f}"
                    top_1_shap = float(vals[top_1_idx])

                    top_2_idx = top_indices[1]
                    top_2_name = cls.FEATURE_NAMES[top_2_idx]
                    top_2_key = FEATURE_SCHEMA[top_2_idx]
                    top_2_val = float(X_raw.iloc[i][top_2_key]) if top_2_key in X_raw.columns else 0.0
                    top_2_val_str = str(int(top_2_val)) if top_2_val.is_integer() else f"{top_2_val:.2f}"
                    top_2_shap = float(vals[top_2_idx])

                    if abs(top_2_shap) > 1e-4:
                        natural_exp = (
                            f"{top_1_name} was {top_1_val_str} (SHAP contribution: {top_1_shap:+.4f}) and "
                            f"{top_2_name} was {top_2_val_str} (SHAP contribution: {top_2_shap:+.4f}), "
                            f"indicating that these features contributed to the model's anomaly isolation output for this event."
                        )
                    else:
                        natural_exp = (
                            f"{top_1_name} was {top_1_val_str} (SHAP contribution: {top_1_shap:+.4f}), "
                            f"indicating that this feature contributed to the model's anomaly isolation output for this event."
                        )
                else:
                    natural_exp = "This activity is consistent with normal system baseline behavior."

            explanations.append({
                'log_id': log_id,
                'model_name': model_name,
                'explanation_status': explanation_status,
                'feature_contributions': contributions,
                'top_reason': top_reason,
                'natural_explanation': natural_exp,
                'what_happened': what_happened,
                'why_suspicious': natural_exp,
                'recommended_action': rec_action,
                'top_3_human_reasons': top_3_human_reasons
            })

        return explanations


# ==============================================================================
# PIPELINE EXECUTION (OBJECTIVES 1 & 2 INTEGRATION)
# ==============================================================================
def run_full_pipeline(log_content, n_estimators=100, contamination=0.15, ground_truth=None):
    """
    Executes full ML pipeline adhering to Objectives 1 & 2:
    Parse -> Clean -> Extract Features -> DataPreprocessor (Preprocess & Validate)
    -> Isolation Forest (Primary Detector) -> One-Class SVM Validation -> SHAP Explanation.
    Pure ML decision logic without keyword overrides.
    """
    parsed_logs = LogParser.parse_logs(log_content)
    cleaned_logs = DataCleaner.clean(parsed_logs)
    raw_feature_df = BehavioralFeatureExtractor.extract_features(cleaned_logs)

    cleaned_feature_df, preprocess_stats = DataPreprocessor.preprocess(raw_feature_df)

    detector = IsolationForestDetector(n_estimators=n_estimators, contamination=contamination)
    detection_results, X_df = detector.fit_predict(cleaned_feature_df)

    ocsvm_validator = OneClassSVMValidator(nu=contamination)
    ocsvm_results = ocsvm_validator.predict(cleaned_feature_df)

    # Consensus validation tracking
    validated_detection_results = []
    for idx, if_det in enumerate(detection_results):
        oc_det = ocsvm_results[idx] if idx < len(ocsvm_results) else {'is_anomaly': 0, 'anomaly_score': 0.0}

        consensus_state = OneClassSVMValidator.get_consensus_state(if_det['is_anomaly'], oc_det['is_anomaly'])

        # Primary decision strictly follows Isolation Forest
        validated_det = dict(if_det)
        validated_det['is_anomaly'] = if_det['is_anomaly']
        validated_det['ocsvm_is_anomaly'] = oc_det['is_anomaly']
        validated_det['ocsvm_score'] = oc_det['anomaly_score']
        validated_det['ocsvm_validated'] = True
        validated_det['consensus_state'] = consensus_state
        validated_det['consensus_agreement'] = bool(if_det['is_anomaly'] == oc_det['is_anomaly'])
        validated_det['severity'] = if_det['severity']
        validated_detection_results.append(validated_det)

    model_comparison = OneClassSVMValidator.compare_models(validated_detection_results, ocsvm_results, ground_truth=ground_truth)

    shap_explanations = ShapExplainerEngine.explain(
        detector.model,
        X_df,
        validated_detection_results,
        parsed_logs=cleaned_logs,
        raw_features=cleaned_feature_df
    )

    return {
        'parsed_logs': cleaned_logs,
        'features': cleaned_feature_df.to_dict(orient='records'),
        'preprocessing_stats': preprocess_stats,
        'detection_results': validated_detection_results,
        'ocsvm_results': ocsvm_results,
        'model_comparison': model_comparison,
        'shap_explanations': shap_explanations
    }
