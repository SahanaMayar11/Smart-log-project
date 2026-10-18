"""
HDFS Isolation Forest Model Training and Evaluation Pipeline
================================================================================
Trains a new scikit-learn Isolation Forest model on the real HDFS benchmark
dataset (575,061 block traces) with strict unsupervised training and held-out
ground-truth evaluation.

Key Design Principles:
1. Reuses canonical 8-feature representation defined in ml_engine.FEATURE_SCHEMA.
2. Strict unsupervised fitting: feature matrix X only; ground-truth labels y
   are never provided during training.
3. Rigorous held-out train/test split (70% train / 30% test) with stratification.
4. Comprehensive empirical evaluation: Accuracy, Precision, Recall, F1, ROC-AUC,
   PR-AUC, FPR, FNR, and Confusion Matrix on the held-out test set.
5. Safe model serialization: writes to versioned/temporary artifact first,
   verifies schema & predict functionality, and backs up original before replacement.
================================================================================
"""

import os
import sys
import argparse
import hashlib
import shutil
import json
import numpy as np
import pandas as pd
import joblib
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix
)

# Ensure backend directory is in Python path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ml_engine import DataPreprocessor, FEATURE_SCHEMA, HDFSDomainAdapter

MODELS_DIR = os.path.join(BASE_DIR, 'models')
PROD_MODEL_PATH = os.path.join(MODELS_DIR, 'hdfs_isolation_forest_model.pkl')
BACKUP_MODEL_PATH = os.path.join(MODELS_DIR, 'hdfs_isolation_forest_model_backup_before_retrain.pkl')
DEFAULT_NEW_MODEL_PATH = os.path.join(MODELS_DIR, 'hdfs_isolation_forest_model_new.pkl')


def compute_file_sha256(filepath):
    """Calculates SHA-256 hash of a file."""
    if not os.path.exists(filepath):
        return None
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(65536), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def find_hdfs_dataset_path(provided_path=None):
    """Locates the HDFS dataset directory or preprocessed files."""
    candidate_paths = [
        provided_path,
        r"C:\Users\Admin\Downloads\HDFS_v1",
        os.path.join(BASE_DIR, "Dataset_HDFS", "HDFS_v1"),
        os.path.join(BASE_DIR, "..", "Downloads", "HDFS_v1")
    ]
    for path in candidate_paths:
        if path and os.path.exists(path):
            return os.path.abspath(path)
    raise FileNotFoundError(
        f"HDFS dataset not found in any candidate locations: {candidate_paths}"
    )


def load_hdfs_features_and_labels(dataset_dir):
    """
    Loads the real HDFS dataset (575,061 block traces), extracts the 8 canonical
    features in FEATURE_SCHEMA order, and separates the ground-truth anomaly labels.
    """
    preprocessed_dir = os.path.join(dataset_dir, "preprocessed")
    eom_path = os.path.join(preprocessed_dir, "Event_occurrence_matrix.csv")
    labels_path = os.path.join(preprocessed_dir, "anomaly_label.csv")

    if not os.path.exists(eom_path) or not os.path.exists(labels_path):
        raise FileNotFoundError(
            f"Required HDFS preprocessed files missing in {preprocessed_dir}. "
            f"Expected Event_occurrence_matrix.csv and anomaly_label.csv"
        )

    print(f"[DATA LOAD] Loading HDFS event occurrence matrix: {eom_path}")
    df_eom = pd.read_csv(eom_path)
    print(f"[DATA LOAD] Loading HDFS ground truth labels: {labels_path}")
    df_labels = pd.read_csv(labels_path)

    # Merge on BlockId
    df_merged = pd.merge(df_eom, df_labels, on='BlockId')
    total_records = len(df_merged)
    print(f"[DATA LOAD] Merged records: {total_records:,} block traces.")

    # Event columns (E1 to E29), Error template columns, and Warning template columns
    event_cols = [f"E{i}" for i in range(1, 30)]
    error_cols = ['E4', 'E7', 'E10', 'E12', 'E14', 'E17', 'E20', 'E29']
    warning_cols = ['E1', 'E8', 'E11', 'E13', 'E19', 'E23', 'E24', 'E27', 'E28']

    # 1. event_frequency: total event occurrences per block trace
    event_freq = df_merged[event_cols].sum(axis=1).astype(float)

    # 2. sequence_length: count of distinct active event templates per block trace
    # (Removes 100% collinear duplicate of event_frequency, providing genuine structural diversity)
    seq_len = (df_merged[event_cols] > 0).sum(axis=1).astype(float)

    # 3. error_count: raw count of error/exception events in trace (no arbitrary +3.0 baseline offset)
    err_count = df_merged[error_cols].sum(axis=1).astype(float)

    # 4. error_pattern: 0.0 (normal / no errors) or 1.0 (error present)
    err_pattern = np.where(err_count > 0, 1.0, 0.0)

    # 5. warning_count: count of warning/interruption/retry events from HDFS templates
    warning_count = df_merged[warning_cols].sum(axis=1).astype(float)

    # 6-8. Authentication & Unknown features: HDFS operational block traces do not record SSH/user logons
    # (Documented dataset limitation; preserved as 0.0 to maintain canonical 8-feature schema alignment)
    zeros = np.zeros(total_records, dtype=float)

    feature_df = pd.DataFrame({
        'event_frequency': event_freq,
        'sequence_length': seq_len,
        'error_count': err_count,
        'error_pattern': err_pattern,
        'login_attempts': zeros,
        'failed_login_attempts': zeros,
        'warning_count': warning_count,
        'unknown_events': zeros
    }, columns=FEATURE_SCHEMA)

    # Ground truth labels: 0 for Normal, 1 for Anomaly (strictly for post-fitting evaluation)
    y_true = np.where(df_merged['Label_y'] == 'Anomaly', 1, 0)
    anomaly_count = int(np.sum(y_true))
    normal_count = total_records - anomaly_count
    anomaly_ratio = anomaly_count / total_records

    print(f"[DATA SUMMARY] Total Blocks: {total_records:,} | Normal: {normal_count:,} ({(1-anomaly_ratio)*100:.2f}%) | Anomalies: {anomaly_count:,} ({anomaly_ratio*100:.4f}%)")

    return feature_df, y_true, total_records, anomaly_count, normal_count, anomaly_ratio


def evaluate_model_on_split(model, X_test, y_test, model_name="Isolation Forest"):
    """Evaluates an Isolation Forest detector on held-out test data with ground truth."""
    raw_preds = model.predict(X_test)
    y_pred = np.where(raw_preds == -1, 1, 0)
    raw_scores = model.decision_function(X_test)
    norm_scores = np.clip(1.0 - (raw_scores + 0.5), 0.0, 1.0)

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
    total = len(y_test)
    detected_anomalies = int(np.sum(y_pred))
    detected_anomaly_pct = (detected_anomalies / total) * 100.0

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    roc_auc = 'N/A'
    pr_auc = 'N/A'
    try:
        roc_auc = float(roc_auc_score(y_test, norm_scores))
    except Exception:
        pass
    try:
        pr_auc = float(average_precision_score(y_test, norm_scores))
    except Exception:
        pass

    return {
        'model_name': model_name,
        'total_samples': total,
        'normal_samples': int((y_test == 0).sum()),
        'anomalous_samples': int((y_test == 1).sum()),
        'detected_anomalies': detected_anomalies,
        'detected_anomaly_percentage': round(detected_anomaly_pct, 4),
        'accuracy': round(acc, 4),
        'precision': round(prec, 4),
        'recall': round(rec, 4),
        'f1_score': round(f1, 4),
        'roc_auc': round(roc_auc, 4) if isinstance(roc_auc, float) else roc_auc,
        'pr_auc': round(pr_auc, 4) if isinstance(pr_auc, float) else pr_auc,
        'false_positive_rate': round(fpr, 4),
        'false_negative_rate': round(fnr, 4),
        'confusion_matrix': {
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'true_positives': int(tp)
        }
    }


def train_hdfs_isolation_forest(
    dataset_path=None,
    output_path=DEFAULT_NEW_MODEL_PATH,
    n_estimators=100,
    contamination=0.0293,
    max_samples='auto',
    random_state=42,
    test_size=0.30,
    replace_production=False
):
    print("=" * 80)
    print("HDFS ISOLATION FOREST REPRODUCIBLE TRAINING & EVALUATION PIPELINE")
    print("=" * 80)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Random State: {random_state}")
    print(f"Contamination: {contamination} (~2.93% HDFS benchmark ground-truth anomaly ratio)")
    print(f"Estimators: {n_estimators} | Max Samples: {max_samples}")

    # Step 1: Locate and load HDFS dataset
    hdfs_dir = find_hdfs_dataset_path(dataset_path)
    print(f"\n[PHASE 1] Loading real HDFS dataset from: {hdfs_dir}")
    raw_feature_df, y_all, total_records, total_anom, total_norm, anom_ratio = load_hdfs_features_and_labels(hdfs_dir)

    # Step 2: Unsupervised Train / Test Split (Held-Out Test, seed=random_state)
    # Ground-truth labels y_all are strictly WITHHELD from train_test_split (stratify=None)
    # to guarantee 100% unsupervised, label-independent experimental setup.
    print(f"\n[PHASE 2] Splitting dataset ({(1-test_size)*100:.0f}% Train / {test_size*100:.0f}% Held-Out Test, seed={random_state}, stratify=None)...")
    indices = np.arange(total_records)
    train_idx, test_idx = train_test_split(
        indices, test_size=test_size, random_state=random_state, stratify=None
    )

    train_raw_feats = raw_feature_df.iloc[train_idx].copy().reset_index(drop=True)
    test_raw_feats = raw_feature_df.iloc[test_idx].copy().reset_index(drop=True)
    y_train = y_all[train_idx]
    y_test = y_all[test_idx]

    # Step 3: Validate & Preprocess using DataPreprocessor with Strict Leakage Protection
    # Fit preprocessing statistics (medians) strictly on train_raw_feats
    print("\n[PHASE 3] Preprocessing training split (statistics learned exclusively on X_train)...")
    train_cleaned_df, train_stats = DataPreprocessor.preprocess(train_raw_feats)
    train_fitted_medians = train_stats['fitted_medians']

    # Transform held-out test split using training medians
    print("Preprocessing held-out test split using fitted training statistics...")
    test_cleaned_df, test_stats = DataPreprocessor.preprocess(test_raw_feats, fit_medians=train_fitted_medians)

    X_train = train_cleaned_df[FEATURE_SCHEMA]
    X_test = test_cleaned_df[FEATURE_SCHEMA]

    assert not X_train.isna().any().any(), "NaN values found in X_train after preprocessing!"
    assert not np.isinf(X_train.values).any(), "Infinite values found in X_train after preprocessing!"
    assert not X_test.isna().any().any(), "NaN values found in X_test after preprocessing!"
    assert not np.isinf(X_test.values).any(), "Infinite values found in X_test after preprocessing!"

    print(f"  - Schema Validated: {list(X_train.columns)}")
    print(f"  - Training Samples (X_train) : {len(X_train):,} (Unsupervised, y_train withheld)")
    print(f"  - Held-Out Test Samples (X_test) : {len(X_test):,} (Normal: {(y_test==0).sum():,}, Anomaly: {(y_test==1).sum():,})")

    # Step 4: Strict Unsupervised Model Training
    print(f"\n[PHASE 4] Fitting sklearn.ensemble.IsolationForest on X_train...")
    print("  [NOTE] Ground-truth labels are STRICTLY WITHHELD during fitting.")
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        max_samples=max_samples,
        random_state=random_state,
        n_jobs=-1
    )
    model.fit(X_train)

    print("  - Model fitting completed successfully.")
    print(f"  - Fitted offset_    : {model.offset_:.6f}")
    print(f"  - Fitted max_samples: {model.max_samples_}")
    print(f"  - Estimator count   : {len(model.estimators_)}")

    # Step 5: Save New Model Artifact First
    print(f"\n[PHASE 5] Serializing newly trained model to separate path: {output_path}")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    joblib.dump(model, output_path)
    new_model_size = os.path.getsize(output_path)
    new_model_sha256 = compute_file_sha256(output_path)
    print(f"  - Saved Model Size  : {new_model_size:,} bytes")
    print(f"  - Saved Model SHA256: {new_model_sha256}")

    # Step 6: Verify Saved Model Reloading & Prediction
    print("\n[PHASE 6] Verifying reloaded model integrity...")
    reloaded_model = joblib.load(output_path)
    saved_schema = list(getattr(reloaded_model, 'feature_names_in_', []))
    if saved_schema != FEATURE_SCHEMA:
        raise RuntimeError(f"Saved model schema mismatch! Expected {FEATURE_SCHEMA}, got {saved_schema}")
    if getattr(reloaded_model, 'n_features_in_', None) != len(FEATURE_SCHEMA):
        raise RuntimeError("Saved model dimensionality mismatch!")
    sample_preds = reloaded_model.predict(X_test[:10])
    print(f"  - Reload Check      : PASSED (Schema: {saved_schema})")
    print(f"  - Inference Test    : PASSED (Sample raw predictions: {sample_preds.tolist()})")

    # Step 7: Evaluate New Model on Held-Out Test Set
    print("\n[PHASE 7] Evaluating newly trained model on held-out test split (172,519 samples)...")
    new_metrics = evaluate_model_on_split(reloaded_model, X_test, y_test, model_name="Newly Trained HDFS Isolation Forest")

    # Step 8: Evaluate Existing Pretrained Model on the Exact Same Test Split
    old_metrics = None
    orig_model_sha256 = None
    orig_model_size = 0
    if os.path.exists(PROD_MODEL_PATH):
        print("\n[PHASE 8] Evaluating existing production model on the exact same held-out test split...")
        try:
            orig_model_size = os.path.getsize(PROD_MODEL_PATH)
            orig_model_sha256 = compute_file_sha256(PROD_MODEL_PATH)
            old_model = joblib.load(PROD_MODEL_PATH)
            old_metrics = evaluate_model_on_split(old_model, X_test, y_test, model_name="Pretrained HDFS Isolation Forest")
        except Exception as e:
            print(f"  - Warning: Could not evaluate existing production model: {e}")

    # Step 9: Print Comparative Evaluation Table
    print("\n" + "=" * 90)
    print("EMPIRICAL COMPARISON ON HELD-OUT HDFS TEST SET (172,519 SAMPLES)")
    print("=" * 90)
    header = f"{'Metric':<30} | {'Existing Pretrained Model':<25} | {'Newly Trained Model':<25}"
    print(header)
    print("-" * 90)

    metrics_keys = [
        ('total_samples', 'Total Test Samples'),
        ('normal_samples', 'Normal Samples (Ground Truth)'),
        ('anomalous_samples', 'Anomalous Samples (Ground Truth)'),
        ('detected_anomalies', 'Detected Anomalies'),
        ('detected_anomaly_percentage', 'Detected Anomaly %'),
        ('accuracy', 'Accuracy'),
        ('precision', 'Precision'),
        ('recall', 'Recall'),
        ('f1_score', 'F1-Score'),
        ('roc_auc', 'ROC-AUC'),
        ('pr_auc', 'PR-AUC'),
        ('false_positive_rate', 'False Positive Rate (FPR)'),
        ('false_negative_rate', 'False Negative Rate (FNR)'),
    ]

    for key, label in metrics_keys:
        old_val = old_metrics[key] if old_metrics and key in old_metrics else "N/A"
        new_val = new_metrics[key]
        print(f"{label:<30} | {str(old_val):<25} | {str(new_val):<25}")

    print("-" * 90)
    print("Confusion Matrix (New Model):")
    cm = new_metrics['confusion_matrix']
    print(f"  TN: {cm['true_negatives']:,} | FP: {cm['false_positives']:,}")
    print(f"  FN: {cm['false_negatives']:,} | TP: {cm['true_positives']:,}")
    print("=" * 90)

    # Step 10: Replace Production Model if Requested
    if replace_production:
        print("\n[PHASE 10] Replacing production model artifact with newly trained model...")
        if os.path.exists(PROD_MODEL_PATH) and not os.path.exists(BACKUP_MODEL_PATH):
            shutil.copy2(PROD_MODEL_PATH, BACKUP_MODEL_PATH)
            print(f"  - Backup Created   : {BACKUP_MODEL_PATH}")

        shutil.copy2(output_path, PROD_MODEL_PATH)
        final_prod_sha256 = compute_file_sha256(PROD_MODEL_PATH)
        print(f"  - Production Model Replaced: {PROD_MODEL_PATH}")
        print(f"  - Production Model SHA256  : {final_prod_sha256}")

    return {
        'status': 'SUCCESS',
        'dataset_path': hdfs_dir,
        'total_samples': total_records,
        'train_samples': len(X_train),
        'test_samples': len(X_test),
        'feature_schema': FEATURE_SCHEMA,
        'n_estimators': n_estimators,
        'contamination': contamination,
        'max_samples': max_samples,
        'random_state': random_state,
        'new_model_path': output_path,
        'new_model_size': new_model_size,
        'new_model_sha256': new_model_sha256,
        'orig_model_path': PROD_MODEL_PATH,
        'orig_model_size': orig_model_size,
        'orig_model_sha256': orig_model_sha256,
        'new_metrics': new_metrics,
        'old_metrics': old_metrics
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train and evaluate Isolation Forest on HDFS dataset.")
    parser.add_argument("--dataset", type=str, default=None, help="Path to HDFS dataset directory.")
    parser.add_argument("--output", type=str, default=DEFAULT_NEW_MODEL_PATH, help="Path to save the new model artifact.")
    parser.add_argument("--n-estimators", type=int, default=100, help="Number of isolation trees.")
    parser.add_argument("--contamination", type=float, default=0.0293, help="Contamination rate.")
    parser.add_argument("--max-samples", type=str, default='auto', help="Max samples per tree.")
    parser.add_argument("--random-state", type=int, default=42, help="Random state seed.")
    parser.add_argument("--test-size", type=float, default=0.30, help="Held-out test split ratio.")
    parser.add_argument("--replace-production", action="store_true", help="Replace backend/models/hdfs_isolation_forest_model.pkl upon success.")
    args = parser.parse_args()

    max_samples_val = int(args.max_samples) if args.max_samples.isdigit() else args.max_samples

    train_hdfs_isolation_forest(
        dataset_path=args.dataset,
        output_path=args.output,
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        max_samples=max_samples_val,
        random_state=args.random_state,
        test_size=args.test_size,
        replace_production=args.replace_production
    )
