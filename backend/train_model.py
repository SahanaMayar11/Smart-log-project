"""Train Smart-Log's Isolation Forest from persisted, preprocessed features.

The application stores the eight cleaned feature columns for each uploaded log
file in ``smartlog.db``.  This script uses those records directly so training
and inference share the schema defined in ``ml_engine.FEATURE_SCHEMA``.
"""

import argparse
import os
import shutil
import sqlite3
from datetime import datetime

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from ml_engine import DataPreprocessor, FEATURE_SCHEMA


BASE_DIR = os.path.dirname(__file__)
DATABASE_PATH = os.path.join(BASE_DIR, "smartlog.db")
MODELS_DIR = os.path.join(BASE_DIR, "models")
IF_MODEL_PATH = os.path.join(MODELS_DIR, "isolation_forest_model.pkl")
BACKUP_MODEL_PATH = os.path.join(MODELS_DIR, "isolation_forest_model_before_retrain.pkl")


def load_preprocessed_training_data(include_live=False):
    """Load historical feature rows already produced by the app's preprocessor.

    Live-monitoring uploads are excluded by default.  Exact duplicate vectors
    are removed because repeated uploads would otherwise disproportionately
    influence an unsupervised baseline.
    """
    if not os.path.exists(DATABASE_PATH):
        raise FileNotFoundError(f"Smart-Log database not found: {DATABASE_PATH}")

    query = f"""
        SELECT {", ".join(f"f.{column}" for column in FEATURE_SCHEMA)}
        FROM extracted_features AS f
        INNER JOIN uploaded_files AS u ON u.id = f.file_id
    """
    if not include_live:
        query += " WHERE LOWER(u.filename) NOT LIKE 'live_%'"

    with sqlite3.connect(DATABASE_PATH) as connection:
        stored_features = pd.read_sql_query(query, connection)

    if stored_features.empty:
        raise ValueError("No stored preprocessed feature rows are available for training.")

    # Revalidate using the same preprocessor used by the API before training.
    validated_features, preprocessing_stats = DataPreprocessor.preprocess(stored_features)
    X_all = validated_features[FEATURE_SCHEMA]
    X_train = X_all.drop_duplicates().reset_index(drop=True)

    if len(X_train) < 2:
        raise ValueError("At least two distinct feature rows are required to train Isolation Forest.")

    return X_train, {
        "stored_rows": len(X_all),
        "training_rows": len(X_train),
        "duplicates_removed": len(X_all) - len(X_train),
        "include_live": include_live,
        "preprocessing_stats": preprocessing_stats,
    }


def _save_model_safely(model):
    """Back up the previous artifact once, then atomically replace it."""
    os.makedirs(MODELS_DIR, exist_ok=True)
    if os.path.exists(IF_MODEL_PATH) and not os.path.exists(BACKUP_MODEL_PATH):
        shutil.copy2(IF_MODEL_PATH, BACKUP_MODEL_PATH)
        print(f"[BACKUP] Previous model retained at: {BACKUP_MODEL_PATH}")

    temporary_path = f"{IF_MODEL_PATH}.{os.getpid()}.tmp"
    try:
        joblib.dump(model, temporary_path)
        os.replace(temporary_path, IF_MODEL_PATH)
    finally:
        if os.path.exists(temporary_path):
            os.remove(temporary_path)


def train_and_save_model(n_estimators=100, contamination=0.15, random_state=42, include_live=False):
    """Retrain and verify the production Isolation Forest on eight features.

    The source is unlabeled, so anomaly counts are diagnostic output only; this
    function intentionally does not calculate or claim an accuracy metric.
    """
    print("=" * 70)
    print("SMART-LOG ISOLATION FOREST RETRAINING")
    print("=" * 70)
    print("[STEP 1] Loading persisted preprocessed feature data...")
    X_train, data_summary = load_preprocessed_training_data(include_live=include_live)

    print(f"         Stored feature rows: {data_summary['stored_rows']}")
    print(f"         Training samples (deduplicated): {data_summary['training_rows']}")
    print(f"         Duplicate rows removed: {data_summary['duplicates_removed']}")
    print(f"         Live-monitoring rows included: {data_summary['include_live']}")
    print(f"         Feature columns: {', '.join(FEATURE_SCHEMA)}")

    print(f"[STEP 2] Training Isolation Forest (n_estimators={n_estimators}, contamination={contamination})...")
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        max_samples="auto",
    )
    model.fit(X_train)

    print("[STEP 3] Saving production model...")
    _save_model_safely(model)
    print(f"         Model path: {IF_MODEL_PATH}")

    print("[STEP 4] Verifying saved model and inference schema...")
    saved_model = joblib.load(IF_MODEL_PATH)
    saved_schema = list(getattr(saved_model, "feature_names_in_", []))
    if saved_schema != FEATURE_SCHEMA:
        raise RuntimeError(f"Saved model schema mismatch. Expected {FEATURE_SCHEMA}, got {saved_schema}")
    if getattr(saved_model, "n_features_in_", None) != len(FEATURE_SCHEMA):
        raise RuntimeError("Saved model does not expect the required eight features.")

    verification_predictions = saved_model.predict(X_train)
    training_anomalies = int((verification_predictions == -1).sum())
    print("         Saved-model prediction: PASSED")
    print(f"         Verified schema: {', '.join(saved_schema)}")
    print(f"         Training-set anomaly flags: {training_anomalies} / {len(X_train)}")
    print("         Accuracy: not available (the training records have no ground-truth labels).")
    print("=" * 70)
    print(f"RETRAINING COMPLETED: {datetime.now().isoformat(timespec='seconds')}")
    print("=" * 70)

    return {
        "model_path": IF_MODEL_PATH,
        "training_samples": len(X_train),
        "feature_columns": FEATURE_SCHEMA.copy(),
        "anomaly_flags": training_anomalies,
        "labels_available": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Retrain Smart-Log's Isolation Forest from stored feature records.")
    parser.add_argument("--include-live", action="store_true", help="Include rows collected by live monitoring (excluded by default).")
    args = parser.parse_args()
    train_and_save_model(include_live=args.include_live)
