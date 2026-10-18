import os
import json
import joblib
import pandas as pd

from sklearn.ensemble import IsolationForest


# =========================================================
# SETTINGS
# =========================================================

FEATURE_COLUMNS = [
    "event_frequency",
    "sequence_length",
    "error_count",
    "error_pattern",
    "login_attempts",
    "failed_login_attempts",
    "warning_count",
    "unknown_events"
]

DATA_PATH = os.path.join(
    os.environ["USERPROFILE"],
    "Documents",
    "SmartLogData",
    "windows_training_features.json"
)

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "models",
    "isolation_forest_model.pkl"
)


# =========================================================
# 1. LOAD TRAINING DATA
# =========================================================

print("=" * 60)
print("ISOLATION FOREST TRAINING")
print("=" * 60)

print("Loading training data:")
print(DATA_PATH)

df = pd.read_json(DATA_PATH)

print("Total records:", len(df))


# =========================================================
# 2. VERIFY FEATURES
# =========================================================

missing_features = [
    col for col in FEATURE_COLUMNS
    if col not in df.columns
]

if missing_features:
    raise ValueError(
        f"Missing required features: {missing_features}"
    )

X = df[FEATURE_COLUMNS].copy()

print()
print("Training features:")
for column in FEATURE_COLUMNS:
    print(" -", column)

print()
print("Training shape:", X.shape)


# =========================================================
# 3. FINAL VALIDATION
# =========================================================

if X.isna().any().any():
    raise ValueError("NaN values found in training data.")

if not X.apply(lambda col: col.map(lambda x: isinstance(x, (int, float))).all()).all():
    print("Warning: checking numeric conversion...")

X = X.apply(pd.to_numeric, errors="coerce")

if X.isna().any().any():
    raise ValueError("Non-numeric values found after conversion.")

if X.isin([float("inf"), float("-inf")]).any().any():
    raise ValueError("Infinite values found in training data.")


# =========================================================
# 4. TRAIN ISOLATION FOREST
# =========================================================

print()
print("Training Isolation Forest...")

model = IsolationForest(
    n_estimators=100,
    contamination=0.15,
    random_state=42,
    max_samples="auto"
)

model.fit(X)


# =========================================================
# 5. SAVE MODEL
# =========================================================

joblib.dump(model, MODEL_PATH)

print()
print("=" * 60)
print("TRAINING COMPLETE")
print("=" * 60)

print("Training records:", len(X))
print("Features used:", len(FEATURE_COLUMNS))
print("Estimators:", model.n_estimators)
print("Contamination:", model.contamination)
print()
print("Model saved to:")
print(MODEL_PATH)


# =========================================================
# 6. VERIFY SAVED MODEL
# =========================================================

loaded_model = joblib.load(MODEL_PATH)

predictions = loaded_model.predict(X)

normal_count = int((predictions == 1).sum())
anomaly_count = int((predictions == -1).sum())

print()
print("MODEL VERIFICATION")
print("------------------")
print("Normal:", normal_count)
print("Anomalies:", anomaly_count)
print("Total:", len(predictions))

print()
print("New Isolation Forest model is ready.")