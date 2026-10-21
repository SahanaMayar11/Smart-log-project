import os
import sys
import joblib
import pandas as pd

backend_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(backend_dir)

from ml_engine import (
    IsolationForestDetector,
    OneClassSVMValidator,
    FEATURE_SCHEMA,
    ShapExplainerEngine
)

models_dir = os.path.join(backend_dir, 'models')

print("=" * 65)
print("1. VERIFYING ALL MODEL ARTIFACTS ON DISK")
print("=" * 65)

for f in sorted(os.listdir(models_dir)):
    if f.endswith('.pkl'):
        full_p = os.path.join(models_dir, f)
        obj = joblib.load(full_p)
        print(f"File: {f}")
        print(f"  Class Module: {obj.__class__.__module__}")
        print(f"  Class Name:   {obj.__class__.__name__}")
        if hasattr(obj, 'n_estimators'):
            print(f"  Estimators:   {obj.n_estimators}")
            print(f"  Contamination:{getattr(obj, 'contamination', None)}")
        if hasattr(obj, 'kernel'):
            print(f"  Kernel:       {obj.kernel}")
            print(f"  nu:           {getattr(obj, 'nu', None)}")
        print(f"  Features In:  {getattr(obj, 'feature_names_in_', None)}")
        print("-" * 65)

print("\n" + "=" * 65)
print("2. VERIFYING UNSUPERVISED ENGINE INSTANTIATION & INFERENCE")
print("=" * 65)

if_det = IsolationForestDetector()
print(f"IsolationForestDetector loaded class: {if_det.model.__class__.__module__}.{if_det.model.__class__.__name__}")

ocsvm_val = OneClassSVMValidator()
print(f"OneClassSVMValidator loaded class:    {ocsvm_val.model.__class__.__module__}.{ocsvm_val.model.__class__.__name__}")

sample_df = pd.DataFrame([{
    'event_frequency': 5.0,
    'sequence_length': 120,
    'error_count': 3,
    'error_pattern': 1,
    'login_attempts': 5,
    'failed_login_attempts': 5,
    'warning_count': 0,
    'unknown_events': 0
}])

if_results, X_in = if_det.predict(sample_df)
print(f"\nIsolation Forest inference output:")
print(f"  is_anomaly:    {if_results[0]['is_anomaly']}")
print(f"  anomaly_score: {if_results[0]['anomaly_score']}")
print(f"  severity:      {if_results[0]['severity']}")

ocsvm_results = ocsvm_val.predict(sample_df)
print(f"\nOne-Class SVM validation output:")
print(f"  is_anomaly:    {ocsvm_results[0]['is_anomaly']}")
print(f"  anomaly_score: {ocsvm_results[0]['anomaly_score']}")

exps = ShapExplainerEngine.explain(if_det.model, X_in, if_results, raw_features=sample_df)
print(f"\nSHAP Explainer output:")
print(f"  Explained Model:    {exps[0]['model_name']}")
print(f"  Explanation Status: {exps[0]['explanation_status']}")
print(f"  Top Factor #1:      {exps[0]['top_3_human_reasons'][0]}")
print(f"  Top Factor #2:      {exps[0]['top_3_human_reasons'][1]}")
print(f"  Why Suspicious:     {exps[0]['why_suspicious']}")

print("\n" + "=" * 65)
print("3. VERIFYING SUPERVISED / BOOSTING ALGORITHMS (XGBoost, RandomForest)")
print("=" * 65)
print("Checking for XGBoost / Random Forest in project...")
is_xgb_used = False
is_rf_used = False

for root, _, files in os.walk(os.path.dirname(backend_dir)):
    if 'node_modules' in root or '.git' in root or '.venv' in root:
        continue
    for file in files:
        if file.endswith('.py') and file != 'verify_models_audit.py':
            fpath = os.path.join(root, file)
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as fp:
                content = fp.read()
                if 'xgboost' in content.lower() or 'xgb' in content.lower():
                    # check if actual import
                    if 'import xgboost' in content or 'from xgboost' in content:
                        is_xgb_used = True
                        print(f"  Found XGBoost in: {file}")
                if 'RandomForestClassifier' in content or 'RandomForestRegressor' in content:
                    is_rf_used = True
                    print(f"  Found RandomForest in: {file}")

print(f"  XGBoost used in project:       {'YES' if is_xgb_used else 'NO (Never used)'}")
print(f"  Random Forest used in project: {'YES' if is_rf_used else 'NO (Never used)'}")
print("=" * 65)
