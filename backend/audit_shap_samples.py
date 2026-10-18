import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import pandas as pd
import numpy as np
import shap
from ml_engine import IsolationForestDetector, ShapExplainerEngine, FEATURE_SCHEMA

detector = IsolationForestDetector()
model = detector.model

print("=== 1. MODEL INSPECTION ===")
print("Model Class:", type(model))
print("Model estimators:", getattr(model, 'n_estimators', None))
print("Model feature schema:", getattr(model, 'feature_names_in_', None))
print("n_features_in_:", getattr(model, 'n_features_in_', None))

samples_data = [
    {
        'name': 'Sample 1: SSH Brute Force (High Failed Logins)',
        'event_frequency': 0.85, 'sequence_length': 45.0, 'error_count': 0.0, 'error_pattern': 0.0,
        'login_attempts': 25.0, 'failed_login_attempts': 24.0, 'warning_count': 0.0, 'unknown_events': 0.0,
        'log_item': {'message': 'sshd: Failed password for invalid user root from 192.168.1.50', 'service': 'sshd', 'user': 'root', 'computer': 'server01'}
    },
    {
        'name': 'Sample 2: Application Crash Loop (High Error Count & Error Pattern)',
        'event_frequency': 0.90, 'sequence_length': 120.0, 'error_count': 45.0, 'error_pattern': 2.0,
        'login_attempts': 1.0, 'failed_login_attempts': 0.0, 'warning_count': 10.0, 'unknown_events': 1.0,
        'log_item': {'message': 'nginx.service: Main process exited, code=dumped, status=11/SEGV', 'service': 'nginx', 'user': 'SYSTEM', 'computer': 'server01'}
    },
    {
        'name': 'Sample 3: Suspicious PowerShell Injection (Unknown Events & Long Sequence)',
        'event_frequency': 0.30, 'sequence_length': 480.0, 'error_count': 2.0, 'error_pattern': 3.0,
        'login_attempts': 0.0, 'failed_login_attempts': 0.0, 'warning_count': 1.0, 'unknown_events': 22.0,
        'log_item': {'message': 'powershell.exe -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...', 'service': 'powershell.exe', 'user': 'Admin', 'computer': 'server01'}
    },
    {
        'name': 'Sample 4: Routine Benign Service Heartbeat (Normal Baseline)',
        'event_frequency': 0.02, 'sequence_length': 40.0, 'error_count': 0.0, 'error_pattern': 0.0,
        'login_attempts': 0.0, 'failed_login_attempts': 0.0, 'warning_count': 0.0, 'unknown_events': 0.0,
        'log_item': {'message': 'systemd-timesyncd: Synchronized to time server 129.6.15.28:123', 'service': 'systemd-timesyncd', 'user': 'SYSTEM', 'computer': 'server01'}
    },
    {
        'name': 'Sample 5: Resource Exhaustion / Warning Storm (High Warning Count)',
        'event_frequency': 0.75, 'sequence_length': 85.0, 'error_count': 1.0, 'error_pattern': 1.0,
        'login_attempts': 0.0, 'failed_login_attempts': 0.0, 'warning_count': 50.0, 'unknown_events': 0.0,
        'log_item': {'message': 'kernel: [Hardware Error]: CPU temperature throttled, thermal limit reached', 'service': 'kernel', 'user': 'SYSTEM', 'computer': 'server01'}
    }
]

df_feat = pd.DataFrame([{k: s[k] for k in FEATURE_SCHEMA} for s in samples_data])
df_feat['log_id'] = [i+1 for i in range(len(samples_data))]

# Step 1: Predictions
pred_res = detector.predict(df_feat)
preds = pred_res[0] if isinstance(pred_res, tuple) else pred_res

# Step 2: SHAP Explain
parsed_logs = [dict(s['log_item'], log_id=i+1) for i, s in enumerate(samples_data)]
exps = ShapExplainerEngine.explain(model, df_feat, preds, parsed_logs=parsed_logs)

print("\n=== 2. SHAP AUDIT COMPARISON FOR 5 SAMPLES ===")
for i, s in enumerate(samples_data):
    name = s['name']
    print(f"\n==================================================")
    print(f"SAMPLE {i+1}: {name}")
    print(f"==================================================")
    print("1. Input 8 Features:")
    for feat in FEATURE_SCHEMA:
        print(f"     {feat:22s}: {s[feat]}")
    print(f"   Prediction Score: {preds[i]['anomaly_score']} | is_anomaly: {preds[i]['is_anomaly']} | Severity: {preds[i]['severity']}")
    print("2. Raw SHAP Feature Contributions:")
    for k, v in exps[i]['feature_contributions'].items():
        print(f"     {k:22s}: {v:+8.4f}")
    print("3. Top Contributing Feature:", exps[i]['top_reason'])
    print("4. Top 3 Contributing Human Factors:")
    for rank, r in enumerate(exps[i]['top_3_human_reasons'], 1):
        print(f"     Factor {rank}: {r}")
    print("5. Why Suspicious / Explanation:")
    print(f"     \"{exps[i]['why_suspicious']}\"")
    print("6. Recommended Action:")
    print(f"     \"{exps[i]['recommended_action']}\"")
