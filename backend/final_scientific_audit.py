import sys, os, hashlib, time
sys.path.insert(0, os.path.dirname(__file__))
import joblib
import pandas as pd
import numpy as np
import shap
from ml_engine import (
    IsolationForestDetector,
    ShapExplainerEngine,
    FEATURE_SCHEMA
)

print("=" * 80)
print("SMART-LOG: FINAL SCIENTIFIC CONSISTENCY AUDIT REPORT")
print("=" * 80)

# ==============================================================================
# 1. PRODUCTION MODEL ARTIFACT INTEGRITY CHECK
# ==============================================================================
print("\n[SECTION 1] PRODUCTION MODEL ARTIFACT INTEGRITY AUDIT")
prod_path = os.path.join(os.path.dirname(__file__), 'models', 'isolation_forest_model.pkl')
hdfs_path = os.path.join(os.path.dirname(__file__), 'models', 'hdfs_isolation_forest_model.pkl')

for name, path in [("Production IF Model", prod_path), ("HDFS IF Model", hdfs_path)]:
    if os.path.exists(path):
        mtime = time.ctime(os.path.getmtime(path))
        size_bytes = os.path.getsize(path)
        with open(path, 'rb') as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        m = joblib.load(path)
        print(f"  Artifact : {name}")
        print(f"    - File Path      : {path}")
        print(f"    - File Size      : {size_bytes} bytes")
        print(f"    - Last Modified  : {mtime}")
        print(f"    - SHA-256 Hash   : {sha256}")
        print(f"    - Estimators     : {getattr(m, 'n_estimators', None)}")
        print(f"    - Features Count : {getattr(m, 'n_features_in_', None)}")
        print(f"    - Feature Schema : {getattr(m, 'feature_names_in_', None)}")
    else:
        print(f"  Artifact {name}: MISSING")

# ==============================================================================
# 2. ISOLATION FOREST BOUNDARY & DECISION FUNCTION AUDIT
# ==============================================================================
print("\n[SECTION 2] ISOLATION FOREST DECISION BOUNDARY & SCORE MAPPING AUDIT")
print("Formula: norm_score = clip(1.0 - (decision_function(X) + 0.5), 0.0, 1.0)")
print("Binary Classification: is_anomaly = 1 if pred == -1 (score >= 0.50) else 0")

boundary_test_scores = [
    ("Strong Inlier / Baseline", +0.30),
    ("Moderate Inlier", +0.10),
    ("Near Boundary (Inlier)", +0.01),
    ("Exact Decision Boundary", 0.00),
    ("Near Boundary (Outlier)", -0.01),
    ("Moderate Outlier", -0.15),
    ("Strong Outlier", -0.30),
    ("Extreme Outlier", -0.45)
]

print(f"{'Description':26s} | {'decision_fn':11s} | {'norm_score':10s} | {'is_anomaly':10s} | {'Severity Band':13s}")
print("-" * 80)
for desc, dec_fn in boundary_test_scores:
    pred_val = -1 if dec_fn <= 0 else 1
    is_anom = 1 if pred_val == -1 else 0
    norm_score = float(np.clip(1.0 - (dec_fn + 0.5), 0.0, 1.0))
    
    if norm_score >= 0.50:
        if norm_score > 0.85:
            sev = 'Critical'
        elif norm_score > 0.70:
            sev = 'High'
        elif norm_score > 0.55:
            sev = 'Medium'
        else:
            sev = 'Low'
    else:
        sev = 'Normal'
    
    print(f"{desc:26s} | {dec_fn:+11.2f} | {norm_score:10.4f} | {is_anom:10d} | {sev:13s}")

# ==============================================================================
# 3. OPERATIONAL SEVERITY BAND TRANSITION VERIFICATION
# ==============================================================================
print("\n[SECTION 3] OPERATIONAL SEVERITY BANDS BOUNDARY VALUE AUDIT")
operational_boundary_values = [
    (0.00, 0, 'Normal'),
    (0.49, 0, 'Normal'),
    (0.50, 1, 'Low'),
    (0.55, 1, 'Low'),
    (0.56, 1, 'Medium'),
    (0.70, 1, 'Medium'),
    (0.71, 1, 'High'),
    (0.85, 1, 'High'),
    (0.86, 1, 'Critical'),
    (1.00, 1, 'Critical')
]

print(f"{'Input Anomaly Score':20s} | {'Expected Flag':13s} | {'Assigned Severity':18s} | {'Verification Status':20s}")
print("-" * 80)
for s, expected_flag, expected_sev in operational_boundary_values:
    if s >= 0.50:
        if s > 0.85:
            sev = 'Critical'
        elif s > 0.70:
            sev = 'High'
        elif s > 0.55:
            sev = 'Medium'
        else:
            sev = 'Low'
        is_a = 1
    else:
        sev = 'Normal'
        is_a = 0
        
    status = "PASS (Consistent)" if (sev == expected_sev and is_a == expected_flag) else "FAIL (Mismatch)"
    print(f"{s:20.2f} | {is_a:13d} | {sev:18s} | {status:20s}")

# ==============================================================================
# 4. SAMPLE-SPECIFIC SHAP EXPLANATION TEST ACROSS 4 MANDATORY SCENARIOS
# ==============================================================================
print("\n[SECTION 4] SAMPLE-SPECIFIC SHAP EXPLANATIONS & RECOMMENDATIONS AUDIT")

detector = IsolationForestDetector()
model = detector.model

test_scenarios = [
    {
        'scenario': '1. Normal Operational Baseline Event',
        'features': {'event_frequency': 0.02, 'sequence_length': 40.0, 'error_count': 0.0, 'error_pattern': 0.0, 'login_attempts': 0.0, 'failed_login_attempts': 0.0, 'warning_count': 0.0, 'unknown_events': 0.0, 'log_id': 1},
        'log_item': {'log_id': 1, 'service': 'systemd-timesyncd', 'message': 'Synchronized time with NTP server pool', 'user': 'SYSTEM', 'computer': 'server01'}
    },
    {
        'scenario': '2. Authentication Anomaly (SSH Brute Force)',
        'features': {'event_frequency': 0.85, 'sequence_length': 45.0, 'error_count': 0.0, 'error_pattern': 0.0, 'login_attempts': 25.0, 'failed_login_attempts': 24.0, 'warning_count': 0.0, 'unknown_events': 0.0, 'log_id': 2},
        'log_item': {'log_id': 2, 'service': 'sshd', 'message': 'Failed password for invalid user admin from 192.168.1.100 port 4522', 'user': 'admin', 'computer': 'server01'}
    },
    {
        'scenario': '3. Application Error / Crash Loop Anomaly',
        'features': {'event_frequency': 0.90, 'sequence_length': 120.0, 'error_count': 45.0, 'error_pattern': 2.0, 'login_attempts': 1.0, 'failed_login_attempts': 0.0, 'warning_count': 10.0, 'unknown_events': 1.0, 'log_id': 3},
        'log_item': {'log_id': 3, 'service': 'nginx', 'message': 'Worker process exited on signal 11 (Segmentation fault) with fatal exception', 'user': 'SYSTEM', 'computer': 'server01'}
    },
    {
        'scenario': '4. Generic Unclassified Windows Event Anomaly',
        'features': {'event_frequency': 0.60, 'sequence_length': 380.0, 'error_count': 0.0, 'error_pattern': 0.0, 'login_attempts': 0.0, 'failed_login_attempts': 0.0, 'warning_count': 0.0, 'unknown_events': 0.0, 'log_id': 4},
        'log_item': {'log_id': 4, 'service': 'CustomDeviceDriver', 'message': 'Device subsystem operational packet transmitted', 'user': 'SYSTEM', 'computer': 'server01'}
    }
]

df_scenarios = pd.DataFrame([s['features'] for s in test_scenarios])
preds_raw = detector.predict(df_scenarios)
preds = preds_raw[0] if isinstance(preds_raw, tuple) else preds_raw
parsed_items = [s['log_item'] for s in test_scenarios]

exps = ShapExplainerEngine.explain(model, df_scenarios, preds, parsed_logs=parsed_items)

for idx, s in enumerate(test_scenarios):
    exp = exps[idx]
    pred = preds[idx]
    print(f"\n--- SCENARIO {idx+1}: {s['scenario']} ---")
    print(f"  Raw Message       : {s['log_item']['message']}")
    print(f"  8 Input Features  : {s['features']}")
    print(f"  Decision Output   : is_anomaly={pred['is_anomaly']} | anomaly_score={pred['anomaly_score']:.4f} | severity={pred['severity']}")
    print(f"  Raw SHAP Contribs : {exp['feature_contributions']}")
    print(f"  Top Factor Rank 1 : {exp['top_3_human_reasons'][0] if exp['top_3_human_reasons'] else 'N/A'}")
    print(f"  Top Factor Rank 2 : {exp['top_3_human_reasons'][1] if len(exp['top_3_human_reasons']) > 1 else 'N/A'}")
    print(f"  Natural Exp Text  : \"{exp['natural_explanation']}\"")
    print(f"  Recommended Action: \"{exp['recommended_action']}\"")
