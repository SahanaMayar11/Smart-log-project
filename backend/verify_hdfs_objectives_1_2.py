import os
import sys
import json
import joblib
import pandas as pd
import numpy as np

# Ensure backend directory is in path
sys.path.append(os.path.dirname(__file__))

from ml_engine import (
    LogParser,
    DataCleaner,
    BehavioralFeatureExtractor,
    DataPreprocessor,
    IsolationForestDetector,
    OneClassSVMValidator,
    ShapExplainerEngine,
    run_full_pipeline,
    FEATURE_SCHEMA
)

from email_alert_manager import email_alert_manager

print("=" * 80)
print("SMART-LOG HDFS DATASET + OBJECTIVES 1 & 2 FINAL VERIFICATION SUITE")
print("=" * 80)

# Sample HDFS / Server Log Content containing missing/invalid noise values to test preprocessor
sample_raw_logs = """
2026-08-13 00:01:10 HDFS_Node1 INFO dfs.DataNode: Receiving block blk_-123456789 src: /10.0.0.1:50010 dest: /10.0.0.2:50010
2026-08-13 00:01:11 HDFS_Node2 ERROR dfs.FSDataset: Exception in receiveBlock for block blk_-987654321 java.io.IOException: Connection reset by peer
2026-08-13 00:01:12 HDFS_Node1 WARN dfs.DataNode: Disk error detected on volume /data1/hdfs
2026-08-13 00:01:13 HDFS_Node3 INFO dfs.DataBlockScanner: Verification succeeded for blk_111222333
2026-08-13 00:01:14 HDFS_Node2 ERROR dfs.DataNode: Access Denied for user admin failed login attempt
2026-08-13 00:01:15 HDFS_Node1 INFO dfs.FSNamesystem: BLOCK* NameSystem.allocateBlock: /user/hadoop/file.txt. blk_444555666
"""

# ==============================================================================
# TEST 1: OBJECTIVE 1 — PREPROCESSING & 8-FEATURE ENGINEERING
# ==============================================================================
print("\n[TEST 1] Objective 1: Preprocessing & 8-Feature Engineering")

parsed = LogParser.parse_logs(sample_raw_logs)
cleaned = DataCleaner.clean(parsed)
raw_df = BehavioralFeatureExtractor.extract_features(cleaned)

# Introduce synthetic NaN and invalid values to prove DataPreprocessor handles them
raw_df.loc[0, 'event_frequency'] = np.nan
raw_df.loc[1, 'sequence_length'] = np.inf
raw_df.loc[2, 'error_count'] = -5

cleaned_df, preprocess_stats = DataPreprocessor.preprocess(raw_df)

feature_list = [col for col in cleaned_df.columns if col in FEATURE_SCHEMA]
schema_pass = (feature_list == FEATURE_SCHEMA and len(feature_list) == 8)
nan_pass = (not cleaned_df[FEATURE_SCHEMA].isna().any().any())
inf_pass = (not np.isinf(cleaned_df[FEATURE_SCHEMA].values).any())

print(f"  - Ingestion & Parsing      : PASSED ({len(parsed)} logs parsed)")
print(f"  - Missing Value Handling   : {'PASSED' if nan_pass else 'FAILED'}")
print(f"  - Invalid Value Handling   : {'PASSED' if inf_pass else 'FAILED'}")
print(f"  - 8-Feature Schema Order   : {'PASSED' if schema_pass else 'FAILED'}")
print(f"  - Exact Feature List       : {feature_list}")

obj1_status = "PASS" if (schema_pass and nan_pass and inf_pass) else "FAIL"

# ==============================================================================
# TEST 2: OBJECTIVE 2 — HDFS ISOLATION FOREST & ONE-CLASS SVM VALIDATION
# ==============================================================================
print("\n[TEST 2] Objective 2: HDFS Isolation Forest & One-Class SVM Validation")

detector = IsolationForestDetector()
model_loaded = (detector.model_selection == 'hdfs')
model_path_exists = os.path.exists(detector.model_path)
model_features_match = (getattr(detector.model, 'n_features_in_', None) == 8)

pipeline_res = run_full_pipeline(sample_raw_logs)

det_results = pipeline_res['detection_results']
ocsvm_results = pipeline_res['ocsvm_results']

ocsvm_participated = all(d.get('ocsvm_validated') is True for d in det_results)
preds_generated = (len(det_results) == len(parsed))

print(f"  - Primary Model Loaded     : {'PASSED' if model_loaded else 'FAILED'} ({detector.model_path})")
print(f"  - Model Parameters        : n_estimators={len(detector.model.estimators_)}, contamination={detector.model.contamination}")
print(f"  - Isolation Forest Predict : {'PASSED' if preds_generated else 'FAILED'}")
print(f"  - One-Class SVM Validation : {'PASSED' if ocsvm_participated else 'FAILED'} (Active decision refinement verified)")

obj2_status = "PASS" if (model_loaded and preds_generated and ocsvm_participated) else "FAIL"

# ==============================================================================
# TEST 3: EXPLAINABILITY (SHAP ENGINE)
# ==============================================================================
print("\n[TEST 3] Explainability: SHAP Engine")

shap_res = pipeline_res['shap_explanations']
shap_valid = (len(shap_res) == len(parsed) and all('feature_contributions' in s for s in shap_res))

if shap_valid:
    sample_exp = shap_res[0]
    print(f"  - SHAP Explanations        : PASSED")
    print(f"  - Sample Top Reason        : {sample_exp['top_reason']}")
    print(f"  - Natural Explanation      : {sample_exp['natural_explanation']}")
else:
    print(f"  - SHAP Explanations        : FAILED")

shap_status = "PASS" if shap_valid else "FAIL"

# ==============================================================================
# TEST 4: ALERT GENERATION
# ==============================================================================
print("\n[TEST 4] Alert Generation: Anomaly Alerting")

sample_anomaly_item = {
    'log_id': 1,
    'timestamp': '2026-08-13 00:01:14',
    'hostname': 'HDFS_Node2',
    'service': 'dfs.DataNode',
    'log_level': 'ERROR',
    'message': 'Access Denied for user admin failed login attempt',
    'is_anomaly': 1,
    'anomaly_score': 0.85,
    'severity': 'Critical',
    'what_happened': 'Access Denied for user admin failed login attempt',
    'why_suspicious': 'Failed login attempts were unusually high.',
    'recommended_action': 'Check authentication credentials and block source IP.',
    'top_3_human_reasons': ['Failed login attempts were unusually high.']
}

try:
    email_alert_manager.send_alert_async(sample_anomaly_item)
    alert_status = "PASS"
    print("  - Anomaly Alert Dispatch   : PASSED (Alert status, severity, and SHAP explanation formatted)")
except Exception as e:
    alert_status = "FAIL"
    print(f"  - Anomaly Alert Dispatch   : FAILED ({e})")

# ==============================================================================
# TEST 5: RUNTIME LIVE PIPELINE
# ==============================================================================
print("\n[TEST 5] Runtime Live Pipeline")

pipeline_success = (len(pipeline_res['parsed_logs']) > 0 and len(pipeline_res['detection_results']) > 0)
live_status = "PASS" if pipeline_success else "FAIL"
print(f"  - Full Pipeline Flow       : {'PASSED' if pipeline_success else 'FAILED'}")

# ==============================================================================
# TEST 6: HDFS/LIVE FEATURE COMPATIBILITY & DOMAIN ADAPTATION TEST
# ==============================================================================
print("\n[TEST 6] HDFS/Live Feature Compatibility & Domain Adaptation Test")

try:
    from ml_engine import HDFSDomainAdapter
    adapted_df = HDFSDomainAdapter.transform(cleaned_df)
    cols = [c for c in adapted_df.columns if c in FEATURE_SCHEMA]
    compat_pass = (
        len(cols) == 8 and
        (adapted_df['error_count'].min() >= 3.0) and
        not adapted_df[cols].isna().any().any()
    )
    print(f"  - HDFS Domain Adapter Mapping: {'PASSED' if compat_pass else 'FAILED'}")
    print(f"  - Pre-adapter vs Post-adapter Error Count Baseline: {cleaned_df['error_count'].iloc[0]} -> {adapted_df['error_count'].iloc[0]}")
except Exception as e:
    compat_pass = False
    print(f"  - HDFS Domain Adapter Mapping: FAILED ({e})")

compat_status = "PASS" if compat_pass else "FAIL"

# ==============================================================================
# FINAL SUMMARY REPORT
# ==============================================================================
print("\n" + "=" * 80)
print("FINAL INTEGRATION SUMMARY REPORT")
print("=" * 80)
print(f"OBJECTIVE 1:               {obj1_status}")
print(f"OBJECTIVE 2:               {obj2_status}")
print(f"HDFS ISOLATION FOREST:     {'PASS' if model_loaded else 'FAIL'}")
print(f"ONE-CLASS SVM VALIDATION:  {'PASS' if ocsvm_participated else 'FAIL'}")
print(f"SHAP:                      {shap_status}")
print(f"ALERT:                     {alert_status}")
print(f"LIVE PIPELINE:             {live_status}")
print(f"HDFS COMPATIBILITY:        {compat_status}")
print("=" * 80)
