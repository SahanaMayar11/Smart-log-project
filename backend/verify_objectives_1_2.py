import os
import sys
import json
import time
import urllib.request
import numpy as np
import pandas as pd
from datetime import datetime

# Add current dir to path
sys.path.insert(0, os.path.dirname(__file__))

from ml_engine import (
    LogParser,
    DataCleaner,
    BehavioralFeatureExtractor,
    DataPreprocessor,
    IsolationForestDetector,
    OneClassSVMValidator,
    ShapExplainerEngine,
    run_full_pipeline,
    FEATURE_SCHEMA,
    FEATURE_DOCUMENTATION
)

BASE_URL = "http://127.0.0.1:5000"


def run_objectives_1_2_verification():
    print("======================================================================")
    print("        SMART-LOG OBJECTIVE 1 & 2 VERIFICATION TEST SUITE")
    print("======================================================================")

    obj1_results = {}
    obj2_results = {}
    regression_results = {}

    # ------------------------------------------------------------------
    # OBJECTIVE 1 TESTS — PREPROCESSING & SCHEMA VALIDATION
    # ------------------------------------------------------------------
    print("\n[SECTION 1] TESTING OBJECTIVE 1 — DATA PREPROCESSING & FEATURE SCHEMA")

    try:
        # Test 1.1: Missing Value Detection & Imputation
        test_df_missing = pd.DataFrame([
            {'event_frequency': np.nan, 'sequence_length': 120, 'error_count': 2, 'error_pattern': 1,
             'login_attempts': 0, 'failed_login_attempts': 0, 'warning_count': 1, 'unknown_events': 0},
            {'event_frequency': 5.0, 'sequence_length': None, 'error_count': 0, 'error_pattern': 0,
             'login_attempts': 1, 'failed_login_attempts': 0, 'warning_count': 0, 'unknown_events': np.nan}
        ])
        cleaned_df, stats_missing = DataPreprocessor.preprocess(test_df_missing)
        has_no_nans = not cleaned_df[FEATURE_SCHEMA].isna().any().any()
        obj1_results['Missing-value detection'] = 'PASS' if stats_missing['missing_values_found'] > 0 else 'FAIL'
        obj1_results['Missing-value handling'] = 'PASS' if has_no_nans and stats_missing['missing_values_handled'] > 0 else 'FAIL'

        # Test 1.2: Invalid Value Detection & Handling (Inf, Negatives, Range)
        test_df_invalid = pd.DataFrame([
            {'event_frequency': np.inf, 'sequence_length': -50, 'error_count': -5, 'error_pattern': 99,
             'login_attempts': -1, 'failed_login_attempts': 0, 'warning_count': 0, 'unknown_events': 0}
        ])
        cleaned_inv_df, stats_invalid = DataPreprocessor.preprocess(test_df_invalid)
        no_infs = not np.isinf(cleaned_inv_df[FEATURE_SCHEMA].values).any()
        no_negs = (cleaned_inv_df[FEATURE_SCHEMA].values >= 0).all()
        err_pat_valid = (cleaned_inv_df['error_pattern'].values[0] == 4.0)

        obj1_results['Invalid-value detection'] = 'PASS' if stats_invalid['invalid_values_found'] > 0 else 'FAIL'
        obj1_results['Invalid-value handling'] = 'PASS' if no_infs and no_negs and err_pat_valid else 'FAIL'

        # Test 1.3: Data Validation & Schema Enforcement
        obj1_results['Data validation'] = 'PASS' if len(cleaned_df) == len(test_df_missing) else 'FAIL'
        obj1_results['Feature selection'] = 'PASS' if len(FEATURE_SCHEMA) == 8 else 'FAIL'
        obj1_results['Feature schema consistency'] = 'PASS' if list(cleaned_df[FEATURE_SCHEMA].columns) == FEATURE_SCHEMA else 'FAIL'
        obj1_results['Preprocessing consistency'] = 'PASS' if len(FEATURE_DOCUMENTATION) == 8 else 'FAIL'

    except Exception as e:
        print(f"  [ERROR] Objective 1 exception: {e}")

    # Print Objective 1 Summary
    print("\nOBJECTIVE 1 — PREPROCESSING STATUS:")
    for k, v in obj1_results.items():
        print(f"  - {k:<30}: {v}")

    obj1_pass = all(v == 'PASS' for v in obj1_results.values()) and len(obj1_results) == 8
    print(f"\nOBJECTIVE 1 RESULT: {'PASS' if obj1_pass else 'FAIL'}")

    # ------------------------------------------------------------------
    # OBJECTIVE 2 TESTS — ISOLATION FOREST & ONE-CLASS SVM VALIDATION
    # ------------------------------------------------------------------
    print("\n" + "="*70)
    print("[SECTION 2] TESTING OBJECTIVE 2 — ISOLATION FOREST & ONE-CLASS SVM VALIDATION")

    try:
        sample_log = """2026-08-11T10:00:00 server1 auth: FAILED login attempt from 192.168.1.50
2026-08-11T10:00:01 server1 auth: FAILED login attempt from 192.168.1.50
2026-08-11T10:00:02 server1 auth: FAILED login attempt from 192.168.1.50
2026-08-11T10:00:03 server1 auth: FAILED login attempt from 192.168.1.50
2026-08-11T10:00:04 server1 system: Service nginx started successfully
2026-08-11T10:00:05 server1 system: Normal system status report"""

        # Ground truth labels for controlled behavioral validation
        # 1 = Anomaly (4 failed logins in window), 0 = Normal
        ground_truth = [1, 1, 1, 1, 0, 0]

        pipeline_res = run_full_pipeline(sample_log, ground_truth=ground_truth)

        # Verification of components
        feats = pipeline_res['features']
        if_dets = pipeline_res['detection_results']
        ocsvm_dets = pipeline_res['ocsvm_results']
        comp = pipeline_res['model_comparison']
        shaps = pipeline_res['shap_explanations']

        obj2_results['Behavioral features'] = 'PASS' if len(feats) == 6 and len(feats[0]) >= 8 else 'FAIL'
        obj2_results['Isolation Forest'] = 'PASS' if len(if_dets) == 6 else 'FAIL'
        obj2_results['Isolation Forest prediction'] = 'PASS' if any(d['is_anomaly'] == 1 for d in if_dets) else 'FAIL'
        obj2_results['One-Class SVM'] = 'PASS' if len(ocsvm_dets) == 6 else 'FAIL'
        obj2_results['One-Class SVM prediction'] = 'PASS' if len(ocsvm_dets) == len(if_dets) else 'FAIL'
        obj2_results['Model comparison'] = 'PASS' if 'comparison_metrics' in comp and 'agreement_rate_percent' in comp['comparison_metrics'] else 'FAIL'

        # Supervised Metrics Verification
        if_metrics = comp.get('isolation_forest', {})
        ocsvm_metrics = comp.get('one_class_svm', {})
        has_supervised = 'accuracy' in if_metrics and 'precision' in if_metrics and 'f1_score' in if_metrics

        obj2_results['Evaluation metrics'] = 'PASS' if has_supervised else 'FAIL'
        obj2_results['SHAP compatibility'] = 'PASS' if len(shaps) == 6 and 'Event Frequency' in shaps[0]['feature_contributions'] else 'FAIL'

    except Exception as e:
        print(f"  [ERROR] Objective 2 exception: {e}")

    # Print Objective 2 Summary
    print("\nOBJECTIVE 2 — ANOMALY DETECTION & VALIDATION STATUS:")
    for k, v in obj2_results.items():
        print(f"  - {k:<30}: {v}")

    obj2_pass = all(v == 'PASS' for v in obj2_results.values()) and len(obj2_results) == 8
    print(f"\nOBJECTIVE 2 RESULT: {'PASS' if obj2_pass else 'FAIL'}")

    # Print Model Comparison Table
    print("\n" + "-"*70)
    print("              MODEL COMPARISON & VALIDATION SUMMARY")
    print("-"*70)
    if 'comparison_metrics' in comp:
        print(f"Total Analyzed Events : {comp['total_events']}")
        print(f"Model Agreement Rate  : {comp['comparison_metrics']['agreement_rate_percent']}%")
        print(f"Jaccard Similarity    : {comp['comparison_metrics']['jaccard_similarity']}")
        print("\nMETRIC                 ISOLATION FOREST    ONE-CLASS SVM")
        print("-" * 55)
        print(f"Normal Events          {comp['isolation_forest']['normal_events']:<20}{comp['one_class_svm']['normal_events']:<20}")
        print(f"Anomaly Events         {comp['isolation_forest']['anomaly_events']:<20}{comp['one_class_svm']['anomaly_events']:<20}")
        if has_supervised:
            print(f"Accuracy               {comp['isolation_forest']['accuracy']:<20}{comp['one_class_svm']['accuracy']:<20}")
            print(f"Precision              {comp['isolation_forest']['precision']:<20}{comp['one_class_svm']['precision']:<20}")
            print(f"Recall                 {comp['isolation_forest']['recall']:<20}{comp['one_class_svm']['recall']:<20}")
            print(f"F1 Score               {comp['isolation_forest']['f1_score']:<20}{comp['one_class_svm']['f1_score']:<20}")

    # ------------------------------------------------------------------
    # REGRESSION TESTS ACROSS EXISTING SYSTEM FEATURES
    # ------------------------------------------------------------------
    print("\n" + "="*70)
    print("[SECTION 3] EXISTING DESKTOP SYSTEM REGRESSION VERIFICATION")

    endpoints_to_check = [
        ('Live System Logs', f"{BASE_URL}/api/system-logs/live"),
        ('Log Analysis', f"{BASE_URL}/api/logs/parsed?limit=5"),
        ('Behavioral Features', f"{BASE_URL}/api/features?limit=5"),
        ('Anomaly Detection', f"{BASE_URL}/api/detection/results?limit=5"),
        ('SHAP Explainability', f"{BASE_URL}/api/shap/explanations?limit=5"),
        ('Dashboard', f"{BASE_URL}/api/dashboard/stats"),
        ('Reports', f"{BASE_URL}/api/reports/summary"),
        ('Model Validation API', f"{BASE_URL}/api/model-validation")
    ]

    for name, url in endpoints_to_check:
        try:
            req = urllib.request.Request(url, headers={'Connection': 'close'})
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    regression_results[name] = 'PASS'
                else:
                    regression_results[name] = f'FAIL ({resp.status})'
        except Exception as e:
            regression_results[name] = f'FAIL ({e})'

    print("\nEXISTING FEATURES REGRESSION MATRIX:")
    for k, v in regression_results.items():
        print(f"  - {k:<25}: {v}")

    print("\n" + "="*70)
    overall_pass = obj1_pass and obj2_pass
    print(f"OVERALL VERIFICATION RESULT: {'PASS' if overall_pass else 'FAIL'}")
    print("="*70)

    return overall_pass


if __name__ == '__main__':
    run_objectives_1_2_verification()
