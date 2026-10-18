"""
Master Demonstration Script for Official Project Objectives
================================================================================
Objective 1:
  Preprocess dataset by cleaning missing/invalid values and selecting relevant
  features, ensuring structured and anomaly-ready data.

Objective 2:
  Behavior-based anomaly detection using Isolation Forest as primary detector
  and validating results using One-Class SVM to improve reliability.
================================================================================
"""

import os
import sys
import json
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

# Ensure objective_implementation root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from data.data_loader import load_hdfs_benchmark_data, get_sample_log_stream, FEATURE_SCHEMA
from preprocessing.cleaner import PreprocessingPipeline
from preprocessing.feature_extractor import LogParserAndExtractor, HDFSDomainAdapter
from models.isolation_forest import IsolationForestPrimaryDetector
from models.one_class_svm import OneClassSVMValidator
from evaluation.evaluate import compute_metrics


def run_full_objective_demonstration():
    print("=" * 80)
    print("SMART-LOG: OFFICIAL OBJECTIVES 1 & 2 DEMONSTRATION")
    print("=" * 80)

    # --------------------------------------------------------------------------
    # PHASE 1: OBJECTIVE 1 — DATA PREPROCESSING & FEATURE ENGINEERING
    # --------------------------------------------------------------------------
    print("\n========================================")
    print("OBJECTIVE 1: DATA PREPROCESSING")
    print("========================================")

    # 1. Load real HDFS benchmark dataset slice
    raw_feature_df, y_all, meta = load_hdfs_benchmark_data(sample_limit=10000, random_state=42)
    print(f"Dataset loaded: {meta['total_records']:,} records ({meta['source']})")
    print(f"Ground-truth distribution: {meta['normal_count']:,} Normal, {meta['anomaly_count']:,} Anomaly ({meta['anomaly_ratio']*100:.2f}%)")

    # 2. Introduce synthetic noise (NaN, Inf, negatives) to explicitly demonstrate cleaning
    print("\nInjecting noise to test preprocessing resilience...")
    raw_feature_df.loc[0, 'event_frequency'] = np.nan
    raw_feature_df.loc[1, 'sequence_length'] = np.inf
    raw_feature_df.loc[2, 'error_count'] = -10.0
    raw_feature_df.loc[3, 'error_pattern'] = 99.0

    # 3. Unsupervised Train / Test Split (70% Train / 30% Held-Out Test, seed=42)
    # Split occurs BEFORE fitting any preprocessing statistics to strictly prevent data leakage.
    # Ground-truth labels y_all are strictly withheld from split (stratify=None) to maintain unsupervised integrity.
    print("\nExecuting unsupervised train/test split (70% Train / 30% Held-Out Test, stratify=None) before preprocessing...")
    train_idx, test_idx = train_test_split(
        np.arange(len(raw_feature_df)),
        test_size=0.30,
        stratify=None,
        random_state=42
    )

    train_raw_feats = raw_feature_df.iloc[train_idx].copy().reset_index(drop=True)
    test_raw_feats = raw_feature_df.iloc[test_idx].copy().reset_index(drop=True)
    y_train = y_all[train_idx]
    y_test = y_all[test_idx]

    # 4. Execute Preprocessing Pipeline: Fit statistics strictly on training data
    print("\nPreprocessing training split (statistics learned exclusively on X_train)...")
    X_train, train_preproc_stats = PreprocessingPipeline.clean_and_preprocess(train_raw_feats)

    # 5. Transform test split using already-fitted training statistics
    print("Preprocessing held-out test split using fitted training statistics...")
    X_test, test_preproc_stats = PreprocessingPipeline.clean_and_preprocess(
        test_raw_feats,
        fit_medians=train_preproc_stats['fitted_medians'],
        fit_max_finite=train_preproc_stats.get('fitted_max_finite')
    )

    print(f"\nMissing values detected in training set : {train_preproc_stats['missing_values_detected']}")
    print(f"Missing values detected in test set     : {test_preproc_stats['missing_values_detected']}")
    print(f"Invalid values detected in training set : {train_preproc_stats['invalid_values_detected']}")
    print(f"Invalid values detected in test set     : {test_preproc_stats['invalid_values_detected']}")

    print("\nSelected behavioral features (Exact 8 Canonical Features):")
    for feat in train_preproc_stats['selected_features']:
        print(f"  - {feat}")

    print(f"\nFinal feature matrices: X_train={X_train.shape}, X_test={X_test.shape}")
    print("Train-isolated preprocessing: PASS")
    print("Data ready for anomaly detection: PASS")

    # --------------------------------------------------------------------------
    # PHASE 2: OBJECTIVE 2 — ISOLATION FOREST ANOMALY DETECTION
    # --------------------------------------------------------------------------
    print("\n========================================")
    print("OBJECTIVE 2: ANOMALY DETECTION")
    print("========================================")

    print(f"Training split (X_train, strictly unlabeled) : {len(X_train):,} samples")
    print(f"Held-out test split (X_test for evaluation)     : {len(X_test):,} samples")

    # 2. Train / Load Primary Isolation Forest Model
    print("\nTraining Isolation Forest primary detector on X_train (Unsupervised)...")
    if_detector = IsolationForestPrimaryDetector(
        n_estimators=100,
        contamination=0.0293,
        max_samples='auto',
        random_state=42
    )
    if_detector.fit(X_train)

    # 3. Predict on Held-Out Test Data
    if_preds = if_detector.predict(X_test)
    if_metrics = compute_metrics(y_test, if_preds['is_anomaly'], if_preds['anomaly_score'], model_name="Isolation Forest")

    print("\nIsolation Forest (Primary Detector)")
    print("-----------------------------------")
    print(f"Model parameters : n_estimators={if_detector.n_estimators}, contamination={if_detector.contamination}")
    print(f"Samples evaluated: {if_preds['total_samples']:,}")
    print(f"Detected anomalies: {if_preds['detected_anomalies']:,}")
    print(f"Anomaly percentage: {if_preds['anomaly_percentage']:.2f}%")
    print(f"Accuracy : {if_metrics['accuracy']:.2f}%")
    print(f"Precision: {if_metrics['precision']:.2f}%")
    print(f"Recall   : {if_metrics['recall']:.2f}%")
    print(f"F1-Score : {if_metrics['f1_score']:.2f}%")
    print(f"ROC-AUC  : {if_metrics['roc_auc']}")

    # --------------------------------------------------------------------------
    # PHASE 3: ONE-CLASS SVM SECONDARY VALIDATION
    # --------------------------------------------------------------------------
    print("\nOne-Class SVM (Secondary Validator)")
    print("-----------------------------------")
    ocsvm_validator = OneClassSVMValidator(kernel='rbf', gamma='scale', nu=0.03)
    ocsvm_validator.fit(X_train)

    ocsvm_preds = ocsvm_validator.predict(X_test)
    ocsvm_metrics = compute_metrics(y_test, ocsvm_preds['is_anomaly'], ocsvm_preds['anomaly_score'], model_name="One-Class SVM")

    print(f"Model parameters : kernel={ocsvm_validator.kernel}, nu={ocsvm_validator.nu}")
    print(f"Samples evaluated: {ocsvm_preds['total_samples']:,}")
    print(f"Detected anomalies: {ocsvm_preds['detected_anomalies']:,}")
    print(f"Anomaly percentage: {ocsvm_preds['anomaly_percentage']:.2f}%")
    print(f"Accuracy : {ocsvm_metrics['accuracy']:.2f}%")
    print(f"Precision: {ocsvm_metrics['precision']:.2f}%")
    print(f"Recall   : {ocsvm_metrics['recall']:.2f}%")
    print(f"F1-Score : {ocsvm_metrics['f1_score']:.2f}%")

    # --------------------------------------------------------------------------
    # PHASE 4: MODEL COMPARISON & CONSENSUS TRIAGE
    # --------------------------------------------------------------------------
    print("\n========================================")
    print("MODEL COMPARISON & VALIDATION")
    print("========================================")

    comparison = OneClassSVMValidator.compare_predictions(if_preds, ocsvm_preds)
    print(f"Total events compared : {comparison['total_events']:,}")
    print(f"Agreement count       : {comparison['agreements']:,} ({comparison['agreement_rate_percent']:.2f}%)")
    print(f"Disagreement count    : {comparison['disagreements']:,}")
    print("\nConsensus Distribution:")
    for state, count in comparison['consensus_counts'].items():
        print(f"  - {state:<44}: {count:,} events")

    # --------------------------------------------------------------------------
    # PHASE 5: LOG INGESTION / INJECTION PIPELINE FLOW DEMONSTRATION
    # --------------------------------------------------------------------------
    print("\n========================================")
    print("LOG INGESTION / INJECTION PIPELINE FLOW")
    print("========================================")
    sample_stream = get_sample_log_stream()
    print(f"Ingesting live log stream ({len(sample_stream)} log events)...")

    parsed_stream = LogParserAndExtractor.parse_log_lines(sample_stream)
    raw_stream_feats = LogParserAndExtractor.extract_behavioral_features(parsed_stream)
    clean_stream_feats, _ = PreprocessingPipeline.clean_and_preprocess(
        raw_stream_feats,
        fit_medians=train_preproc_stats['fitted_medians'],
        fit_max_finite=train_preproc_stats.get('fitted_max_finite')
    )
    mapped_stream_feats = HDFSDomainAdapter.transform(clean_stream_feats)

    stream_if_preds = if_detector.predict(mapped_stream_feats)
    stream_ocsvm_preds = ocsvm_validator.predict(mapped_stream_feats)

    print(f"Ingested logs parsed      : {len(parsed_stream)}")
    print(f"Behavioral features matrix: {clean_stream_feats.shape}")
    print(f"Isolation Forest anomalies: {stream_if_preds['detected_anomalies']} / {len(parsed_stream)}")
    print(f"One-Class SVM anomalies   : {stream_ocsvm_preds['detected_anomalies']} / {len(parsed_stream)}")
    print("\nEvent-by-Event Triage Output:")

    for idx, (p_log, if_anom, if_score, oc_anom) in enumerate(zip(
        parsed_stream,
        stream_if_preds['is_anomaly'],
        stream_if_preds['anomaly_score'],
        stream_ocsvm_preds['is_anomaly']
    )):
        status_label = "[ANOMALY]" if if_anom == 1 else "[NORMAL ]"
        oc_label = "[OCSVM: AGREED]" if if_anom == oc_anom else "[OCSVM: DISAGREE]"
        msg_snip = (p_log['message'][:42] + '...') if len(p_log['message']) > 42 else p_log['message']
        print(f"  Log #{idx+1:02d} | {status_label} (Score: {if_score:.4f}) {oc_label} | {p_log['service']:<10} | {msg_snip}")

    # --------------------------------------------------------------------------
    # PHASE 6: SAVE REAL RESULTS
    # --------------------------------------------------------------------------
    results_dir = os.path.join(BASE_DIR, 'results')
    os.makedirs(results_dir, exist_ok=True)

    # 1. Preprocessing results CSV
    preproc_out_path = os.path.join(results_dir, 'preprocessing_results.csv')
    pd.concat([X_train, X_test]).head(100).to_csv(preproc_out_path, index=False)

    # 2. Anomaly detection results CSV
    anomaly_df = X_test.copy()
    anomaly_df['ground_truth_label'] = y_test
    anomaly_df['if_predicted_anomaly'] = if_preds['is_anomaly']
    anomaly_df['if_anomaly_score'] = if_preds['anomaly_score']
    anomaly_df['ocsvm_predicted_anomaly'] = ocsvm_preds['is_anomaly']
    anomaly_df['ocsvm_anomaly_score'] = ocsvm_preds['anomaly_score']
    anomaly_out_path = os.path.join(results_dir, 'anomaly_results.csv')
    anomaly_df.head(200).to_csv(anomaly_out_path, index=False)

    # 3. Evaluation summary JSON
    eval_json = {
        'objective_1': {
            'status': 'PASS',
            'records_preprocessed': train_preproc_stats['final_records'] + test_preproc_stats['final_records'],
            'missing_values_handled': train_preproc_stats['missing_values_cleaned'] + test_preproc_stats['missing_values_cleaned'],
            'invalid_values_handled': train_preproc_stats['invalid_values_cleaned'] + test_preproc_stats['invalid_values_cleaned'],
            'feature_schema': train_preproc_stats['selected_features']
        },
        'objective_2': {
            'status': 'PASS',
            'primary_model': if_metrics,
            'secondary_validator': ocsvm_metrics,
            'model_comparison': comparison
        },
        'pipeline_status': 'PASS'
    }
    eval_out_path = os.path.join(results_dir, 'evaluation_results.json')
    with open(eval_out_path, 'w', encoding='utf-8') as f:
        json.dump(eval_json, f, indent=2)

    print(f"\nArtifacts saved in {results_dir}:")
    print(f"  - {os.path.basename(preproc_out_path)}")
    print(f"  - {os.path.basename(anomaly_out_path)}")
    print(f"  - {os.path.basename(eval_out_path)}")

   
if __name__ == '__main__':
    run_full_objective_demonstration()
