"""
Smart-Log: Standardized Evaluation and Ablation Pipeline
================================================================================
Evaluation Methodology & Dataset Documentation:
- Dataset Name: Constructed Syslog Scenario Evaluation Dataset
- Dataset Nature: Deterministically constructed from realistic syslog scenario
  templates representing normal system operations and common attack vectors.
  Labels are derived directly from the deterministic scenario generation rules
  because this repository does not contain native human-annotated syslog ground truth.
- Objective: Reproducible, leakage-free benchmark comparing:
    * Experiment 1: Isolation Forest (Primary Baseline)
    * Experiment 2: Isolation Forest + One-Class SVM Validation (Consensus Strategy)
    * Experiment 3: One-Class SVM (Comparative Baseline)
- Output Artifacts:
    * backend/evaluation_results.json
    * backend/results.csv
================================================================================
"""

import os
import sys
import json
import csv
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix
)

# Ensure backend directory is in python path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from ml_engine import (
    LogParser,
    DataCleaner,
    BehavioralFeatureExtractor,
    DataPreprocessor,
    OneClassSVMValidator,
    FEATURE_SCHEMA
)


def build_constructed_evaluation_dataset(seed=42):
    """
    Constructs a deterministic 1,000-sample scenario evaluation dataset.
    750 Normal system operations (Label=0) and 250 Anomalous attack events (Label=1).
    All labels originate from unambiguous scenario generation templates.
    """
    np.random.seed(seed)

    users = ['admin', 'ubuntu', 'developer', 'root', 'guest', 'sysadmin', 'oracle', 'postgres', 'deploy', 'service']
    services = ['nginx', 'sshd', 'systemd', 'CRON', 'mysql', 'docker', 'postfix', 'kernel', 'sudo', 'ufw']
    cmds = ['sysstat-collector', 'backup-db', 'logrotate', 'disk-check', 'certbot-renew', 'cleanup-tmp']
    domains = ['example.com', 'test.org', 'internal.net', 'company.com']
    endpoints = ['health', 'users', 'data', 'metrics', 'status', 'api/v1/auth', 'static/css/main.css', 'index.html']

    logs = []
    labels = []  # 0: Normal, 1: Anomaly

    # --- 1. Normal Server Operations (750 records) ---
    for i in range(750):
        h = str(np.random.randint(1, 15)).zfill(2)
        m = str(np.random.randint(0, 60)).zfill(2)
        s = str(np.random.randint(0, 60)).zfill(2)
        time_str = f"10:{m}:{s}"
        pid = np.random.randint(1000, 9999)
        ip = f"192.168.1.{np.random.randint(2, 250)}"
        port = np.random.randint(10000, 60000)
        user = np.random.choice(users)
        service = np.random.choice(services)
        cmd = np.random.choice(cmds)
        domain = np.random.choice(domains)
        endpoint = np.random.choice(endpoints)
        uptime = f"{np.random.randint(100, 9999)}.{np.random.randint(100, 999)}"

        category = i % 7
        if category == 0:
            line = f"2026-08-08T{time_str} server-{h} systemd[1]: Started {service} service daemon."
        elif category == 1:
            line = f"2026-08-08T{time_str} server-{h} sshd[{pid}]: Accepted publickey for {user} from {ip} port {port} ssh2"
        elif category == 2:
            line = f"2026-08-08T{time_str} server-{h} CRON[{pid}]: (root) CMD ({cmd})"
        elif category == 3:
            line = f"2026-08-08T{time_str} server-{h} nginx[{pid}]: 2026/08/08 {time_str} [info] {pid}#0: GET /{endpoint} 200 OK"
        elif category == 4:
            line = f"2026-08-08T{time_str} server-{h} kernel[0]: [{uptime}] Firewall: IN=eth0 OUT= SRC=10.0.0.{np.random.randint(2, 250)} DST=192.168.1.1 PROTO=TCP SPT={port} DPT=80 SYN"
        elif category == 5:
            line = f"2026-08-08T{time_str} server-{h} sudo[{pid}]: pam_unix(sudo:session): session opened for user root by {user}"
        else:
            line = f"2026-08-08T{time_str} server-{h} postfix/cleanup[{pid}]: info: header Subject: normal system status report from admin@{domain}"

        logs.append(line)
        labels.append(0)

    # --- 2. Anomalous Attack Events (250 records) ---
    for i in range(250):
        h = str(np.random.randint(1, 15)).zfill(2)
        m = str(np.random.randint(0, 60)).zfill(2)
        s = str(np.random.randint(0, 60)).zfill(2)
        time_str = f"10:{m}:{s}"
        pid = np.random.randint(1000, 9999)
        ip = f"198.51.100.{np.random.randint(2, 250)}"
        port = np.random.randint(10000, 60000)
        user = np.random.choice(['admin', 'root', 'oracle', 'postgres', 'invalid_user', 'hacker'])
        service = np.random.choice(services)
        uptime = f"{np.random.randint(100, 9999)}.{np.random.randint(100, 999)}"

        category = i % 6
        if category == 0:
            line = f"2026-08-08T{time_str} server-{h} sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2"
        elif category == 1:
            line = f"2026-08-08T{time_str} server-{h} auth[{pid}]: UNKNOWN_EVENT: Buffer overflow attempt in authentication packet header from {ip}"
        elif category == 2:
            line = f"2026-08-08T{time_str} server-{h} kernel[0]: [{uptime}] Out of memory: Kill process {pid} ({service}) score 950 or sacrifice child"
        elif category == 3:
            line = f"2026-08-08T{time_str} server-{h} nginx[{pid}]: 2026/08/08 {time_str} [error] {pid}#0: *{pid} open() \"/etc/shadow\" failed (13: Permission denied)"
        elif category == 4:
            line = f"2026-08-08T{time_str} server-{h} kernel[0]: [{uptime}] audit: type=1400 audit({time_str}): apparmor=\"DENIED\" operation=\"exec\" name=\"/tmp/exploit.sh\""
        else:
            line = f"2026-08-08T{time_str} server-{h} auth[{pid}]: UNKNOWN_EVENT: Privilege escalation exploit detected from user {user}"

        logs.append(line)
        labels.append(1)

    raw_df = pd.DataFrame({'log_line': logs, 'label': labels})
    raw_df = raw_df.drop_duplicates(subset=['log_line']).reset_index(drop=True)
    return raw_df


def compute_metrics(y_true, y_pred, scores=None):
    """Computes full suite of classification and rate metrics without hardcoding."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    roc_auc = None
    pr_auc = None
    if scores is not None:
        try:
            roc_auc = float(roc_auc_score(y_true, scores))
            pr_auc = float(average_precision_score(y_true, scores))
        except Exception:
            pass

    return {
        'accuracy': round(acc, 4),
        'precision': round(prec, 4),
        'recall': round(rec, 4),
        'f1_score': round(f1, 4),
        'roc_auc': round(roc_auc, 4) if roc_auc is not None else 'N/A',
        'pr_auc': round(pr_auc, 4) if pr_auc is not None else 'N/A',
        'false_positive_rate': round(fpr, 4),
        'false_negative_rate': round(fnr, 4),
        'confusion_matrix': {
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'true_positives': int(tp)
        }
    }


def run_standardized_evaluation():
    print("=" * 80)
    print("SMART-LOG: STANDARDIZED REPRODUCIBLE EVALUATION & ABLATION STUDY")
    print("=" * 80)

    # 1. Dataset generation & documentation
    print("\n[PHASE 1] Loading Constructed Syslog Scenario Evaluation Dataset...")
    df_raw = build_constructed_evaluation_dataset(seed=42)
    total_records = len(df_raw)
    total_anom = int(df_raw['label'].sum())
    total_norm = total_records - total_anom

    print(f"  - Dataset Name           : Constructed Syslog Scenario Evaluation Dataset")
    print(f"  - Total Unique Records   : {total_records}")
    print(f"  - Normal Operational Logs: {total_norm} ({(total_norm/total_records)*100:.1f}%)")
    print(f"  - Anomalous Attack Logs  : {total_anom} ({(total_anom/total_records)*100:.1f}%)")
    print(f"  - Ground Truth Nature    : Deterministic scenario templates (No fabricated external labels)")

    # 2. Parsing, cleaning, and feature extraction
    print("\n[PHASE 2] Parsing logs & extracting 8 canonical behavioral features...")
    parsed_logs = LogParser.parse_logs("\n".join(df_raw['log_line'].tolist()))
    cleaned_logs = DataCleaner.clean(parsed_logs)
    raw_feature_df = BehavioralFeatureExtractor.extract_features(cleaned_logs)

    # 3. Train/Test Split (70% Train / 30% Test) without Label Stratification
    print("\n[PHASE 3] Splitting dataset (70% Train / 30% Held-Out Test, unstratified, seed=42)...")
    indices = np.arange(total_records)
    train_idx, test_idx = train_test_split(
        indices, test_size=0.30, random_state=42, stratify=None
    )

    train_raw_feats = raw_feature_df.iloc[train_idx].copy().reset_index(drop=True)
    test_raw_feats = raw_feature_df.iloc[test_idx].copy().reset_index(drop=True)
    y_train = df_raw['label'].values[train_idx]
    y_test = df_raw['label'].values[test_idx]

    print(f"  - Training Samples       : {len(train_raw_feats)} (Anomalies: {int(y_train.sum())})")
    print(f"  - Held-Out Test Samples  : {len(test_raw_feats)} (Anomalies: {int(y_test.sum())})")

    # 4. Data Preprocessing with Strict Leakage Protection
    print("\n[PHASE 4] Preprocessing with strict data leakage protection...")
    train_cleaned_df, train_stats = DataPreprocessor.preprocess(train_raw_feats)
    train_fitted_medians = train_stats['fitted_medians']

    # Apply training medians to test split
    test_cleaned_df, test_stats = DataPreprocessor.preprocess(test_raw_feats, fit_medians=train_fitted_medians)

    X_train = train_cleaned_df[FEATURE_SCHEMA].values
    X_test = test_cleaned_df[FEATURE_SCHEMA].values

    # Assert no NaNs or Infs
    assert not np.isnan(X_train).any() and not np.isinf(X_train).any(), "NaN/Inf in training feature matrix!"
    assert not np.isnan(X_test).any() and not np.isinf(X_test).any(), "NaN/Inf in test feature matrix!"
    print(f"  - Canonical Feature Schema: {', '.join(FEATURE_SCHEMA)}")
    print(f"  - Leakage Protection     : PASSED (Training medians applied to held-out test split)")

    # =========================================================================
    # EXPERIMENT 1: ISOLATION FOREST ALONE (PRIMARY MODEL)
    # =========================================================================
    print("\n[EXPERIMENT 1] Evaluating Isolation Forest Alone (Primary Baseline)...")
    if_clf = IsolationForest(n_estimators=100, contamination=0.25, random_state=42, max_samples='auto')
    if_clf.fit(X_train)

    if_test_preds = if_clf.predict(X_test)
    if_y_pred = np.where(if_test_preds == -1, 1, 0)
    if_raw_scores = if_clf.decision_function(X_test)
    # Normalized score where higher is more anomalous
    if_norm_scores = np.clip(1.0 - (if_raw_scores + 0.5), 0.0, 1.0)

    if_metrics = compute_metrics(y_test, if_y_pred, scores=if_norm_scores)
    print(f"  - Accuracy: {if_metrics['accuracy']*100:.2f}% | Precision: {if_metrics['precision']*100:.2f}% | Recall: {if_metrics['recall']*100:.2f}% | F1: {if_metrics['f1_score']*100:.2f}%")
    print(f"  - ROC-AUC : {if_metrics['roc_auc']} | PR-AUC: {if_metrics['pr_auc']} | FPR: {if_metrics['false_positive_rate']*100:.2f}% | FNR: {if_metrics['false_negative_rate']*100:.2f}%")

    # =========================================================================
    # EXPERIMENT 3: ONE-CLASS SVM ALONE (COMPARATIVE BASELINE)
    # =========================================================================
    print("\n[EXPERIMENT 3] Evaluating One-Class SVM Alone (Comparative Baseline)...")
    # Features scaled with StandardScaler fitted strictly on training data
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    ocsvm_clf = OneClassSVM(nu=0.25, kernel='rbf', gamma='scale')
    ocsvm_clf.fit(X_train_scaled)

    ocsvm_test_preds = ocsvm_clf.predict(X_test_scaled)
    ocsvm_y_pred = np.where(ocsvm_test_preds == -1, 1, 0)
    ocsvm_raw_scores = ocsvm_clf.decision_function(X_test_scaled)
    ocsvm_norm_scores = np.clip(1.0 - (ocsvm_raw_scores + 0.5), 0.0, 1.0)

    ocsvm_metrics = compute_metrics(y_test, ocsvm_y_pred, scores=ocsvm_norm_scores)
    print(f"  - Accuracy: {ocsvm_metrics['accuracy']*100:.2f}% | Precision: {ocsvm_metrics['precision']*100:.2f}% | Recall: {ocsvm_metrics['recall']*100:.2f}% | F1: {ocsvm_metrics['f1_score']*100:.2f}%")
    print(f"  - ROC-AUC : {ocsvm_metrics['roc_auc']} | PR-AUC: {ocsvm_metrics['pr_auc']} | FPR: {ocsvm_metrics['false_positive_rate']*100:.2f}% | FNR: {ocsvm_metrics['false_negative_rate']*100:.2f}%")

    # =========================================================================
    # EXPERIMENT 2: ISOLATION FOREST + ONE-CLASS SVM VALIDATION (DUAL-MODEL)
    # =========================================================================
    print("\n[EXPERIMENT 2] Evaluating Isolation Forest + One-Class SVM Validation...")
    
    # 4-State Consensus Distribution
    consensus_states = []
    dual_consensus_y_pred = []
    for if_p, oc_p in zip(if_y_pred, ocsvm_y_pred):
        state = OneClassSVMValidator.get_consensus_state(if_p, oc_p)
        consensus_states.append(state)
        # Dual Consensus: flag anomaly only when both IF and OCSVM agree
        dual_consensus_y_pred.append(1 if (if_p == 1 and oc_p == 1) else 0)

    dual_consensus_y_pred = np.array(dual_consensus_y_pred)
    dual_scores = (if_norm_scores + ocsvm_norm_scores) / 2.0
    dual_metrics = compute_metrics(y_test, dual_consensus_y_pred, scores=dual_scores)

    state_counts = pd.Series(consensus_states).value_counts().to_dict()

    print(f"  - Consensus Distribution on Test Set:")
    for state_name, count in state_counts.items():
        print(f"      * {state_name:<38}: {count} ({count/len(y_test)*100:.1f}%)")
    print(f"  - Accuracy: {dual_metrics['accuracy']*100:.2f}% | Precision: {dual_metrics['precision']*100:.2f}% | Recall: {dual_metrics['recall']*100:.2f}% | F1: {dual_metrics['f1_score']*100:.2f}%")
    print(f"  - ROC-AUC : {dual_metrics['roc_auc']} | PR-AUC: {dual_metrics['pr_auc']} | FPR: {dual_metrics['false_positive_rate']*100:.2f}% | FNR: {dual_metrics['false_negative_rate']*100:.2f}%")

    # Measure False-Positive Reduction
    fp_if = if_metrics['confusion_matrix']['false_positives']
    fp_dual = dual_metrics['confusion_matrix']['false_positives']
    fp_reduction_pct = round(((fp_if - fp_dual) / fp_if) * 100.0, 2) if fp_if > 0 else 0.0

    print(f"\n  • False Positive Comparison: IF Alone = {fp_if} FPs (FPR: {if_metrics['false_positive_rate']*100:.2f}%) vs Dual Consensus = {fp_dual} FPs (FPR: {dual_metrics['false_positive_rate']*100:.2f}%)")
    print(f"  • Empirically Demonstrated FP Reduction: {fp_reduction_pct}% on this benchmark dataset.")

    # =========================================================================
    # EXPORT STRUCTURED RESULTS
    # =========================================================================
    results_payload = {
        'evaluation_metadata': {
            'dataset_name': 'Constructed Syslog Scenario Evaluation Dataset',
            'dataset_description': '1000-sample deterministic scenario dataset (750 normal, 250 anomalous) constructed to provide reproducible evaluation without fabricated external labels.',
            'total_samples': total_records,
            'train_samples': len(train_raw_feats),
            'test_samples': len(test_raw_feats),
            'feature_schema': FEATURE_SCHEMA,
            'random_seed': 42,
            'split_ratio': '70% Train / 30% Held-Out Test (Unstratified, strictly unsupervised)',
            'data_leakage_protection': 'Training medians strictly applied to test split'
        },
        'experiments': {
            'experiment_1_isolation_forest_alone': {
                'model_name': 'Isolation Forest',
                'hyperparameters': {'n_estimators': 100, 'contamination': 0.25, 'random_state': 42},
                'metrics': if_metrics
            },
            'experiment_2_isolation_forest_plus_ocsvm_consensus': {
                'model_name': 'Isolation Forest + One-Class SVM Consensus Validation',
                'strategy': 'Dual-model consensus validation (positive anomaly only when both agree)',
                'consensus_state_distribution': state_counts,
                'false_positive_reduction_percent': fp_reduction_pct,
                'metrics': dual_metrics
            },
            'experiment_3_one_class_svm_alone': {
                'model_name': 'One-Class SVM',
                'hyperparameters': {'nu': 0.25, 'kernel': 'rbf', 'gamma': 'scale'},
                'metrics': ocsvm_metrics
            }
        }
    }

    # Save evaluation_results.json
    json_path = os.path.join(BASE_DIR, 'evaluation_results.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results_payload, f, indent=2)
    print(f"\n[OUTPUT] Saved structured results to: {json_path}")

    # Save results.csv
    csv_path = os.path.join(BASE_DIR, 'results.csv')
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Model/Experiment', 'Dataset', 'Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC-AUC', 'PR-AUC', 'FPR', 'FNR', 'TP', 'FP', 'TN', 'FN'])
        
        for exp_key, exp_data in results_payload['experiments'].items():
            m = exp_data['metrics']
            cm = m['confusion_matrix']
            writer.writerow([
                exp_data['model_name'],
                results_payload['evaluation_metadata']['dataset_name'],
                m['accuracy'],
                m['precision'],
                m['recall'],
                m['f1_score'],
                m['roc_auc'],
                m['pr_auc'],
                m['false_positive_rate'],
                m['false_negative_rate'],
                cm['true_positives'],
                cm['false_positives'],
                cm['true_negatives'],
                cm['false_negatives']
            ])
    print(f"[OUTPUT] Saved comparative summary table to: {csv_path}")

    # Print Final Markdown Comparison Table
    print("\n" + "=" * 80)
    print("FINAL COMPARATIVE ABLATION SUMMARY TABLE")
    print("=" * 80)
    print(f"{'Experiment / Model':<40} | {'Acc':<7} | {'Prec':<7} | {'Rec':<7} | {'F1':<7} | {'ROC-AUC':<8} | {'FPR':<7}")
    print("-" * 90)
    for exp_key, exp_data in results_payload['experiments'].items():
        m = exp_data['metrics']
        print(f"{exp_data['model_name']:<40} | {m['accuracy']:<7.4f} | {m['precision']:<7.4f} | {m['recall']:<7.4f} | {m['f1_score']:<7.4f} | {str(m['roc_auc']):<8} | {m['false_positive_rate']:<7.4f}")
    print("=" * 80)

    return results_payload


if __name__ == '__main__':
    run_standardized_evaluation()
