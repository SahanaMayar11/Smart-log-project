# Data Loader Module for Objective Implementation
import os
import sys
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

FEATURE_SCHEMA = [
    'event_frequency',
    'sequence_length',
    'error_count',
    'error_pattern',
    'login_attempts',
    'failed_login_attempts',
    'warning_count',
    'unknown_events'
]


def find_hdfs_dataset_dir():
    """Locates the real HDFS benchmark dataset directory in the project or system."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base_dir, '..', '..', 'backend', 'Dataset_HDFS', 'HDFS_v1'),
        r'C:\Users\Admin\Downloads\HDFS_v1',
        os.path.join(base_dir, '..', 'data', 'HDFS_v1'),
    ]
    for p in candidates:
        if os.path.exists(p):
            preproc = os.path.join(p, 'preprocessed')
            if os.path.exists(os.path.join(preproc, 'Event_occurrence_matrix.csv')):
                return os.path.abspath(p)
    return None


def load_hdfs_benchmark_data(sample_limit=None, random_state=42):
    """
    Loads real HDFS benchmark dataset (575,061 block traces or subset).
    Extracts raw 8-feature representation from event occurrence matrix (E1-E29).
    Returns raw feature DataFrame X_raw, ground truth labels y (for evaluation only),
    and dataset metadata.
    """
    dataset_dir = find_hdfs_dataset_dir()
    if not dataset_dir:
        raise FileNotFoundError('HDFS dataset not found in backend/Dataset_HDFS/HDFS_v1 or standard locations.')

    preprocessed_dir = os.path.join(dataset_dir, 'preprocessed')
    eom_path = os.path.join(preprocessed_dir, 'Event_occurrence_matrix.csv')
    labels_path = os.path.join(preprocessed_dir, 'anomaly_label.csv')

    print(f'[DATA LOADER] Loading HDFS Event Occurrence Matrix: {eom_path}')
    df_eom = pd.read_csv(eom_path)
    print(f'[DATA LOADER] Loading HDFS Ground Truth Labels: {labels_path}')
    df_labels = pd.read_csv(labels_path)

    df_merged = pd.merge(df_eom, df_labels, on='BlockId')
    total_records = len(df_merged)

    if sample_limit and sample_limit < total_records:
        print(f'[DATA LOADER] Unstratified sampling {sample_limit:,} records from {total_records:,} total traces (seed={random_state})...')
        df_merged, _ = train_test_split(
            df_merged,
            train_size=sample_limit,
            stratify=None,
            random_state=random_state
        )
        df_merged = df_merged.reset_index(drop=True)
        total_records = len(df_merged)
    else:
        df_merged = df_merged.reset_index(drop=True)
        total_records = len(df_merged)

    event_cols = [f'E{i}' for i in range(1, 30)]
    error_cols = ['E4', 'E7', 'E10', 'E12', 'E14', 'E17', 'E20', 'E29']
    warning_cols = ['E1', 'E8', 'E11', 'E13', 'E19', 'E23', 'E24', 'E27', 'E28']

    event_freq = df_merged[event_cols].sum(axis=1).astype(float)
    seq_len = (df_merged[event_cols] > 0).sum(axis=1).astype(float)
    err_count_raw = df_merged[error_cols].sum(axis=1).astype(float)
    err_count = err_count_raw
    err_pattern = np.where(err_count_raw > 0, 1.0, 0.0)
    warning_count = df_merged[warning_cols].sum(axis=1).astype(float)
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

    y_true = np.where(df_merged['Label_y'] == 'Anomaly', 1, 0)
    anomaly_count = int(np.sum(y_true))
    normal_count = total_records - anomaly_count

    return feature_df, y_true, {
        'source': 'Real HDFS Distributed Cluster Benchmark (LogHub)',
        'total_records': total_records,
        'normal_count': normal_count,
        'anomaly_count': anomaly_count,
        'anomaly_ratio': round(anomaly_count / total_records, 4)
    }


def get_sample_log_stream():
    """Provides a realistic log stream with normal operations and injected threats."""
    return [
        '2026-08-15T10:00:01 server-01 systemd[1]: Started Nginx HTTP and reverse proxy server.',
        '2026-08-15T10:00:02 server-01 sshd[1042]: Accepted publickey for admin from 192.168.1.50 port 51234 ssh2',
        '2026-08-15T10:00:03 server-01 CRON[1045]: (root) CMD (sysstat-collector)',
        '2026-08-15T10:00:04 server-01 nginx[1050]: 2026/08/15 10:00:04 [info] 1050#0: GET /api/v1/health 200 OK',
        '2026-08-15T10:00:05 server-01 sshd[2201]: Failed password for invalid user root from 203.0.113.195 port 44221',
        '2026-08-15T10:00:05 server-01 sshd[2202]: Failed password for invalid user root from 203.0.113.195 port 44222',
        '2026-08-15T10:00:06 server-01 sshd[2203]: Failed password for invalid user admin from 203.0.113.195 port 44223',
        '2026-08-15T10:00:07 server-01 kernel[0]: [1042.551] Out of Memory: Kill process 9912 (leak_worker) score 950',
        '2026-08-15T10:00:08 server-01 systemd[1]: database.service: Main process exited, code=killed, status=9/KILL',
        '2026-08-15T10:00:09 server-01 systemd[1]: database.service: Failed with result oom-killer.',
        '2026-08-15T10:00:10 server-01 CRON[1090]: (root) CMD (/usr/local/bin/backup-db.sh)',
        '2026-08-15T10:00:11 server-01 nginx[1050]: 2026/08/15 10:00:11 [info] 1050#0: GET /dashboard 200 OK'
    ]
