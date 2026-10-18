import pytest
import numpy as np
import pandas as pd
from ml_engine import IsolationForestDetector, OneClassSVMValidator, FEATURE_SCHEMA


def test_isolation_forest_prediction_schema(sample_feature_df):
    detector = IsolationForestDetector()
    results, X_input = detector.predict(sample_feature_df)

    assert len(results) == len(sample_feature_df)
    for r in results:
        assert 'log_id' in r
        assert 'is_anomaly' in r
        assert r['is_anomaly'] in (0, 1)
        assert 'anomaly_score' in r
        assert 0.0 <= r['anomaly_score'] <= 1.0
        assert 'severity' in r
        assert r['severity'] in ('Normal', 'Low', 'Medium', 'High', 'Critical', 'Warning', 'Anomaly')


def test_anomaly_score_monotonicity():
    detector = IsolationForestDetector()

    # Normal row: all zeros / typical values
    normal_row = pd.DataFrame([{
        'log_id': 1, 'event_frequency': 5.0, 'sequence_length': 60,
        'error_count': 0, 'error_pattern': 0, 'login_attempts': 0,
        'failed_login_attempts': 0, 'warning_count': 0, 'unknown_events': 0
    }])
    
    # Highly anomalous row: massive error bursts, high failed logins, unknown events
    anomaly_row = pd.DataFrame([{
        'log_id': 2, 'event_frequency': 100.0, 'sequence_length': 500,
        'error_count': 25, 'error_pattern': 4, 'login_attempts': 30,
        'failed_login_attempts': 30, 'warning_count': 10, 'unknown_events': 15
    }])

    res_norm, _ = detector.predict(normal_row)
    res_anom, _ = detector.predict(anomaly_row)

    # Monotonicity requirement: anomalous row must have higher score than normal row
    assert res_anom[0]['anomaly_score'] >= res_norm[0]['anomaly_score']


def test_one_class_svm_prediction(sample_feature_df):
    validator = OneClassSVMValidator()
    results = validator.predict(sample_feature_df)

    assert len(results) == len(sample_feature_df)
    for r in results:
        assert 'log_id' in r
        assert 'is_anomaly' in r
        assert r['is_anomaly'] in (0, 1)
        assert 'anomaly_score' in r
        assert 0.0 <= r['anomaly_score'] <= 1.0


def test_consensus_states():
    # 4 distinct consensus states
    assert OneClassSVMValidator.get_consensus_state(0, 0) == 'Consensus Normal'
    assert OneClassSVMValidator.get_consensus_state(1, 1) == 'Consensus Anomaly'
    assert OneClassSVMValidator.get_consensus_state(1, 0) == 'Model Disagreement: Isolation Forest'
    assert OneClassSVMValidator.get_consensus_state(0, 1) == 'Model Disagreement: One-Class SVM'


def test_model_comparison_metrics():
    if_results = [
        {'is_anomaly': 0, 'anomaly_score': 0.2},
        {'is_anomaly': 1, 'anomaly_score': 0.8},
        {'is_anomaly': 1, 'anomaly_score': 0.75}
    ]
    ocsvm_results = [
        {'is_anomaly': 0, 'anomaly_score': 0.3},
        {'is_anomaly': 1, 'anomaly_score': 0.85},
        {'is_anomaly': 0, 'anomaly_score': 0.4}
    ]
    ground_truth = [0, 1, 1]

    comp = OneClassSVMValidator.compare_models(if_results, ocsvm_results, ground_truth=ground_truth)

    assert comp['total_events'] == 3
    assert 'isolation_forest' in comp
    assert 'one_class_svm' in comp
    assert 'comparison_metrics' in comp
    assert comp['comparison_metrics']['consensus_distribution']['Consensus Normal'] == 1
    assert comp['comparison_metrics']['consensus_distribution']['Consensus Anomaly'] == 1
    assert comp['comparison_metrics']['consensus_distribution']['Model Disagreement: Isolation Forest'] == 1
    assert comp['isolation_forest']['accuracy'] == 1.0
