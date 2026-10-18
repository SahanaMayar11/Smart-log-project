import pytest
import pandas as pd
from ml_engine import LogParser, DataCleaner, BehavioralFeatureExtractor, FEATURE_SCHEMA


def test_extract_exact_8_features(sample_syslog_content):
    parsed = LogParser.parse_logs(sample_syslog_content)
    cleaned = DataCleaner.clean(parsed)
    df = BehavioralFeatureExtractor.extract_features(cleaned)

    # Check that output is DataFrame
    assert isinstance(df, pd.DataFrame)
    assert len(df) == len(cleaned)

    # Check all 8 canonical features exist in exact schema
    for feat in FEATURE_SCHEMA:
        assert feat in df.columns, f"Feature {feat} missing from extracted features"


def test_feature_data_types(sample_syslog_content):
    parsed = LogParser.parse_logs(sample_syslog_content)
    cleaned = DataCleaner.clean(parsed)
    df = BehavioralFeatureExtractor.extract_features(cleaned)

    assert df['event_frequency'].dtype.kind in ('f', 'i')
    assert df['sequence_length'].dtype.kind in ('i', 'u')
    assert df['error_count'].dtype.kind in ('i', 'u')
    assert df['error_pattern'].dtype.kind in ('i', 'u')
    assert df['login_attempts'].dtype.kind in ('i', 'u')
    assert df['failed_login_attempts'].dtype.kind in ('i', 'u')
    assert df['warning_count'].dtype.kind in ('i', 'u')
    assert df['unknown_events'].dtype.kind in ('i', 'u')


def test_sliding_window_calculations():
    # Sequence of 3 logs: 2 failed logins followed by 1 normal log
    logs = [
        {'log_id': 1, 'message': 'Failed password for root', 'log_level': 'ERROR', 'event_type': 'AUTHENTICATION'},
        {'log_id': 2, 'message': 'Failed password for admin', 'log_level': 'ERROR', 'event_type': 'AUTHENTICATION'},
        {'log_id': 3, 'message': 'Service started OK', 'log_level': 'INFO', 'event_type': 'SYSTEM_EVENT'}
    ]
    cleaned = DataCleaner.clean(logs)
    df = BehavioralFeatureExtractor.extract_features(cleaned)

    # Event frequency should be window length (3 for short sequence)
    assert df.loc[0, 'event_frequency'] == 3.0
    # Error count for first log should see 2 errors in window
    assert df.loc[0, 'error_count'] == 2
    # Failed login count for first log should be 2
    assert df.loc[0, 'failed_login_attempts'] == 2
    # Error pattern for first log (contains FAILED) should be 1
    assert df.loc[0, 'error_pattern'] == 1


def test_error_pattern_categorization():
    test_cases = [
        ('Failed login attempt', 1),
        ('no such file or directory found', 2),
        ('Out of memory: Kill process', 3),
        ('Permission denied open /etc/shadow', 4),
        ('Routine system event', 0)
    ]
    
    logs = [{'log_id': idx + 1, 'message': msg, 'log_level': 'INFO', 'event_type': 'SYSTEM_EVENT'} for idx, (msg, _) in enumerate(test_cases)]
    cleaned = DataCleaner.clean(logs)
    df = BehavioralFeatureExtractor.extract_features(cleaned)

    for idx, (_, expected_pat) in enumerate(test_cases):
        assert df.loc[idx, 'error_pattern'] == expected_pat
