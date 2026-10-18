import pytest
import numpy as np
import pandas as pd
from ml_engine import DataPreprocessor, HDFSDomainAdapter, FEATURE_SCHEMA


def test_preprocessor_missing_columns():
    # DataFrame with only 2 of 8 features
    partial_df = pd.DataFrame([
        {'log_id': 1, 'event_frequency': 5.0, 'sequence_length': 100}
    ])
    cleaned_df, stats = DataPreprocessor.preprocess(partial_df)

    assert len(cleaned_df) == 1
    assert stats['missing_values_found'] > 0
    assert stats['missing_values_handled'] == stats['missing_values_found']
    for col in FEATURE_SCHEMA:
        assert col in cleaned_df.columns
        assert not np.isnan(cleaned_df[col].iloc[0])


def test_preprocessor_nan_imputation():
    df_nan = pd.DataFrame([
        {'event_frequency': np.nan, 'sequence_length': 100, 'error_count': 2, 'error_pattern': 1,
         'login_attempts': 0, 'failed_login_attempts': 0, 'warning_count': 1, 'unknown_events': 0},
        {'event_frequency': 10.0, 'sequence_length': np.nan, 'error_count': 0, 'error_pattern': 0,
         'login_attempts': 1, 'failed_login_attempts': 0, 'warning_count': 0, 'unknown_events': np.nan}
    ])
    cleaned_df, stats = DataPreprocessor.preprocess(df_nan)

    assert not cleaned_df[FEATURE_SCHEMA].isna().any().any()
    assert stats['missing_values_handled'] > 0


def test_preprocessor_invalid_and_infinite_values():
    df_invalid = pd.DataFrame([
        {'event_frequency': np.inf, 'sequence_length': -50, 'error_count': -5, 'error_pattern': 99,
         'login_attempts': -1, 'failed_login_attempts': 0, 'warning_count': 0, 'unknown_events': 0}
    ])
    cleaned_df, stats = DataPreprocessor.preprocess(df_invalid)

    # Infs capped
    assert not np.isinf(cleaned_df[FEATURE_SCHEMA].values).any()
    # Negatives clipped to 0
    assert (cleaned_df[FEATURE_SCHEMA].values >= 0).all()
    # Error pattern bounded to [0, 4]
    assert cleaned_df['error_pattern'].iloc[0] == 4.0
    assert stats['invalid_values_handled'] > 0


def test_preprocessor_data_leakage_protection():
    train_df = pd.DataFrame([
        {'event_frequency': 10.0, 'sequence_length': 100, 'error_count': 2, 'error_pattern': 1,
         'login_attempts': 0, 'failed_login_attempts': 0, 'warning_count': 1, 'unknown_events': 0},
        {'event_frequency': 20.0, 'sequence_length': 200, 'error_count': 4, 'error_pattern': 2,
         'login_attempts': 2, 'failed_login_attempts': 2, 'warning_count': 2, 'unknown_events': 0}
    ])
    train_cleaned, train_stats = DataPreprocessor.preprocess(train_df)
    fitted_medians = train_stats['fitted_medians']

    assert fitted_medians['event_frequency'] == 15.0
    assert fitted_medians['sequence_length'] == 150.0

    # Test split with missing value should use fitted medians from training split
    test_df = pd.DataFrame([
        {'event_frequency': np.nan, 'sequence_length': np.nan, 'error_count': 0, 'error_pattern': 0,
         'login_attempts': 0, 'failed_login_attempts': 0, 'warning_count': 0, 'unknown_events': 0}
    ])
    test_cleaned, test_stats = DataPreprocessor.preprocess(test_df, fit_medians=fitted_medians)

    assert test_cleaned['event_frequency'].iloc[0] == 15.0
    assert test_cleaned['sequence_length'].iloc[0] == 150.0


def test_hdfs_domain_adapter_transformation(sample_feature_df):
    cleaned_df, _ = DataPreprocessor.preprocess(sample_feature_df)
    adapted_df = HDFSDomainAdapter.transform(cleaned_df)

    assert len(adapted_df) == len(cleaned_df)
    assert list(adapted_df.columns) == FEATURE_SCHEMA

    # Baseline error count is non-negative without artificial 3.0 offset
    assert adapted_df['error_count'].min() >= 0.0
    # Authentication & unknown features zeroed out for HDFS model compatibility
    assert (adapted_df['login_attempts'] == 0.0).all()
    assert (adapted_df['failed_login_attempts'] == 0.0).all()
    assert (adapted_df['unknown_events'] == 0.0).all()
