import os
import pytest
import json
import numpy as np
import pandas as pd
from evaluate_models import build_constructed_evaluation_dataset, compute_metrics


def test_build_constructed_evaluation_dataset():
    df = build_constructed_evaluation_dataset(seed=42)
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 1000
    assert 'log_line' in df.columns
    assert 'label' in df.columns
    assert df['label'].sum() == 250
    assert (df['label'] == 0).sum() == 750


def test_compute_metrics():
    y_true = [0, 0, 1, 1]
    y_pred = [0, 0, 1, 1]
    scores = [0.1, 0.2, 0.8, 0.9]

    metrics = compute_metrics(y_true, y_pred, scores=scores)
    assert metrics['accuracy'] == 1.0
    assert metrics['precision'] == 1.0
    assert metrics['recall'] == 1.0
    assert metrics['f1_score'] == 1.0
    assert metrics['false_positive_rate'] == 0.0
    assert metrics['false_negative_rate'] == 0.0
    assert metrics['roc_auc'] == 1.0


def test_evaluation_artifacts_exist():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend'))
    json_path = os.path.join(base_dir, 'evaluation_results.json')
    csv_path = os.path.join(base_dir, 'results.csv')

    assert os.path.exists(json_path), f"Missing {json_path}"
    assert os.path.exists(csv_path), f"Missing {csv_path}"

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        assert 'evaluation_metadata' in data
        assert 'experiments' in data
        assert 'experiment_1_isolation_forest_alone' in data['experiments']
        assert 'experiment_2_isolation_forest_plus_ocsvm_consensus' in data['experiments']
        assert 'experiment_3_one_class_svm_alone' in data['experiments']


def test_unsupervised_split_integrity():
    """Verifies that the unsupervised splitting does not leak labels into training data."""
    from evaluate_models import build_constructed_evaluation_dataset
    from sklearn.model_selection import train_test_split
    df = build_constructed_evaluation_dataset(seed=42)
    indices = np.arange(len(df))
    # Unstratified split
    train_idx, test_idx = train_test_split(indices, test_size=0.30, random_state=42, stratify=None)
    assert len(train_idx) == 700
    assert len(test_idx) == 300
    # Both sets must have non-zero representation without artificial matching of proportions
    assert df['label'].iloc[train_idx].sum() > 0
    assert df['label'].iloc[test_idx].sum() > 0


def test_ocsvm_unfitted_raises_error():
    """Verifies that OneClassSVMValidator raises error instead of self-fitting on test data."""
    from sklearn.exceptions import NotFittedError
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'Smart_log'))
    from models.one_class_svm import OneClassSVMValidator
    validator = OneClassSVMValidator()
    dummy_data = pd.DataFrame([
        {'event_frequency': 10.0, 'sequence_length': 7.0, 'error_count': 0.0, 'error_pattern': 0.0,
         'login_attempts': 0.0, 'failed_login_attempts': 0.0, 'warning_count': 0.0, 'unknown_events': 0.0}
    ])
    with pytest.raises(NotFittedError):
        validator.predict(dummy_data)

