import pytest
import pandas as pd
from ml_engine import (
    IsolationForestDetector,
    ShapExplainerEngine,
    FEATURE_SCHEMA
)


def test_shap_explanation_schema(sample_feature_df):
    detector = IsolationForestDetector()
    results, X_input = detector.predict(sample_feature_df)

    explanations = ShapExplainerEngine.explain(detector.model, X_input, results)

    assert len(explanations) == len(sample_feature_df)
    for exp in explanations:
        assert 'log_id' in exp
        assert 'feature_contributions' in exp
        assert 'top_reason' in exp
        assert 'natural_explanation' in exp
        assert 'what_happened' in exp
        assert 'why_suspicious' in exp
        assert 'recommended_action' in exp
        assert 'top_3_human_reasons' in exp
        assert isinstance(exp['top_3_human_reasons'], list)


def test_shap_8_feature_alignment(sample_feature_df):
    detector = IsolationForestDetector()
    results, X_input = detector.predict(sample_feature_df)

    explanations = ShapExplainerEngine.explain(detector.model, X_input, results)

    for exp in explanations:
        contribs = exp['feature_contributions']
        assert len(contribs) == 8
        for name in ShapExplainerEngine.FEATURE_NAMES:
            assert name in contribs


def test_shap_human_readable_reasons():
    log_item_normal = {'log_id': 1, 'service': 'systemd', 'message': 'Started service daemon.'}
    log_item_anomaly = {'log_id': 2, 'service': 'sshd', 'message': 'Failed password for invalid user admin'}

    what_norm = ShapExplainerEngine.get_what_happened(log_item_normal)
    what_anom = ShapExplainerEngine.get_what_happened(log_item_anomaly)
    action_norm = ShapExplainerEngine.get_recommended_action(log_item_normal, is_anomaly=False)
    action_anom = ShapExplainerEngine.get_recommended_action(log_item_anomaly, is_anomaly=True)

    assert "service" in what_norm.lower() or "started" in what_norm.lower()
    assert "failed" in what_anom.lower()
    assert "no action required" in action_norm.lower()
    assert "check" in action_anom.lower() or "investigate" in action_anom.lower()
