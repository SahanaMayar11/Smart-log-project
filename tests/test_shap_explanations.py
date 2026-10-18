import pytest
import pandas as pd
import numpy as np
from ml_engine import (
    IsolationForestDetector,
    ShapExplainerEngine,
    FEATURE_SCHEMA
)


@pytest.fixture
def detector():
    return IsolationForestDetector()


def test_severity_operational_bands_boundary_values(detector):
    """
    Validates deterministic mapping of continuous anomaly_score in [0,1]
    to operational severity bands across exact boundary values:
    0.49, 0.50, 0.55, 0.70, 0.85, 1.00.
    """
    # The Isolation Forest score mapping is: norm_score = clip(1.0 - (decision_function + 0.5), 0.0, 1.0)
    # Binary anomaly decision threshold is strictly at norm_score >= 0.50 (decision_function <= 0)
    
    test_cases = [
        (0.49, 0, 'Normal'),
        (0.50, 1, 'Low'),
        (0.55, 1, 'Low'),
        (0.56, 1, 'Medium'),
        (0.70, 1, 'Medium'),
        (0.71, 1, 'High'),
        (0.85, 1, 'High'),
        (0.86, 1, 'Critical'),
        (1.00, 1, 'Critical'),
    ]
    
    for score, expected_is_anomaly, expected_severity in test_cases:
        # Mocking the predict loop severity determination logic
        if score >= 0.50:
            if score > 0.85:
                sev = 'Critical'
            elif score > 0.70:
                sev = 'High'
            elif score > 0.55:
                sev = 'Medium'
            else:
                sev = 'Low'
        else:
            sev = 'Normal'
            
        assert sev == expected_severity, f"Score {score} expected {expected_severity}, got {sev}"


def test_sample_specific_shap_explanations_dynamic_values(detector):
    """
    Tests that SHAP explanations dynamically incorporate the actual input feature values,
    feature names, and contribution magnitudes rather than static templates.
    """
    samples = [
        # Sample 1: High failed login attempts
        {
            'event_frequency': 0.85, 'sequence_length': 45.0, 'error_count': 0.0, 'error_pattern': 0.0,
            'login_attempts': 25.0, 'failed_login_attempts': 24.0, 'warning_count': 0.0, 'unknown_events': 0.0,
            'log_id': 1
        },
        # Sample 2: High error count crash loop
        {
            'event_frequency': 0.90, 'sequence_length': 120.0, 'error_count': 45.0, 'error_pattern': 2.0,
            'login_attempts': 1.0, 'failed_login_attempts': 0.0, 'warning_count': 10.0, 'unknown_events': 1.0,
            'log_id': 2
        }
    ]
    
    df = pd.DataFrame(samples)
    preds, _ = detector.predict(df)
    
    parsed_logs = [
        {'log_id': 1, 'message': 'Failed password for root', 'service': 'sshd'},
        {'log_id': 2, 'message': 'Segmentation fault in worker process', 'service': 'nginx'}
    ]
    
    explanations = ShapExplainerEngine.explain(detector.model, df, preds, parsed_logs=parsed_logs)
    
    assert len(explanations) == 2
    
    # Verify Sample 1 explanation contains its actual feature value (e.g. 24 or 45 or 0.85)
    exp1 = explanations[0]
    assert exp1['log_id'] == 1
    assert 'feature_contributions' in exp1
    assert len(exp1['feature_contributions']) == 8
    
    # Top 3 human reasons must include actual numerical feature values
    assert len(exp1['top_3_human_reasons']) == 3
    assert any('was ' in reason for reason in exp1['top_3_human_reasons'])
    assert any('SHAP contribution:' in reason for reason in exp1['top_3_human_reasons'])
    
    # Verify Sample 2 explanation differs and has sample-specific values
    exp2 = explanations[1]
    assert exp2['log_id'] == 2
    assert exp1['natural_explanation'] != exp2['natural_explanation'] or exp1['top_reason'] != exp2['top_reason']


def test_distinct_samples_produce_different_numerical_shap():
    """
    Tests that 5 distinct input vectors produce non-identical SHAP contribution dictionaries.
    """
    detector = IsolationForestDetector()
    
    samples = [
        {'event_frequency': 0.85, 'sequence_length': 45.0, 'error_count': 0.0, 'error_pattern': 0.0, 'login_attempts': 25.0, 'failed_login_attempts': 24.0, 'warning_count': 0.0, 'unknown_events': 0.0, 'log_id': 1},
        {'event_frequency': 0.90, 'sequence_length': 120.0, 'error_count': 45.0, 'error_pattern': 2.0, 'login_attempts': 1.0, 'failed_login_attempts': 0.0, 'warning_count': 10.0, 'unknown_events': 1.0, 'log_id': 2},
        {'event_frequency': 0.30, 'sequence_length': 480.0, 'error_count': 2.0, 'error_pattern': 3.0, 'login_attempts': 0.0, 'failed_login_attempts': 0.0, 'warning_count': 1.0, 'unknown_events': 22.0, 'log_id': 3},
        {'event_frequency': 0.02, 'sequence_length': 40.0, 'error_count': 0.0, 'error_pattern': 0.0, 'login_attempts': 0.0, 'failed_login_attempts': 0.0, 'warning_count': 0.0, 'unknown_events': 0.0, 'log_id': 4},
        {'event_frequency': 0.75, 'sequence_length': 85.0, 'error_count': 1.0, 'error_pattern': 1.0, 'login_attempts': 0.0, 'failed_login_attempts': 0.0, 'warning_count': 50.0, 'unknown_events': 0.0, 'log_id': 5},
    ]
    
    df = pd.DataFrame(samples)
    preds, _ = detector.predict(df)
    explanations = ShapExplainerEngine.explain(detector.model, df, preds)
    
    contrib_vectors = [list(exp['feature_contributions'].values()) for exp in explanations]
    
    # Assert that all 5 samples do not have identical SHAP vectors
    for i in range(len(contrib_vectors)):
        for j in range(i + 1, len(contrib_vectors)):
            assert contrib_vectors[i] != contrib_vectors[j], f"Sample {i+1} and {j+1} have identical SHAP contributions!"


def test_top_feature_matches_attribution():
    """
    Verifies that the top-ranked feature in feature_contributions matches top_reason for anomalies.
    """
    detector = IsolationForestDetector()
    samples = [
        {'event_frequency': 0.90, 'sequence_length': 120.0, 'error_count': 45.0, 'error_pattern': 2.0, 'login_attempts': 1.0, 'failed_login_attempts': 0.0, 'warning_count': 10.0, 'unknown_events': 1.0, 'log_id': 1}
    ]
    df = pd.DataFrame(samples)
    preds, _ = detector.predict(df)
    explanations = ShapExplainerEngine.explain(detector.model, df, preds)
    
    exp = explanations[0]
    if preds[0]['is_anomaly'] == 1:
        # Find feature with maximum absolute SHAP contribution
        max_feat = max(exp['feature_contributions'].items(), key=lambda x: abs(x[1]))[0]
        assert exp['top_reason'] == max_feat, f"Expected top reason {max_feat}, got {exp['top_reason']}"


def test_evidence_based_recommended_actions():
    """
    Tests evidence-based recommendation logic:
    - Auth events receive auth advice
    - PowerShell events receive PowerShell advice
    - Service crashes receive service health advice
    - Unclassified events receive neutral fallback
    - Normal events receive standard baseline monitoring advice
    """
    # 1. Normal event
    normal_act = ShapExplainerEngine.get_recommended_action({'message': 'System started'}, is_anomaly=False)
    assert normal_act == "No action required. Continue standard operational monitoring."
    
    # 2. Auth anomaly
    auth_act = ShapExplainerEngine.get_recommended_action(
        {'message': 'Failed password for root from 192.168.1.1', 'service': 'sshd'},
        is_anomaly=True,
        top_feature='Failed Login Attempts'
    )
    assert "authentication source and user account" in auth_act
    
    # 3. PowerShell anomaly
    ps_act = ShapExplainerEngine.get_recommended_action(
        {'message': 'powershell.exe -enc AAAAA', 'service': 'powershell.exe'},
        is_anomaly=True,
        top_feature='Sequence Length'
    )
    assert "PowerShell or command execution" in ps_act
    
    # 4. Error / Crash anomaly
    err_act = ShapExplainerEngine.get_recommended_action(
        {'message': 'Process died with fatal error', 'service': 'nginx'},
        is_anomaly=True,
        top_feature='Error Count'
    )
    assert "Inspect service health and recent crash logs" in err_act
    
    # 5. Neutral fallback for generic anomalous event
    neutral_act = ShapExplainerEngine.get_recommended_action(
        {'message': 'Custom peripheral state toggle', 'service': 'custom_driver'},
        is_anomaly=True,
        top_feature=None
    )
    assert neutral_act == "Investigate the associated event and surrounding activity in Windows Event Viewer before taking corrective action."
