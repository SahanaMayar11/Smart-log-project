import json
import pytest


def test_api_dashboard_stats(flask_client):
    res = flask_client.get('/api/dashboard/stats')
    assert res.status_code == 200
    data = res.get_json()
    assert 'total_logs' in data
    assert 'normal_logs' in data
    assert 'anomaly_logs' in data
    assert 'human_summary' in data


def test_api_features(flask_client):
    res = flask_client.get('/api/features?limit=5')
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    if len(data) > 0:
        row = data[0]
        assert 'event_frequency' in row
        assert 'sequence_length' in row
        assert 'error_count' in row
        assert 'error_pattern' in row
        assert 'login_attempts' in row
        assert 'failed_login_attempts' in row
        assert 'warning_count' in row
        assert 'unknown_events' in row


def test_api_detection_results(flask_client):
    res = flask_client.get('/api/detection/results?limit=5')
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    if len(data) > 0:
        row = data[0]
        assert 'is_anomaly' in row
        assert 'anomaly_score' in row
        assert 'severity' in row


def test_api_shap_explanations(flask_client):
    res = flask_client.get('/api/shap/explanations?limit=5')
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    if len(data) > 0:
        row = data[0]
        assert 'feature_contributions' in row
        assert 'top_reason' in row
        assert 'natural_explanation' in row


def test_api_model_validation(flask_client):
    res = flask_client.get('/api/model-validation')
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'success'
    assert 'feature_schema' in data
    assert 'feature_documentation' in data


def test_api_model_info(flask_client):
    res = flask_client.get('/api/model-info')
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'success'
    assert 'n_estimators' in data
    assert 'contamination' in data
    assert 'feature_schema' in data


def test_api_system_logs_live(flask_client):
    res = flask_client.get('/api/system-logs/live?limit=10')
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'success'
    assert 'is_monitoring' in data
    assert 'events' in data
    assert isinstance(data['events'], list)
