"""
Comprehensive test suite for the Attack Simulator & Anomaly Injector.

Tests:
1. Scenario definitions catalog integrity (5 scenarios, required metadata).
2. Synthetic event generation and unique identifiers.
3. Feature extraction and schema validation on synthetic logs.
4. Separate rule-based heuristic evaluations.
5. GET /api/test/scenarios endpoint.
6. Invalid and missing scenario error handling.
7. End-to-end injection of all five attack scenarios via POST /api/test/inject-anomaly.
8. Model integrity (genuine inference, score range, consensus agreement).
9. Database persistence with is_simulated markers and scenario tagging.
10. Test history retrieval and cleanup endpoints.
"""

import json
import sqlite3
import pytest
import numpy as np
import pandas as pd

from attack_simulator import (
    SCENARIOS_CATALOG,
    get_scenario_or_404,
    generate_synthetic_scenario_logs,
    evaluate_scenario_rule_based
)
from database import DB_PATH, get_db_connection
from ml_engine import FEATURE_SCHEMA, LogParser, DataCleaner, BehavioralFeatureExtractor


def test_all_five_scenario_definitions():
    """Verify all five attack scenarios exist and contain complete metadata."""
    expected_scenarios = [
        'ssh_bruteforce',
        'buffer_overflow',
        'privilege_escalation',
        'directory_traversal',
        'dos_burst'
    ]
    for sc_id in expected_scenarios:
        assert sc_id in SCENARIOS_CATALOG, f"Missing scenario {sc_id}"
        sc = SCENARIOS_CATALOG[sc_id]
        assert sc['id'] == sc_id
        assert 'name' in sc and len(sc['name']) > 0
        assert 'description' in sc and len(sc['description']) > 0
        assert 'target_signals' in sc and isinstance(sc['target_signals'], list)
        assert len(sc['target_signals']) > 0
        assert 'expected_signals' in sc
        assert 'security_recommendation' in sc and len(sc['security_recommendation']) > 0
        assert 'model_compatibility' in sc
        assert 'sample_preview' in sc


def test_get_scenario_or_404():
    """Verify get_scenario_or_404 returns scenario or raises ValueError."""
    sc = get_scenario_or_404('ssh_bruteforce')
    assert sc['id'] == 'ssh_bruteforce'

    with pytest.raises(ValueError) as exc:
        get_scenario_or_404('non_existent_exploit')
    assert "Unknown scenario identifier" in str(exc.value)


def test_synthetic_event_generation():
    """Verify synthetic logs generated for each scenario have markers and valid format."""
    for sc_id in SCENARIOS_CATALOG.keys():
        sim_data = generate_synthetic_scenario_logs(sc_id)
        assert sim_data['scenario_id'] == sc_id
        assert sim_data['is_simulated'] is True
        assert 'sim_id' in sim_data
        assert 'raw_text' in sim_data
        assert 'events' in sim_data
        events = sim_data['events']
        assert len(events) >= 3, f"Scenario {sc_id} generated fewer than 3 events"

        for event in events:
            assert 'timestamp' in event
            assert 'hostname' in event
            assert 'service' in event
            assert 'message' in event


def test_feature_extraction_on_synthetic_events():
    """Verify synthetic logs parse cleanly and produce valid 8-feature schema without NaNs."""
    for sc_id in SCENARIOS_CATALOG.keys():
        sim_data = generate_synthetic_scenario_logs(sc_id)
        raw_text = sim_data['raw_text']

        parsed_logs = LogParser.parse_logs(raw_text)
        assert len(parsed_logs) > 0, f"Failed to parse logs for {sc_id}"

        cleaned_logs = DataCleaner.clean(parsed_logs)
        features_df = BehavioralFeatureExtractor.extract_features(cleaned_logs)

        assert not features_df.empty, f"Failed to extract features for {sc_id}"
        for col in FEATURE_SCHEMA:
            assert col in features_df.columns, f"Feature column {col} missing in {sc_id}"
            assert not features_df[col].isna().any(), f"NaN in feature {col} for {sc_id}"


def test_rule_based_evaluation():
    """Verify rule-based evaluation triggers for high-signal scenario telemetry."""
    # Test SSH brute force with high failed login attempts
    mock_features_ssh = pd.DataFrame([{
        'failed_login_attempts': 15,
        'error_count': 5,
        'event_frequency': 8.0,
        'sequence_length': 120,
        'bytes_transferred': 200,
        'component_entropy': 0.1,
        'login_attempts': 15,
        'warning_count': 0
    }])
    eval_ssh = evaluate_scenario_rule_based('ssh_bruteforce', mock_features_ssh)
    assert eval_ssh['is_anomaly'] is True
    assert eval_ssh['confidence'] >= 0.8
    assert 'Failed Login Attempts' in eval_ssh['reason']

    # Test DoS burst with high frequency
    mock_features_dos = pd.DataFrame([{
        'failed_login_attempts': 0,
        'error_count': 2,
        'event_frequency': 25.0,
        'sequence_length': 300,
        'bytes_transferred': 5000,
        'component_entropy': 0.05,
        'login_attempts': 0,
        'warning_count': 1
    }])
    eval_dos = evaluate_scenario_rule_based('dos_burst', mock_features_dos)
    assert eval_dos['is_anomaly'] is True
    assert eval_dos['confidence'] >= 0.85
    assert 'Volumetric' in eval_dos['reason'] or 'DoS' in eval_dos['reason']


def test_api_get_scenarios(flask_client):
    """Verify GET /api/test/scenarios endpoint."""
    res = flask_client.get('/api/test/scenarios')
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'success'
    assert 'scenarios' in data
    assert len(data['scenarios']) == 5

    scenario_ids = [s['id'] for s in data['scenarios']]
    assert 'ssh_bruteforce' in scenario_ids
    assert 'buffer_overflow' in scenario_ids
    assert 'privilege_escalation' in scenario_ids
    assert 'directory_traversal' in scenario_ids
    assert 'dos_burst' in scenario_ids


def test_api_inject_invalid_requests(flask_client):
    """Verify 400 responses on invalid scenario injection requests."""
    # Empty payload
    res1 = flask_client.post('/api/test/inject-anomaly', json={})
    assert res1.status_code == 400
    d1 = res1.get_json()
    assert 'error' in d1 or 'message' in d1

    # Unsupported scenario
    res2 = flask_client.post('/api/test/inject-anomaly', json={'scenario': 'kernel_rootkit_v99'})
    assert res2.status_code == 400
    d2 = res2.get_json()
    assert 'Invalid or missing scenario identifier' in (d2.get('error') or d2.get('message'))


def test_api_inject_all_five_scenarios(flask_client):
    """Verify end-to-end injection and ML evaluation for all 5 scenarios."""
    scenarios_to_test = [
        'ssh_bruteforce',
        'buffer_overflow',
        'privilege_escalation',
        'directory_traversal',
        'dos_burst'
    ]

    for sc_id in scenarios_to_test:
        res = flask_client.post('/api/test/inject-anomaly', json={'scenario': sc_id})
        assert res.status_code == 200, f"Injection failed for {sc_id}: {res.data}"
        data = res.get_json()
        assert data['status'] == 'success'
        sim = data['simulation']
        assert sim['scenario_id'] == sc_id
        assert sim['is_simulated'] is True
        assert sim['events_generated'] >= 3

        # Verify genuine detection results
        results = sim['injected_results']
        assert len(results) > 0, f"No anomaly results produced for {sc_id}"
        for r in results:
            assert 'id' in r
            assert 'anomaly_score' in r
            assert 0.0 <= r['anomaly_score'] <= 1.0
            assert r['is_anomaly'] in (0, 1)
            assert 'consensus_state' in r
            assert r['is_simulated'] == 1
            assert r['simulation_scenario'] == sc_id

        # Verify rule-based evaluation exists separately
        assert 'rule_based_evaluation' in sim
        assert 'is_anomaly' in sim['rule_based_evaluation']


def test_database_persistence_and_simulated_markers(flask_client):
    """Verify that injected records are persisted in SQLite with is_simulated=1."""
    # Inject a test attack
    res = flask_client.post('/api/test/inject-anomaly', json={'scenario': 'ssh_bruteforce'})
    assert res.status_code == 200
    data = res.get_json()
    file_id = data['simulation']['file_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check uploaded_files
    cursor.execute("SELECT id, is_simulated, simulation_scenario FROM uploaded_files WHERE id = ?", (file_id,))
    row_file = cursor.fetchone()
    assert row_file is not None
    assert row_file['is_simulated'] == 1
    assert row_file['simulation_scenario'] == 'ssh_bruteforce'

    # Check parsed_logs
    cursor.execute("SELECT COUNT(*) FROM parsed_logs WHERE file_id = ? AND is_simulated = 1", (file_id,))
    count_logs = cursor.fetchone()[0]
    assert count_logs > 0

    # Check anomaly_results
    cursor.execute("""
        SELECT ar.id, ar.is_simulated, ar.simulation_scenario, ar.consensus_state, ar.consensus_agreement
        FROM anomaly_results ar
        JOIN parsed_logs pl ON ar.log_id = pl.id
        WHERE pl.file_id = ?
    """, (file_id,))
    results = cursor.fetchall()
    assert len(results) > 0
    for r in results:
        assert r['is_simulated'] == 1
        assert r['simulation_scenario'] == 'ssh_bruteforce'
        assert r['consensus_state'] is not None

    conn.close()


def test_api_test_history_and_cleanup(flask_client):
    """Verify GET /api/test/history and POST /api/test/cleanup endpoints."""
    # Inject a scenario to ensure test data exists
    flask_client.post('/api/test/inject-anomaly', json={'scenario': 'dos_burst'})

    # Test history retrieval
    res_hist = flask_client.get('/api/test/history')
    assert res_hist.status_code == 200
    hist_data = res_hist.get_json()
    assert hist_data['status'] == 'success'
    assert hist_data['count'] > 0
    assert any(h['simulation_scenario'] == 'dos_burst' for h in hist_data['history'])

    # Test cleanup
    res_clean = flask_client.post('/api/test/cleanup')
    assert res_clean.status_code == 200
    clean_data = res_clean.get_json()
    assert clean_data['status'] == 'success'
    assert 'deleted' in clean_data
    assert 'uploaded_files' in clean_data['deleted']
    assert 'parsed_logs' in clean_data['deleted']

    # Verify history is now empty
    res_hist_after = flask_client.get('/api/test/history')
    assert res_hist_after.get_json()['count'] == 0


def test_simulation_feature_extraction_authenticity():
    """
    Verifies that all 8 behavioral features are genuinely extracted across the 5 scenarios
    without permanent zeroing, fabricated constants, or semantic misattribution.
    """
    # 1. SSH Brute Force -> Authentic failed logins and login attempts
    ssh_sim = generate_synthetic_scenario_logs('ssh_bruteforce')
    ssh_feats = BehavioralFeatureExtractor.extract_features(
        DataCleaner.clean(LogParser.parse_logs(ssh_sim['raw_text']))
    )
    assert ssh_feats['failed_login_attempts'].max() >= 3, "SSH brute-force failed login attempts not extracted"
    assert ssh_feats['login_attempts'].max() >= 3, "SSH brute-force login attempts not extracted"
    assert ssh_feats['error_count'].max() >= 3

    # 2. Buffer Overflow -> Extreme sequence length, error pattern 4, unknown events
    bof_sim = generate_synthetic_scenario_logs('buffer_overflow')
    bof_feats = BehavioralFeatureExtractor.extract_features(
        DataCleaner.clean(LogParser.parse_logs(bof_sim['raw_text']))
    )
    assert bof_feats['sequence_length'].max() > 200, "Buffer overflow sequence length not captured"
    assert bof_feats['unknown_events'].max() >= 1, "Buffer overflow unknown events not captured"
    assert bof_feats['error_pattern'].max() == 4, "Buffer overflow error pattern 4 not categorized"

    # 3. Privilege Escalation -> Auth failures and unknown events
    priv_sim = generate_synthetic_scenario_logs('privilege_escalation')
    priv_feats = BehavioralFeatureExtractor.extract_features(
        DataCleaner.clean(LogParser.parse_logs(priv_sim['raw_text']))
    )
    assert priv_feats['login_attempts'].max() >= 1, "Privilege escalation login attempts not captured"
    assert priv_feats['failed_login_attempts'].max() >= 1, "Privilege escalation failed logins not captured"
    assert priv_feats['error_pattern'].max() == 4, "Security denial error pattern 4 not categorized"
    assert priv_feats['unknown_events'].max() >= 1, "Exploit probe unknown events not captured"

    # 4. Directory Traversal -> Path traversal error without misattributing to login attempts
    dt_sim = generate_synthetic_scenario_logs('directory_traversal')
    dt_feats = BehavioralFeatureExtractor.extract_features(
        DataCleaner.clean(LogParser.parse_logs(dt_sim['raw_text']))
    )
    assert dt_feats['failed_login_attempts'].max() == 0, "Web directory traversal falsely attributed to login failure"
    assert dt_feats['login_attempts'].max() == 0, "Web directory traversal falsely attributed to login attempt"
    assert dt_feats['error_count'].max() >= 1, "Directory traversal errors not counted"
    assert dt_feats['error_pattern'].max() == 4, "Permission denied pattern not categorized"

    # 5. DoS Burst -> High event frequency, warnings, OOM kill pattern 3
    dos_sim = generate_synthetic_scenario_logs('dos_burst')
    dos_feats = BehavioralFeatureExtractor.extract_features(
        DataCleaner.clean(LogParser.parse_logs(dos_sim['raw_text']))
    )
    assert dos_feats['event_frequency'].max() >= 3, "DoS frequency burst not captured"
    assert dos_feats['warning_count'].max() >= 1, "DoS SYN-flood/worker warnings not counted"
    assert dos_feats['error_pattern'].max() == 3, "Out-of-memory error pattern 3 not categorized"


def test_shap_unsupported_model_graceful_handling():
    """
    Verifies that passing a non-tree estimator (e.g. One-Class SVM) to ShapExplainerEngine
    handles the unsupported explainer gracefully without raising unhandled errors or fabricating values.
    """
    from ml_engine import OneClassSVMValidator, ShapExplainerEngine

    ocsvm_val = OneClassSVMValidator()
    df_sample = pd.DataFrame([{
        'event_frequency': 19.0, 'sequence_length': 7.0, 'error_count': 0.0, 'error_pattern': 0.0,
        'login_attempts': 0.0, 'failed_login_attempts': 0.0, 'warning_count': 0.0, 'unknown_events': 0.0,
        'log_id': 1
    }])
    preds = [{'log_id': 1, 'is_anomaly': 1, 'anomaly_score': 0.85, 'severity': 'High'}]

    explanations = ShapExplainerEngine.explain(ocsvm_val.model, df_sample, preds)
    assert len(explanations) == 1
    exp = explanations[0]
    assert exp['model_name'] == 'One-Class SVM'
    assert exp['explanation_status'] == 'unsupported_model'
    assert 'unsupported' in exp['natural_explanation'].lower() or 'unavailable' in exp['natural_explanation'].lower()
    # Confirm values are not fabricated
    assert all(v == 0.0 for v in exp['feature_contributions'].values())


def test_shap_empty_features_graceful_handling():
    """Verifies that ShapExplainerEngine handles empty input gracefully."""
    from ml_engine import IsolationForestDetector, ShapExplainerEngine

    detector = IsolationForestDetector()
    empty_df = pd.DataFrame(columns=FEATURE_SCHEMA)
    explanations = ShapExplainerEngine.explain(detector.model, empty_df, [])
    assert explanations == []


def test_simulation_cleanup_atomic_and_real_data_protection(flask_client):
    """
    Verifies that cleanup:
    1. Strictly targets is_simulated = 1 records.
    2. Protects real records, even if their filename contains 'Synthetic'.
    3. Returns table-by-table deleted counts.
    4. Is idempotent when run repeatedly.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Insert a real user file that happens to have 'Synthetic' in its filename
    cursor.execute("""
        INSERT INTO uploaded_files (filename, total_logs, normal_count, anomaly_count, is_simulated)
        VALUES ('Synthetic_Real_Production_Run.log', 10, 10, 0, 0)
    """)
    real_file_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO parsed_logs (file_id, timestamp, hostname, service, log_level, event_type, message, is_simulated)
        VALUES (?, '2026-08-08T12:00:00', 'prod-srv', 'kernel', 'INFO', 'SYSTEM_EVENT', 'Real log entry', 0)
    """, (real_file_id,))
    real_log_id = cursor.lastrowid

    # 2. Insert a simulated run
    cursor.execute("""
        INSERT INTO uploaded_files (filename, total_logs, normal_count, anomaly_count, is_simulated, simulation_scenario)
        VALUES ('Synthetic_Attack_Test.log', 5, 2, 3, 1, 'ssh_bruteforce')
    """)
    sim_file_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO parsed_logs (file_id, timestamp, hostname, service, log_level, event_type, message, is_simulated, simulation_scenario)
        VALUES (?, '2026-08-08T12:01:00', 'sim-srv', 'sshd', 'ERROR', 'AUTHENTICATION', 'Failed password', 1, 'ssh_bruteforce')
    """, (sim_file_id,))
    sim_log_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO anomaly_results (file_id, log_id, is_anomaly, anomaly_score, severity, is_simulated, simulation_scenario)
        VALUES (?, ?, 1, 0.88, 'Critical', 1, 'ssh_bruteforce')
    """, (sim_file_id, sim_log_id))

    cursor.execute("""
        INSERT INTO shap_explanations (file_id, log_id, is_simulated)
        VALUES (?, ?, 1)
    """, (sim_file_id, sim_log_id))

    conn.commit()

    # 3. Execute cleanup via POST /api/test/cleanup
    res = flask_client.post('/api/test/cleanup')
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'success'
    deleted = data['deleted']
    assert deleted['uploaded_files'] >= 1
    assert deleted['parsed_logs'] >= 1
    assert deleted['anomaly_results'] >= 1
    assert deleted['shap_explanations'] >= 1

    # 4. Verify REAL file and log still exist!
    cursor.execute("SELECT id FROM uploaded_files WHERE id = ?", (real_file_id,))
    assert cursor.fetchone() is not None, "Real file was incorrectly deleted by cleanup!"

    cursor.execute("SELECT id FROM parsed_logs WHERE id = ?", (real_log_id,))
    assert cursor.fetchone() is not None, "Real log was incorrectly deleted by cleanup!"

    # 5. Verify SIMULATED file and log are deleted
    cursor.execute("SELECT id FROM uploaded_files WHERE id = ?", (sim_file_id,))
    assert cursor.fetchone() is None, "Simulated file was not deleted by cleanup!"

    cursor.execute("SELECT id FROM parsed_logs WHERE id = ?", (sim_log_id,))
    assert cursor.fetchone() is None, "Simulated log was not deleted by cleanup!"

    # 6. Verify idempotency
    res2 = flask_client.post('/api/test/cleanup')
    assert res2.status_code == 200
    assert res2.get_json()['deleted']['uploaded_files'] == 0

    # Cleanup the test real file
    cursor.execute("DELETE FROM parsed_logs WHERE id = ?", (real_log_id,))
    cursor.execute("DELETE FROM uploaded_files WHERE id = ?", (real_file_id,))
    conn.commit()
    conn.close()
