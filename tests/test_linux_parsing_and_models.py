"""
Comprehensive test suite verifying Linux syslog parsing, SSH/Sudo event normalization,
feature extraction, unsupervised anomaly detection (Isolation Forest & One-Class SVM),
and SHAP explainability consistency.

Test A: Successful SSH password login (sahana)
Test B: Successful SSH publickey login
Test C: Single Failed SSH login
Test D: Repeated failed logins (Brute force burst)
Test E: Mixed authentication sequence
Test F: Sudo authentication failure with multiple attempts
Test G: Malformed / unsupported log handling
Test H: Score and explanation consistency
"""

import pytest
import pandas as pd
from ml_engine import (
    LogParser,
    DataCleaner,
    BehavioralFeatureExtractor,
    IsolationForestDetector,
    OneClassSVMValidator,
    ShapExplainerEngine,
    run_full_pipeline,
    FEATURE_SCHEMA
)


def test_case_a_successful_ssh_password_login():
    """Test A: Normal Linux SSH login must parse cleanly, yield normal features, and score Normal (< 0.50)."""
    raw_log = "Oct 20 10:00:01 server01 sshd[1201]: Accepted password for sahana from 192.168.1.10 port 50221 ssh2"
    
    # 1. Parsing verification
    parsed = LogParser.parse_line(raw_log, line_index=0)
    assert parsed is not None
    assert parsed['os_type'] == 'Linux'
    assert parsed['hostname'] == 'server01'
    assert parsed['service'] == 'sshd'
    assert parsed['pid'] == '1201'
    assert parsed['user'] == 'sahana'
    assert parsed['src_ip'] == '192.168.1.10'
    assert parsed['port'] == 50221
    assert parsed['auth_result'] == 'success'
    assert parsed['auth_method'] == 'password'
    assert parsed['log_level'] == 'INFO'
    assert parsed['event_type'] == 'AUTHENTICATION'
    assert parsed['action'] == 'SSH Authentication Succeeded'
    assert 'sahana' in parsed['description']
    assert 'server01' in parsed['description']
    assert parsed['parsing_status'] == 'success'

    # 2. Pipeline execution verification
    res = run_full_pipeline(raw_log)
    feats = res['features'][0]
    det = res['detection_results'][0]
    shap = res['shap_explanations'][0]

    # Feature verification: legitimate single login
    assert feats['event_frequency'] == 1.0
    assert feats['sequence_length'] == len(parsed['message'])
    assert feats['error_count'] == 0
    assert feats['error_pattern'] == 0
    assert feats['login_attempts'] == 1
    assert feats['failed_login_attempts'] == 0
    assert feats['warning_count'] == 0
    assert feats['unknown_events'] == 0

    # Model inference verification: strictly normal baseline (< 0.50)
    assert det['is_anomaly'] == 0, f"Expected Normal (0), got {det['is_anomaly']} with score {det['anomaly_score']}"
    assert det['anomaly_score'] < 0.50, f"Anomaly score {det['anomaly_score']} must be below 0.50 threshold"
    assert det['severity'] == 'Normal'
    assert det['consensus_state'] == 'Consensus Normal'
    assert det['consensus_agreement'] is True

    # Explanation verification: must describe Linux SSH login, NOT a Windows event
    assert "Windows" not in shap['what_happened']
    assert "computer 20" not in shap['what_happened']
    assert "sahana" in shap['what_happened']
    assert "192.168.1.10" in shap['what_happened']
    assert "server01" in shap['what_happened']
    assert shap['top_reason'] == 'Normal Behavior'
    assert "normal" in shap['why_suspicious'].lower()
    assert "No action required" in shap['recommended_action']


def test_case_b_successful_ssh_publickey_login():
    """Test B: Successful publickey SSH login verification."""
    raw_log = "Oct 20 10:05:22 server01 sshd[1245]: Accepted publickey for sahana from 192.168.1.10 port 50222 ssh2: RSA SHA256:abc123xyz"
    
    parsed = LogParser.parse_line(raw_log, line_index=0)
    assert parsed['auth_result'] == 'success'
    assert parsed['auth_method'] == 'publickey'
    assert parsed['user'] == 'sahana'
    assert parsed['src_ip'] == '192.168.1.10'
    assert parsed['port'] == 50222
    assert parsed['log_level'] == 'INFO'

    res = run_full_pipeline(raw_log)
    det = res['detection_results'][0]
    assert det['is_anomaly'] == 0
    assert det['anomaly_score'] < 0.50
    assert det['severity'] == 'Normal'
    assert "public key" in res['shap_explanations'][0]['what_happened'].lower()


def test_case_c_single_failed_ssh_login():
    """Test C: Single failed SSH password login increments failed_login_attempts."""
    raw_log = "Oct 20 10:10:00 server01 sshd[1290]: Failed password for sahana from 192.168.1.10 port 50223 ssh2"
    
    parsed = LogParser.parse_line(raw_log, line_index=0)
    assert parsed['auth_result'] == 'failure'
    assert parsed['auth_method'] == 'password'
    assert parsed['user'] == 'sahana'
    assert parsed['src_ip'] == '192.168.1.10'
    assert parsed['log_level'] == 'ERROR'
    assert parsed['action'] == 'SSH Authentication Failed'

    res = run_full_pipeline(raw_log)
    feats = res['features'][0]
    assert feats['login_attempts'] == 1
    assert feats['failed_login_attempts'] == 1
    assert feats['error_pattern'] == 1
    assert "failed" in res['shap_explanations'][0]['what_happened'].lower()


def test_case_d_repeated_failed_logins_brute_force():
    """Test D: Repeated rapid failed SSH logins trigger anomaly detection and high failed login counts."""
    logs = [
        f"Oct 20 10:12:{10 + i:02d} server01 sshd[{1300 + i}]: Failed password for invalid user user{i} from 198.51.100.45 port {40000 + i} ssh2"
        for i in range(10)
    ]
    raw_content = "\n".join(logs)
    res = run_full_pipeline(raw_content)

    assert len(res['detection_results']) == 10
    # Center logs in window should have high failed login attempts
    mid_feats = res['features'][5]
    assert mid_feats['failed_login_attempts'] >= 5
    assert mid_feats['login_attempts'] >= 5

    # At least some of the burst events should be detected as anomaly
    anomalies = [d for d in res['detection_results'] if d['is_anomaly'] == 1]
    assert len(anomalies) > 0, "Repeated 10x brute force failure burst must trigger anomaly results"

    # SHAP explanations should emphasize failed logins or frequency
    for a in anomalies:
        shap = res['shap_explanations'][int(a['log_id']) - 1]
        assert "Investigate" in shap['recommended_action']


def test_case_e_mixed_authentication_sequence():
    """Test E: Mixed sequence of normal operations and authentication events."""
    lines = [
        "Oct 20 10:20:00 server01 systemd: Starting Daily apt download activities...",
        "Oct 20 10:20:05 server01 sshd[1401]: Failed password for invalid user admin from 203.0.113.10 port 49152 ssh2",
        "Oct 20 10:20:10 server01 sshd[1402]: Accepted password for sahana from 192.168.1.10 port 50225 ssh2",
        "Oct 20 10:20:15 server01 systemd: Started Daily apt download activities."
    ]
    raw_content = "\n".join(lines)
    res = run_full_pipeline(raw_content)

    assert len(res['parsed_logs']) == 4
    # The accepted password log is index 2
    accepted_log = res['parsed_logs'][2]
    assert accepted_log['user'] == 'sahana'
    assert accepted_log['auth_result'] == 'success'
    assert accepted_log['log_level'] == 'INFO'


def test_case_f_sudo_authentication_failure():
    """Test F: Sudo multi-attempt authentication failure parsing and feature extraction."""
    raw_log = "Oct 20 10:15:00 server01 sudo: sahana : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/sahana ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    
    parsed = LogParser.parse_line(raw_log, line_index=0)
    assert parsed['os_type'] == 'Linux'
    assert parsed['service'] == 'sudo'
    assert parsed['user'] == 'sahana'
    assert parsed['auth_result'] == 'failure'
    assert parsed['failed_attempts_count'] == 3
    assert parsed['log_level'] == 'ERROR'
    assert "Sudo privilege elevation failure" in parsed['description']

    res = run_full_pipeline(raw_log)
    feats = res['features'][0]
    assert feats['failed_login_attempts'] == 3
    assert feats['login_attempts'] == 1


def test_case_g_malformed_unsupported_log():
    """Test G: Malformed / unsupported log produces transparent warnings without bogus tokens."""
    raw_log = "Garbage payload 12345 !@#$%^&* without standard header"
    
    parsed = LogParser.parse_line(raw_log, line_index=0)
    assert parsed is not None
    assert parsed['parsing_status'] == 'unsupported_format'
    assert parsed['parsing_warning'] is not None
    assert parsed['hostname'] == 'unknown_host'
    assert parsed['service'] == 'unknown_service'
    assert parsed['message'] == raw_log
    # Must NOT have parsed bogus tokens like hostname="20" or service="10:00:01"
    assert parsed['hostname'] != '20'
    assert parsed['service'] != '10:00:01'

    res = run_full_pipeline(raw_log)
    shap = res['shap_explanations'][0]
    assert "Windows system event logged from 10:00:01 on computer 20" not in shap['what_happened']


def test_case_h_score_and_explanation_consistency():
    """Test H: Full consistency across score, classification, consensus, and SHAP narrative."""
    normal_log = "Oct 20 10:00:01 server01 sshd[1201]: Accepted password for sahana from 192.168.1.10 port 50221 ssh2"
    res_norm = run_full_pipeline(normal_log)
    d_norm = res_norm['detection_results'][0]
    s_norm = res_norm['shap_explanations'][0]

    # Normal consistency
    assert d_norm['is_anomaly'] == 0
    assert d_norm['anomaly_score'] < 0.50
    assert d_norm['severity'] == 'Normal'
    assert s_norm['top_reason'] == 'Normal Behavior'
    assert "No action required" in s_norm['recommended_action']
    assert "normal" in s_norm['why_suspicious'].lower()

    # Active model consistency
    import os
    os.environ['SMARTLOG_IF_MODEL'] = 'active'
    try:
        res_act = run_full_pipeline(normal_log)
        d_act = res_act['detection_results'][0]
        assert d_act['is_anomaly'] == 0
        assert d_act['anomaly_score'] < 0.50
        assert d_act['severity'] == 'Normal'
    finally:
        os.environ['SMARTLOG_IF_MODEL'] = 'hdfs'


def test_case_i_backdoor_useradd_detection():
    """Test I: Backdoor user creation (UID=0, GID=0) must be detected as an anomaly."""
    backdoor_log = "Oct 20 10:15:40 server01 useradd[1501]: new user: name=unknownuser, UID=0, GID=0, home=/root, shell=/bin/bash"
    res = run_full_pipeline(backdoor_log)
    d = res['detection_results'][0]
    p = res['parsed_logs'][0]
    s = res['shap_explanations'][0]

    assert p['service'] == 'useradd'
    assert p['user'] == 'unknownuser'
    assert p['log_level'] == 'ERROR'
    assert p['event_type'] == 'SECURITY'
    assert d['is_anomaly'] == 1
    assert d['anomaly_score'] >= 0.50
    assert "backdoor" in p['description'].lower()
    assert "IMMEDIATE ACTION REQUIRED" in s['recommended_action']
