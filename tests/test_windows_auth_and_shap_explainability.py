import pytest
import os
import sys
import json
import numpy as np
import pandas as pd

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from incident_correlator import WindowsAuthenticationCorrelator, LOGON_TYPE_MAP, STATUS_CODE_MAP
from system_log_collector import parse_wevtutil_xml_snippet
from ml_engine import (
    LogParser,
    ShapExplainerEngine,
    IsolationForestDetector,
    BehavioralFeatureExtractor,
    run_full_pipeline,
    FEATURE_SCHEMA
)
from app import format_db_row_to_event


# ==============================================================================
# TEST 1: Windows repeated Event 4625 grouped into incident
# ==============================================================================
def test_windows_repeated_event_4625_grouping():
    events = [
        {
            'id': 'sec-4625-101',
            'record_id': 101,
            'event_id': 4625,
            'action': 'Logon Failure',
            'user': 'Sahana',
            'computer': 'Rocky',
            'domain': 'Rocky',
            'logon_type': '2',
            'timestamp': '2026-10-20 22:10:05',
            'status_code': '0xc000006d',
            'sub_status': '0xc000006a'
        },
        {
            'id': 'sec-4625-102',
            'record_id': 102,
            'event_id': 4625,
            'action': 'Logon Failure',
            'user': 'Sahana',
            'computer': 'Rocky',
            'domain': 'Rocky',
            'logon_type': '2',
            'timestamp': '2026-10-20 22:10:18',
            'status_code': '0xc000006d',
            'sub_status': '0xc000006a'
        },
        {
            'id': 'sec-4625-103',
            'record_id': 103,
            'event_id': 4625,
            'action': 'Logon Failure',
            'user': 'Sahana',
            'computer': 'Rocky',
            'domain': 'Rocky',
            'logon_type': '2',
            'timestamp': '2026-10-20 22:10:32',
            'status_code': '0xc000006d',
            'sub_status': '0xc000006a'
        }
    ]

    res = WindowsAuthenticationCorrelator.correlate_events(events, time_window_seconds=300)
    assert res['has_active_attack_pattern'] is True
    assert len(res['incidents']) == 1

    inc = res['incidents'][0]
    assert inc['account'] == 'Sahana'
    assert inc['failure_count'] == 3
    assert inc['has_subsequent_success'] is False
    assert inc['risk_level'] == 'Medium'
    assert 'Interactive / Local Console' in inc['logon_type']
    assert len(inc['participating_record_ids']) >= 3


# ==============================================================================
# TEST 2: Repeated Event 4625 followed by Event 4624 / 4801 success correlation
# ==============================================================================
def test_windows_repeated_failures_followed_by_success():
    events = [
        {
            'id': 'sec-4625-201',
            'record_id': 201,
            'event_id': 4625,
            'action': 'Logon Failure',
            'user': 'AdminUser',
            'computer': 'DESKTOP-PC',
            'domain': 'WORKGROUP',
            'logon_type': '2',
            'timestamp': '2026-10-20 22:15:00'
        },
        {
            'id': 'sec-4625-202',
            'record_id': 202,
            'event_id': 4625,
            'action': 'Logon Failure',
            'user': 'AdminUser',
            'computer': 'DESKTOP-PC',
            'domain': 'WORKGROUP',
            'logon_type': '2',
            'timestamp': '2026-10-20 22:15:15'
        },
        {
            'id': 'sec-4625-203',
            'record_id': 203,
            'event_id': 4625,
            'action': 'Logon Failure',
            'user': 'AdminUser',
            'computer': 'DESKTOP-PC',
            'domain': 'WORKGROUP',
            'logon_type': '2',
            'timestamp': '2026-10-20 22:15:30'
        },
        {
            'id': 'sec-4801-204',
            'record_id': 204,
            'event_id': 4801,
            'action': 'Workstation Unlocked',
            'user': 'AdminUser',
            'computer': 'DESKTOP-PC',
            'domain': 'WORKGROUP',
            'timestamp': '2026-10-20 22:15:45'
        }
    ]

    res = WindowsAuthenticationCorrelator.correlate_events(events, time_window_seconds=300)
    assert res['has_active_attack_pattern'] is True
    assert len(res['incidents']) == 1

    inc = res['incidents'][0]
    assert inc['failure_count'] == 3
    assert inc['has_subsequent_success'] is True
    assert inc['risk_level'] == 'High'
    assert inc['success_time'] == '2026-10-20 22:15:45'
    assert 'followed by a successful logon' in inc['incident_description']


# ==============================================================================
# TEST 3: Isolated single Event 4625 does not trigger multi-attempt incident
# ==============================================================================
def test_isolated_single_4625_no_false_alarm():
    events = [
        {
            'id': 'sec-4625-301',
            'record_id': 301,
            'event_id': 4625,
            'action': 'Logon Failure',
            'user': 'SingleTypoUser',
            'computer': 'Rocky',
            'timestamp': '2026-10-20 22:20:00'
        }
    ]

    res = WindowsAuthenticationCorrelator.correlate_events(events)
    assert res['has_active_attack_pattern'] is False
    assert len(res['incidents']) == 0
    assert res['correlated_events'][0]['is_correlated_incident'] is False


# ==============================================================================
# TEST 4: Routine background telemetry segregated as non-correlated
# ==============================================================================
def test_background_telemetry_segregation():
    events = [
        {
            'id': 'ps-40961-401',
            'record_id': 401,
            'event_id': 40961,
            'provider': 'Microsoft-Windows-PowerShell',
            'action': 'PowerShell Activity',
            'event_type': 'POWERSHELL_TELEMETRY',
            'timestamp': '2026-10-20 22:25:00'
        },
        {
            'id': 'wlan-10000-402',
            'record_id': 402,
            'event_id': 10000,
            'provider': 'Microsoft-Windows-WLAN-AutoConfig',
            'action': 'Wireless Connectivity Event',
            'event_type': 'NETWORK_CONNECTIVITY',
            'timestamp': '2026-10-20 22:25:02'
        },
        {
            'id': 'proc-4688-403',
            'record_id': 403,
            'event_id': 4688,
            'provider': 'Microsoft-Windows-Security-Auditing',
            'action': 'WhatsApp Started',
            'application_name': 'WhatsApp',
            'timestamp': '2026-10-20 22:25:05'
        }
    ]

    res = WindowsAuthenticationCorrelator.correlate_events(events)
    assert res['has_active_attack_pattern'] is False
    for evt in res['correlated_events']:
        assert evt['is_correlated_incident'] is False
        assert evt['is_background_telemetry'] is True


# ==============================================================================
# TEST 5: Windows event parsing and normalization (no Linux misclassification)
# ==============================================================================
def test_windows_event_parsing_and_no_linux_mislabeling():
    win_line = "2026-10-20 22:30:10 Rocky Microsoft-Windows-Security-Auditing[4625]: An account failed to log on."
    parsed = LogParser.parse_line(win_line)

    assert parsed is not None
    assert parsed['os_type'] == 'Windows'
    assert 'Microsoft-Windows-Security-Auditing' in parsed['service']

    # Now verify format_db_row_to_event preserves Windows metadata
    db_row = {
        'id': 501,
        'timestamp': '2026-10-20 22:30:10',
        'service': 'Microsoft-Windows-Security-Auditing[4625]',
        'channel': 'Security',
        'event_id': 4625,
        'user': 'Sahana',
        'computer': 'Rocky',
        'parent_process': 'explorer.exe',
        'parent_process_name': 'explorer.exe',
        'is_anomaly': 1,
        'anomaly_score': 0.75,
        'severity': 'High'
    }

    formatted = format_db_row_to_event(db_row)
    assert 'Linux' not in formatted['source_label']
    assert formatted['parent_process'] != 'systemd'
    assert formatted['parent_process'] == 'explorer.exe'
    assert formatted['channel'] == 'Security'
    assert formatted['computer'] == 'Rocky'
    assert formatted['user'] == 'Sahana'


# ==============================================================================
# TEST 6: Native wevtutil XML parsing without string-split </Data> artifacts
# ==============================================================================
def test_wevtutil_xml_parsing_clean_data_tags():
    sample_xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
        <System>
            <Provider Name='Microsoft-Windows-Security-Auditing'/>
            <EventID>4625</EventID>
            <Level>0</Level>
            <EventRecordID>34731</EventRecordID>
            <TimeCreated SystemTime='2026-10-20T22:10:04.1234567Z'/>
            <Execution ProcessID='752'/>
            <Channel>Security</Channel>
            <Computer>Rocky</Computer>
        </System>
        <EventData>
            <Data Name='TargetUserName'>Sahana</Data>
            <Data Name='TargetDomainName'>Rocky</Data>
            <Data Name='Status'>0xc000006d</Data>
            <Data Name='SubStatus'>0xc000006a</Data>
            <Data Name='LogonType'>2</Data>
        </EventData>
    </Event>"""

    parsed_events = parse_wevtutil_xml_snippet(sample_xml, default_channel='Security')
    assert len(parsed_events) == 1
    evt = parsed_events[0]

    assert evt['event_id'] == 4625
    assert evt['record_id'] == 34731
    assert evt['user'] == 'Sahana'
    assert '</Data' not in evt['user']
    assert evt['domain'] == 'Rocky'
    assert '</Data' not in evt['domain']
    assert evt['logon_type'] == '2'
    assert evt['status_code'] == '0xc000006d'
    assert evt['sub_status'] == '0xc000006a'


# ==============================================================================
# TEST 7: Event 4800 (Lock) and Event 4801 (Unlock) parsing
# ==============================================================================
def test_wevtutil_lock_and_unlock_events():
    xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
        <System>
            <Provider Name='Microsoft-Windows-Security-Auditing'/>
            <EventID>4800</EventID>
            <EventRecordID>34700</EventRecordID>
            <TimeCreated SystemTime='2026-10-20T22:05:00.0000000Z'/>
            <Channel>Security</Channel>
            <Computer>Rocky</Computer>
        </System>
        <EventData>
            <Data Name='TargetUserName'>Sahana</Data>
            <Data Name='TargetDomainName'>Rocky</Data>
        </EventData>
    </Event>
    <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
        <System>
            <Provider Name='Microsoft-Windows-Security-Auditing'/>
            <EventID>4801</EventID>
            <EventRecordID>34740</EventRecordID>
            <TimeCreated SystemTime='2026-10-20T22:11:00.0000000Z'/>
            <Channel>Security</Channel>
            <Computer>Rocky</Computer>
        </System>
        <EventData>
            <Data Name='TargetUserName'>Sahana</Data>
            <Data Name='TargetDomainName'>Rocky</Data>
        </EventData>
    </Event>"""

    parsed = parse_wevtutil_xml_snippet(xml, default_channel='Security')
    assert len(parsed) == 2

    assert parsed[0]['event_id'] == 4800
    assert parsed[0]['event_type'] == 'WORKSTATION_LOCKED'
    assert parsed[0]['action'] == 'Workstation Locked'
    assert parsed[0]['user'] == 'Sahana'

    assert parsed[1]['event_id'] == 4801
    assert parsed[1]['event_type'] == 'WORKSTATION_UNLOCKED'
    assert parsed[1]['action'] == 'Workstation Unlocked'
    assert parsed[1]['user'] == 'Sahana'


# ==============================================================================
# TEST 8: ShapExplainerEngine generates all 8 structured plain-English sections
# ==============================================================================
def test_shap_explainer_eight_sections():
    # Build minimal training data to fit IsolationForest
    n_samples = 50
    X_train = pd.DataFrame({
        'event_frequency': np.random.uniform(0.1, 1.0, n_samples),
        'sequence_length': np.random.uniform(50, 150, n_samples),
        'error_count': np.zeros(n_samples),
        'error_pattern': np.zeros(n_samples),
        'login_attempts': np.ones(n_samples),
        'failed_login_attempts': np.zeros(n_samples),
        'warning_count': np.zeros(n_samples),
        'unknown_events': np.zeros(n_samples)
    })

    detector = IsolationForestDetector(n_estimators=50, contamination=0.1)
    detection_results, X_df = detector.fit_predict(X_train)

    parsed_logs = [
        {
            'log_id': idx + 1,
            'event_id': 4688 if idx > 0 else 4625,
            'channel': 'Security',
            'service': 'Microsoft-Windows-Security-Auditing',
            'user': 'Sahana',
            'computer': 'Rocky',
            'message': 'Failed logon attempt' if idx == 0 else 'Process created',
            'action': 'Logon Failure' if idx == 0 else 'Application Started'
        }
        for idx in range(n_samples)
    ]

    explanations = ShapExplainerEngine.explain(
        detector.model,
        X_df,
        detection_results,
        parsed_logs=parsed_logs,
        raw_features=X_train
    )

    assert len(explanations) == n_samples
    first_exp = explanations[0]

    # Verify all 8 structured sections are populated
    assert 'what_happened' in first_exp and len(first_exp['what_happened']) > 0
    assert 'application_source' in first_exp and len(first_exp['application_source']) > 0
    assert 'what_it_means' in first_exp and len(first_exp['what_it_means']) > 0
    assert 'why_flagged' in first_exp and len(first_exp['why_flagged']) > 0
    assert 'evidence' in first_exp and len(first_exp['evidence']) > 0
    assert 'risk_assessment' in first_exp and len(first_exp['risk_assessment']) > 0
    assert 'recommended_action' in first_exp and len(first_exp['recommended_action']) > 0
    assert 'limitations_uncertainty' in first_exp and len(first_exp['limitations_uncertainty']) > 0

    # Verify technical details dictionary exists for advanced view
    assert 'technical_details' in first_exp
    assert 'feature_contributions' in first_exp['technical_details']
    assert 'model_name' in first_exp['technical_details']

    # Verify backward compatibility
    assert 'natural_explanation' in first_exp
    assert 'top_3_human_reasons' in first_exp
    assert 'feature_contributions' in first_exp


# ==============================================================================
# TEST 9: Technical feature name translations are human-readable
# ==============================================================================
def test_shap_feature_translations_are_human_readable():
    desc_map = ShapExplainerEngine.FEATURE_HUMAN_DESCRIPTIONS

    assert 'Repeated Authentication Failures' in desc_map['Failed Login Attempts']
    assert 'Authentication Activity Volume' in desc_map['Login Attempts']
    assert 'Log Detail / Message Complexity' in desc_map['Sequence Length']
    assert 'Operational Errors' in desc_map['Error Count']
    assert 'Unusual Error Indicator' in desc_map['Error Pattern']
    assert 'Event Velocity' in desc_map['Event Frequency']
    assert 'System Warnings' in desc_map['Warning Count']
    assert 'Uncommon Event Identifiers' in desc_map['Unknown Events']


# ==============================================================================
# TEST 10: End-to-end integration: Windows lock-screen authentication simulation
# ==============================================================================
def test_end_to_end_lock_screen_authentication_pipeline():
    # Simulate: Lock workstation, 3 failed passwords, unlock workstation
    simulated_events = [
        {
            'id': 'sec-4800-1',
            'record_id': 1,
            'event_id': 4800,
            'action': 'Workstation Locked',
            'user': 'Sahana',
            'computer': 'Rocky',
            'domain': 'Rocky',
            'timestamp': '2026-10-20 22:10:00'
        },
        {
            'id': 'sec-4625-2',
            'record_id': 2,
            'event_id': 4625,
            'action': 'Logon Failure',
            'user': 'Sahana',
            'computer': 'Rocky',
            'domain': 'Rocky',
            'logon_type': '2',
            'timestamp': '2026-10-20 22:10:15',
            'status_code': '0xc000006d',
            'sub_status': '0xc000006a'
        },
        {
            'id': 'sec-4625-3',
            'record_id': 3,
            'event_id': 4625,
            'action': 'Logon Failure',
            'user': 'Sahana',
            'computer': 'Rocky',
            'domain': 'Rocky',
            'logon_type': '2',
            'timestamp': '2026-10-20 22:10:30',
            'status_code': '0xc000006d',
            'sub_status': '0xc000006a'
        },
        {
            'id': 'sec-4625-4',
            'record_id': 4,
            'event_id': 4625,
            'action': 'Logon Failure',
            'user': 'Sahana',
            'computer': 'Rocky',
            'domain': 'Rocky',
            'logon_type': '2',
            'timestamp': '2026-10-20 22:10:45',
            'status_code': '0xc000006d',
            'sub_status': '0xc000006a'
        },
        {
            'id': 'sec-4801-5',
            'record_id': 5,
            'event_id': 4801,
            'action': 'Workstation Unlocked',
            'user': 'Sahana',
            'computer': 'Rocky',
            'domain': 'Rocky',
            'timestamp': '2026-10-20 22:11:10'
        }
    ]

    corr = WindowsAuthenticationCorrelator.correlate_events(simulated_events)
    assert corr['has_active_attack_pattern'] is True
    assert len(corr['incidents']) == 1

    incident = corr['incidents'][0]
    assert incident['failure_count'] == 3
    assert incident['account'] == 'Sahana'
    assert incident['has_subsequent_success'] is True
    assert incident['risk_level'] == 'High'
    assert incident['first_failure_time'] == '2026-10-20 22:10:15'
    assert incident['last_failure_time'] == '2026-10-20 22:10:45'
    assert incident['success_time'] == '2026-10-20 22:11:10'

    # Verify correlated events link to the incident
    correlated = corr['correlated_events']
    assert len(correlated) == 5
    # The 3 failures and the unlock event are linked
    linked_events = [e for e in correlated if e.get('is_correlated_incident') is True]
    assert len(linked_events) == 4
    for e in linked_events:
        assert e['correlation_incident_id'] == 'INC-AUTH-1'
