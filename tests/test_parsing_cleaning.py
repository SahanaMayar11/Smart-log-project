import pytest
from ml_engine import LogParser, DataCleaner


def test_parse_standard_syslog_line():
    line = "2026-08-08T10:00:01 server-01 systemd[1]: Started System Logging Service."
    parsed = LogParser.parse_line(line, line_index=0)
    
    assert parsed is not None
    assert parsed['log_id'] == 1
    assert parsed['timestamp'] == "2026-08-08T10:00:01"
    assert parsed['hostname'] == "server-01"
    assert "systemd" in parsed['service']
    assert parsed['log_level'] == "INFO"
    assert parsed['event_type'] == "SYSTEM_EVENT"
    assert parsed['message'] == "Started System Logging Service."


def test_parse_auth_failed_line():
    line = "2026-08-08T10:01:15 server-01 sshd[1489]: Failed password for invalid user admin from 198.51.100.45 port 41234 ssh2"
    parsed = LogParser.parse_line(line, line_index=1)
    
    assert parsed is not None
    assert parsed['log_id'] == 2
    assert parsed['log_level'] == "ERROR"
    assert parsed['event_type'] == "AUTHENTICATION"
    assert "Failed password" in parsed['message']


def test_parse_empty_and_whitespace_lines():
    assert LogParser.parse_line("", line_index=0) is None
    assert LogParser.parse_line("   \n", line_index=1) is None


def test_parse_malformed_non_standard_line():
    line = "2026-08-08 localhost system Error: unformatted error string with no syslog header"
    parsed = LogParser.parse_line(line, line_index=5)
    
    assert parsed is not None
    assert parsed['log_id'] == 6
    assert parsed['log_level'] == "ERROR"


def test_data_cleaner_handles_missing_fields():
    dirty_logs = [
        {'log_id': 1, 'hostname': None, 'service': '  sshd  ', 'message': None},
        {'log_id': 2, 'hostname': ' server-01 ', 'service': None, 'message': ' Error detected '}
    ]
    cleaned = DataCleaner.clean(dirty_logs)
    
    assert len(cleaned) == 2
    assert cleaned[0]['hostname'] == 'unknown_host'
    assert cleaned[0]['service'] == 'sshd'
    assert cleaned[0]['message'] == 'empty_message'
    assert cleaned[1]['hostname'] == 'server-01'
    assert cleaned[1]['service'] == 'unknown_service'
    assert cleaned[1]['message'] == 'Error detected'


def test_batch_parse_logs(sample_syslog_content):
    parsed = LogParser.parse_logs(sample_syslog_content)
    assert len(parsed) == 8
    
    cleaned = DataCleaner.clean(parsed)
    assert len(cleaned) == 8
    assert all(c['hostname'] == 'server-01' for c in cleaned)
