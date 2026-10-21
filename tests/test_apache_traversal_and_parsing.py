import pytest
from ml_engine import (
    LogParser, DataCleaner, BehavioralFeatureExtractor,
    DataPreprocessor, run_full_pipeline, FEATURE_SCHEMA
)


def test_apache_path_traversal_samples():
    """Verifies that the reproducible unpacking error is resolved and both user sample logs parse properly."""
    log1 = '192.168.1.50 - - [18/Oct/2026:11:45:12 +0000] "GET /../../../../etc/passwd HTTP/1.1" 400 166 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
    log2 = '192.168.1.50 - - [18/Oct/2026:11:45:30 +0000] "GET /static/scripts/../../../boot.ini HTTP/1.1" 404 232 "-" "curl/7.68.0"'

    # Verify no unpacking exception is thrown
    p1 = LogParser.parse_line(log1, 0)
    p2 = LogParser.parse_line(log2, 1)

    assert p1 is not None
    assert p1['parsing_status'] == 'success'
    assert p1['src_ip'] == '192.168.1.50'
    assert p1['timestamp'] == '18/Oct/2026:11:45:12 +0000'
    assert p1['http_method'] == 'GET'
    assert p1['http_uri'] == '/../../../../etc/passwd'
    assert p1['http_status'] == 400
    assert p1['http_bytes'] == 166
    assert p1['http_user_agent'] == 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    assert p1['action'] == 'Path-traversal attempt candidate'
    assert 'does not prove attack succeeded' in p1['description']
    assert p1['event_type'] == 'WEB_SECURITY'

    assert p2 is not None
    assert p2['parsing_status'] == 'success'
    assert p2['src_ip'] == '192.168.1.50'
    assert p2['timestamp'] == '18/Oct/2026:11:45:30 +0000'
    assert p2['http_method'] == 'GET'
    assert p2['http_uri'] == '/static/scripts/../../../boot.ini'
    assert p2['http_status'] == 404
    assert p2['http_bytes'] == 232
    assert p2['http_user_agent'] == 'curl/7.68.0'
    assert p2['action'] == 'Suspicious traversal attempt candidate'
    assert 'does not prove attack succeeded' in p2['description']
    assert p2['event_type'] == 'WEB_SECURITY'


def test_combined_log_format_with_referrer_and_user_agent():
    """Verifies standard Combined Log Format with active referrer and user agent."""
    line = '10.10.10.25 - alice [20/Oct/2026:14:20:10 +0000] "GET /dashboard/reports HTTP/1.1" 200 8432 "https://example.com/home" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"'
    p = LogParser.parse_line(line, 0)

    assert p is not None
    assert p['parsing_status'] == 'success'
    assert p['src_ip'] == '10.10.10.25'
    assert p['user'] == 'alice'
    assert p['timestamp'] == '20/Oct/2026:14:20:10 +0000'
    assert p['http_method'] == 'GET'
    assert p['http_uri'] == '/dashboard/reports'
    assert p['http_protocol'] == 'HTTP/1.1'
    assert p['http_status'] == 200
    assert p['http_bytes'] == 8432
    assert p['http_referrer'] == 'https://example.com/home'
    assert p['http_user_agent'] == 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'
    assert p['event_type'] == 'WEB_SERVICE'
    assert p['action'] == 'HTTP GET /dashboard/reports'


def test_common_log_format_clf():
    """Verifies Common Log Format (CLF) without referrer or user-agent."""
    line = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326'
    p = LogParser.parse_line(line, 0)

    assert p is not None
    assert p['parsing_status'] == 'success'
    assert p['src_ip'] == '127.0.0.1'
    assert p['user'] == 'frank'
    assert p['timestamp'] == '10/Oct/2000:13:55:36 -0700'
    assert p['http_method'] == 'GET'
    assert p['http_uri'] == '/apache_pb.gif'
    assert p['http_protocol'] == 'HTTP/1.0'
    assert p['http_status'] == 200
    assert p['http_bytes'] == 2326
    assert p['http_referrer'] is None
    assert p['http_user_agent'] is None


def test_missing_bytes_dash():
    """Verifies that missing byte counts represented by '-' parse without error."""
    line = '198.51.100.12 - - [20/Oct/2026:15:00:00 +0000] "HEAD /healthcheck HTTP/1.1" 200 -'
    p = LogParser.parse_line(line, 0)

    assert p is not None
    assert p['parsing_status'] == 'success'
    assert p['src_ip'] == '198.51.100.12'
    assert p['http_method'] == 'HEAD'
    assert p['http_uri'] == '/healthcheck'
    assert p['http_status'] == 200
    assert p['http_bytes'] == 0


def test_malformed_http_logs_graceful():
    """Verifies defense in depth: malformed or truncated HTTP lines do not throw unhandled exceptions."""
    malformed_lines = [
        '192.168.1.50 - - truncated line without request',
        '192.168.1.50 - - [invalid timestamp] "BROKEN REQUEST 500',
        '!!! RAW GARBAGE DATA 12345 !!!'
    ]
    for idx, line in enumerate(malformed_lines):
        p = LogParser.parse_line(line, idx)
        assert p is not None
        assert p['parsing_status'] == 'unsupported_format'
        assert p['action'] == 'Unparsed Raw Log'


def test_normal_web_traffic_not_flagged():
    """Verifies legitimate web requests containing dots or slashes are NOT falsely flagged as directory traversal."""
    normal_lines = [
        '127.0.0.1 - - [18/Oct/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 4520 "-" "curl/7.68.0"',
        '127.0.0.1 - - [18/Oct/2026:12:00:01 +0000] "GET /static/css/styles.min.css HTTP/1.1" 200 12500',
        '127.0.0.1 - - [18/Oct/2026:12:00:02 +0000] "GET /api/v1/users?page=1&sort=asc HTTP/1.1" 200 890'
    ]
    for idx, line in enumerate(normal_lines):
        p = LogParser.parse_line(line, idx)
        assert p is not None
        assert p['event_type'] == 'WEB_SERVICE'
        assert 'traversal' not in p['action'].lower()
        assert 'traversal' not in p['description'].lower()


def test_encoded_path_traversal_detection():
    """Verifies URL-encoded and double-encoded path traversal probes are safely caught."""
    encoded_lines = [
        '192.168.1.99 - - [18/Oct/2026:13:00:00 +0000] "GET /%2e%2e%2f%2e%2e%2fetc/passwd HTTP/1.1" 400 166',
        '192.168.1.99 - - [18/Oct/2026:13:00:01 +0000] "GET /static/..%2f..%2fwindows/system32 HTTP/1.1" 404 200'
    ]
    p1 = LogParser.parse_line(encoded_lines[0], 0)
    p2 = LogParser.parse_line(encoded_lines[1], 1)

    assert p1['event_type'] == 'WEB_SECURITY'
    assert 'traversal' in p1['action'].lower()

    assert p2['event_type'] == 'WEB_SECURITY'
    assert 'traversal' in p2['action'].lower()


def test_feature_extraction_and_pipeline():
    """Verifies that behavioral features conform to FEATURE_SCHEMA and run_full_pipeline produces valid results."""
    log_content = (
        '192.168.1.50 - - [18/Oct/2026:11:45:12 +0000] "GET /../../../../etc/passwd HTTP/1.1" 400 166 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"\n'
        '192.168.1.50 - - [18/Oct/2026:11:45:30 +0000] "GET /static/scripts/../../../boot.ini HTTP/1.1" 404 232 "-" "curl/7.68.0"'
    )

    results = run_full_pipeline(log_content)

    assert 'parsed_logs' in results
    assert len(results['parsed_logs']) == 2

    assert 'features' in results
    assert len(results['features']) == 2
    for f in results['features']:
        for col in FEATURE_SCHEMA:
            assert col in f

    # Traversal security probes map to err_pattern 4 and unknown_events
    assert results['features'][0]['error_pattern'] == 4
    assert results['features'][1]['error_pattern'] == 4

    assert 'detection_results' in results
    assert len(results['detection_results']) == 2

    assert 'shap_explanations' in results
    assert len(results['shap_explanations']) == 2
    for exp in results['shap_explanations']:
        assert 'feature_contributions' in exp
        assert 'what_happened' in exp
        assert 'recommended_action' in exp
