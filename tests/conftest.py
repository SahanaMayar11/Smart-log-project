import os
import sys
import pytest
import pandas as pd
import numpy as np

# Ensure backend directory is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import app
from ml_engine import (
    FEATURE_SCHEMA,
    LogParser,
    DataCleaner,
    BehavioralFeatureExtractor,
    DataPreprocessor,
    IsolationForestDetector,
    OneClassSVMValidator,
    ShapExplainerEngine
)


@pytest.fixture
def sample_syslog_content():
    return """2026-08-08T10:00:01 server-01 systemd[1]: Started System Logging Service.
2026-08-08T10:00:05 server-01 sshd[1402]: Accepted password for root from 192.168.1.50 port 54322 ssh2
2026-08-08T10:01:15 server-01 sshd[1489]: Failed password for invalid user admin from 198.51.100.45 port 41234 ssh2
2026-08-08T10:01:16 server-01 sshd[1491]: Failed password for invalid user admin from 198.51.100.45 port 41236 ssh2
2026-08-08T10:02:05 server-01 nginx[2010]: 2026/08/08 10:02:05 [error] 2010#0: *1 open() "/var/www/html/admin.php" failed (2: No such file or directory)
2026-08-08T10:04:10 server-01 kernel[0]: [ 120.450123] Out of memory: Kill process 2010 (nginx) score 850 or sacrifice child
2026-08-08T10:07:40 server-01 auth[2250]: UNKNOWN_EVENT: Buffer overflow attempt in authentication packet header
2026-08-08T10:09:00 server-01 CRON[2350]: (root) CMD (sysstat-collector)"""


@pytest.fixture
def sample_feature_df():
    return pd.DataFrame([
        {
            'log_id': 1,
            'event_frequency': 5.0,
            'sequence_length': 65,
            'error_count': 0,
            'error_pattern': 0,
            'login_attempts': 1,
            'failed_login_attempts': 0,
            'warning_count': 0,
            'unknown_events': 0
        },
        {
            'log_id': 2,
            'event_frequency': 5.0,
            'sequence_length': 85,
            'error_count': 3,
            'error_pattern': 1,
            'login_attempts': 4,
            'failed_login_attempts': 4,
            'warning_count': 0,
            'unknown_events': 0
        },
        {
            'log_id': 3,
            'event_frequency': 5.0,
            'sequence_length': 120,
            'error_count': 2,
            'error_pattern': 3,
            'login_attempts': 0,
            'failed_login_attempts': 0,
            'warning_count': 1,
            'unknown_events': 1
        }
    ])


from database import init_db

@pytest.fixture
def flask_client():
    init_db()
    from app import seed_sample_data_if_empty
    seed_sample_data_if_empty()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client
