# Behavioral Feature Extraction Module for Objective 1
import re
import numpy as np
import pandas as pd

FEATURE_SCHEMA = [
    'event_frequency',
    'sequence_length',
    'error_count',
    'error_pattern',
    'login_attempts',
    'failed_login_attempts',
    'warning_count',
    'unknown_events'
]


class LogParserAndExtractor:
    """
    Parses raw log strings and extracts the 8 canonical behavioral features
    over sliding sequence windows.
    """

    @staticmethod
    def parse_log_lines(raw_lines):
        parsed_records = []
        syslog_pattern = r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+([\w\.\-]+)\s+([\w\.\-\[\]]+):\s*(.*)$'

        for idx, line in enumerate(raw_lines):
            line = line.strip()
            if not line:
                continue

            match = re.match(syslog_pattern, line)
            if match:
                timestamp, hostname, service, message = match.groups()
            else:
                parts = line.split(' ', 3)
                timestamp = parts[0] if len(parts) > 0 else '2026-08-15T10:00:00'
                hostname = parts[1] if len(parts) > 1 else 'localhost'
                service = parts[2] if len(parts) > 2 else 'system'
                message = parts[3] if len(parts) > 3 else line

            msg_upper = message.upper()
            if 'ERROR' in msg_upper or 'FAILED' in msg_upper or 'EXCEPTION' in msg_upper:
                level = 'ERROR'
            elif 'WARN' in msg_upper:
                level = 'WARNING'
            else:
                level = 'INFO'

            parsed_records.append({
                'log_id': idx + 1,
                'timestamp': timestamp,
                'hostname': hostname,
                'service': service,
                'log_level': level,
                'message': message
            })
        return parsed_records

    @classmethod
    def extract_behavioral_features(cls, parsed_logs):
        total_logs = len(parsed_logs)
        features = []

        for i, log in enumerate(parsed_logs):
            msg = log['message']
            msg_upper = msg.upper()

            start_w = max(0, i - 2)
            end_w = min(total_logs, i + 3)
            window_logs = parsed_logs[start_w:end_w]

            event_freq = float(len(window_logs))
            seq_len = float(len(msg))

            error_count = float(sum(1 for w in window_logs if w.get('log_level') == 'ERROR'))

            if 'FAILED' in msg_upper:
                err_pattern = 1.0
            elif 'NO SUCH FILE' in msg_upper:
                err_pattern = 2.0
            elif 'OUT OF MEMORY' in msg_upper or 'KILLED' in msg_upper:
                err_pattern = 3.0
            elif 'DENIED' in msg_upper or 'OVERFLOW' in msg_upper:
                err_pattern = 4.0
            else:
                err_pattern = 0.0

            login_attempts = float(sum(1 for w in window_logs if 'SSHD' in str(w.get('service')).upper() or 'AUTH' in str(w.get('message')).upper()))
            failed_logins = float(sum(1 for w in window_logs if 'FAILED' in str(w.get('message')).upper() or 'DENIED' in str(w.get('message')).upper()))
            warning_count = float(sum(1 for w in window_logs if w.get('log_level') == 'WARNING'))
            unknown_events = float(sum(1 for w in window_logs if 'UNKNOWN' in str(w.get('message')).upper()))

            features.append({
                'event_frequency': event_freq,
                'sequence_length': seq_len,
                'error_count': error_count,
                'error_pattern': err_pattern,
                'login_attempts': login_attempts,
                'failed_login_attempts': failed_logins,
                'warning_count': warning_count,
                'unknown_events': unknown_events
            })

        return pd.DataFrame(features, columns=FEATURE_SCHEMA)


class HDFSDomainAdapter:
    """
    Transforms generic server log behavioral features into HDFS-compatible feature representation.
    Derived from HDFS Training Dataset Statistical Constants (575,061 records).
    """
    HDFS_FREQ_MEDIAN = 19.0
    HDFS_FREQ_STD = 5.177735
    HDFS_SEQ_MEDIAN = 7.0
    HDFS_SEQ_STD = 1.578432
    HDFS_ERR_MEDIAN = 0.0

    @classmethod
    def transform(cls, raw_df):
        mapped_df = raw_df.copy()
        err_total = mapped_df['error_count'] + mapped_df['failed_login_attempts']
        mapped_df['error_count'] = cls.HDFS_ERR_MEDIAN + err_total
        mapped_df['error_pattern'] = np.where(err_total > 0, 1.0, 0.0)

        seq_len = mapped_df['sequence_length'].clip(lower=1)
        mapped_df['sequence_length'] = (cls.HDFS_SEQ_MEDIAN + (np.log10(seq_len) - np.log10(200.0)) * cls.HDFS_SEQ_STD * 2.0).clip(2.0, 298.0)

        freq = mapped_df['event_frequency'].clip(lower=1)
        mapped_df['event_frequency'] = (cls.HDFS_FREQ_MEDIAN + (freq - 5.0) * cls.HDFS_FREQ_STD).clip(2.0, 298.0)

        mapped_df['warning_count'] = mapped_df['warning_count'].clip(lower=0.0)
        mapped_df['login_attempts'] = 0.0
        mapped_df['failed_login_attempts'] = 0.0
        mapped_df['unknown_events'] = 0.0
        return mapped_df[FEATURE_SCHEMA]
