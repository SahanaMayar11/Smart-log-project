"""
Smart-Log Attack Simulator & Anomaly Injector Module
================================================================================
Generates deterministic synthetic server security events for 5 attack scenarios:
1. SSH Brute-Force Simulation
2. Buffer Overflow / Oversized Payload Simulation
3. Privilege Escalation / Access Denied Simulation
4. Sensitive File Access / Directory Traversal Simulation
5. Traffic Flood / DoS-Like Burst Simulation

Design Principles:
- Strict Technical Honesty: Synthetic events are passed through the genuine,
  unmodified ML detection pipeline. No scores are faked or forced.
- Transparency: Clearly distinguishes genuine ML predictions from
  simulation-only rule-based heuristic checks.
- Safety: Purely synthetic in-memory strings. Does not execute external commands,
  connect to remote systems, or generate real denial-of-service traffic.
================================================================================
"""

import os
import uuid
from datetime import datetime, timedelta

# Canonical 5 Attack Scenarios Catalog
SCENARIOS_CATALOG = {
    'ssh_bruteforce': {
        'id': 'ssh_bruteforce',
        'name': 'SSH Brute-Force Simulation',
        'category': 'Authentication Abuse',
        'description': (
            'Simulates an automated credential stuffing and dictionary attack against the SSH daemon. '
            'Generates rapid consecutive failed authentication attempts targeting administrative '
            'and system accounts from an untrusted external IP address.'
        ),
        'target_signals': ['failed_login_attempts', 'login_attempts', 'event_frequency'],
        'expected_signals_description': (
            'Significant spike in failed_login_attempts (burst >= 3 in window), '
            'elevated login_attempts, and high event frequency.'
        ),
        'recommended_action': (
            'Block source IP 198.51.100.45 on the perimeter firewall (ufw/iptables), '
            'enforce fail2ban rate-limiting, and disable password-based SSH authentication '
            'in sshd_config in favor of ed25519 public key authentication.'
        ),
        'model_compatibility': {
            'supported_natively_in_feature_schema': True,
            'hdfs_adapter_behavior': (
                'In HDFS model mode, failed_login_attempts is mapped into error_count via '
                'HDFSDomainAdapter because the HDFS cluster dataset lacked SSH auth logs. '
                'In active multi-feature model mode, it is evaluated natively across all 8 features.'
            ),
            'expected_ml_behavior': 'High likelihood of anomaly detection due to failure burst.'
        },
        'sample_logs_preview': [
            '2026-08-08T10:00:01 server-01 sshd[1489]: Failed password for invalid user admin from 198.51.100.45 port 41234 ssh2',
            '2026-08-08T10:00:02 server-01 sshd[1490]: Failed password for invalid user root from 198.51.100.45 port 41236 ssh2',
            '2026-08-08T10:00:03 server-01 sshd[1491]: Failed password for invalid user oracle from 198.51.100.45 port 41238 ssh2',
            '2026-08-08T10:00:04 server-01 sshd[1492]: Failed password for invalid user postgres from 198.51.100.45 port 41240 ssh2',
            '2026-08-08T10:00:05 server-01 sshd[1493]: Failed password for invalid user deploy from 198.51.100.45 port 41242 ssh2'
        ]
    },
    'buffer_overflow': {
        'id': 'buffer_overflow',
        'name': 'Buffer Overflow / Oversized Payload Simulation',
        'category': 'Exploit / Memory Corruption',
        'description': (
            'Simulates an exploit attempt transmitting an abnormally long payload string and memory '
            'corruption signature targeting a server authentication daemon, resulting in a general protection fault.'
        ),
        'target_signals': ['sequence_length', 'error_pattern', 'unknown_events'],
        'expected_signals_description': (
            'Extreme sequence_length (>220 characters), error_pattern categorized as 4 '
            '(Overflow/Denied signature), and unknown_events count spike.'
        ),
        'recommended_action': (
            'Isolate the targeted authentication daemon process, collect core memory dumps for '
            'forensic binary disassembly, verify software package integrity using debsums/rpm -V, '
            'and deploy the vendor security patch.'
        ),
        'model_compatibility': {
            'supported_natively_in_feature_schema': True,
            'hdfs_adapter_behavior': (
                'Sequence length re-centered continuously around HDFS median; error pattern 4 '
                'maps directly into abnormal error states.'
            ),
            'expected_ml_behavior': 'High likelihood of isolation due to extreme sequence length and error signature.'
        },
        'sample_logs_preview': [
            '2026-08-08T10:05:01 server-01 auth[2250]: UNKNOWN_EVENT: Buffer overflow attempt in authentication packet header from 198.51.100.80 payload_hex=0x9090909090909090eb1f5e89760831c088460789460c31bb895... [len=248]',
            '2026-08-08T10:05:02 server-01 kernel[0]: [ 412.9812] traps: auth-daemon[2250] general protection fault ip:7f81a201 sp:7ffe312b error:0 in libc.so.6'
        ]
    },
    'privilege_escalation': {
        'id': 'privilege_escalation',
        'name': 'Privilege Escalation / Access Denied Simulation',
        'category': 'Privilege Abuse / Policy Violation',
        'description': (
            'Simulates an unauthorized low-privilege user session attempting root script execution '
            'and unauthorized sudo access, explicitly blocked and recorded by AppArmor/SELinux mandatory access controls.'
        ),
        'target_signals': ['error_pattern', 'error_count', 'unknown_events'],
        'expected_signals_description': (
            'Error pattern categorized as 4 (DENIED access violation), elevated error_count, '
            'and unmapped exploit execution event.'
        ),
        'recommended_action': (
            'Terminate active shell sessions for user guest, inspect staging directory /tmp/.exploit_priv.sh, '
            'audit /etc/sudoers for unauthorized rule additions, and verify AppArmor profiles are enforced.'
        ),
        'model_compatibility': {
            'supported_natively_in_feature_schema': True,
            'hdfs_adapter_behavior': (
                'Evaluated via error_count and error_pattern transitions. Fully supported across both models.'
            ),
            'expected_ml_behavior': 'Flagged as anomaly due to AppArmor denial signature and error pattern.'
        },
        'sample_logs_preview': [
            '2026-08-08T10:10:01 server-01 sudo[3100]: pam_unix(sudo:auth): authentication failure; logname=guest uid=1002 euid=0 tty=/dev/pts/1 ruser=guest rhost= user=root',
            '2026-08-08T10:10:02 server-01 sudo[3100]: pam_unix(sudo:auth): conversation failed; 3 incorrect password attempts; logname=guest uid=1002 euid=0',
            '2026-08-08T10:10:03 server-01 su[3110]: FAILED SU (to root) guest on /dev/pts/1',
            '2026-08-08T10:10:04 server-01 kernel[0]: [ 890.112] audit: type=1400 audit: apparmor="DENIED" operation="open" profile="/usr/bin/python3" name="/etc/shadow" pid=3102 comm="python3" requested_mask="r" denied_mask="r"',
            '2026-08-08T10:10:05 server-01 auth[3105]: UNKNOWN_EVENT: Unauthorized privilege escalation exploit probe detected from untrusted user session guest'
        ]
    },
    'directory_traversal': {
        'id': 'directory_traversal',
        'name': 'Sensitive File Access / Directory Traversal Simulation',
        'category': 'Unauthorized File Access',
        'description': (
            'Simulates an external HTTP reconnaissance client submitting path traversal sequences '
            '(/../../../../etc/shadow, /etc/passwd) to probe for sensitive credential storage files.'
        ),
        'target_signals': ['error_count', 'error_pattern', 'sequence_length'],
        'expected_signals_description': (
            'Burst of web server error entries with error_pattern = 4 (Permission denied), '
            'elevated error_count, and path traversal query strings.'
        ),
        'recommended_action': (
            'Deploy Web Application Firewall (WAF) rule to block dot-dot-slash traversal patterns, '
            'verify web server chroot/sandboxing, and confirm file permissions on /etc/shadow are strictly 000.'
        ),
        'model_compatibility': {
            'supported_natively_in_feature_schema': True,
            'hdfs_adapter_behavior': (
                'Error pattern 4 and elevated error count are mapped into continuous anomaly scale.'
            ),
            'expected_ml_behavior': 'High likelihood of anomaly detection due to repeated permission denials.'
        },
        'sample_logs_preview': [
            '2026-08-08T10:15:01 server-01 nginx[4120]: 2026/08/08 10:15:01 [error] 4120#0: *104 open() "/etc/shadow" failed (13: Permission denied), client: 198.51.100.99, request: "GET /../../../../etc/shadow HTTP/1.1"',
            '2026-08-08T10:15:02 server-01 nginx[4120]: 2026/08/08 10:15:02 [error] 4120#0: *105 open() "/etc/passwd" failed (13: Permission denied), client: 198.51.100.99, request: "GET /../../../../etc/passwd HTTP/1.1"',
            '2026-08-08T10:15:03 server-01 nginx[4120]: 2026/08/08 10:15:03 [error] 4120#0: *106 open() "/proc/self/environ" failed (13: Permission denied), client: 198.51.100.99, request: "GET /../../../../proc/self/environ HTTP/1.1"'
        ]
    },
    'dos_burst': {
        'id': 'dos_burst',
        'name': 'Traffic Flood / DoS-Like Burst Simulation',
        'category': 'Resource Exhaustion / DoS',
        'description': (
            'Simulates an abnormal high-frequency volumetric connection surge saturating worker pools, '
            'triggering kernel SYN-flood defense warnings, and causing Out-of-Memory process termination.'
        ),
        'target_signals': ['event_frequency', 'error_count', 'warning_count', 'error_pattern'],
        'expected_signals_description': (
            'High event_frequency in sliding window, surge in warning_count, and error_pattern = 3 '
            '(Out of memory / Killed).'
        ),
        'recommended_action': (
            'Enable SYN flood protection cookies in sysctl (net.ipv4.tcp_syncookies = 1), '
            'configure reverse proxy connection rate limits (limit_conn / limit_req), '
            'and increase worker_rlimit_nofile.'
        ),
        'model_compatibility': {
            'supported_natively_in_feature_schema': True,
            'hdfs_adapter_behavior': (
                'Event frequency and OOM error pattern (pattern 3) drive rapid tree isolation.'
            ),
            'expected_ml_behavior': 'High likelihood of anomaly detection due to event frequency and OOM kill.'
        },
        'sample_logs_preview': [
            '2026-08-08T10:20:01 server-01 nginx[5001]: [warn] 5001#0: *1000 1024 worker_connections are not enough while connecting to upstream, client: 198.51.100.120',
            '2026-08-08T10:20:01 server-01 nginx[5001]: [warn] 5001#0: *1001 1024 worker_connections are not enough while connecting to upstream, client: 198.51.100.120',
            '2026-08-08T10:20:02 server-01 kernel[0]: [ 1520.450] [warn] TCP: request_sock_TCP: Possible SYN flooding on port 80. Sending cookies.',
            '2026-08-08T10:20:03 server-01 kernel[0]: [ 1522.112] Out of memory: Kill process 5001 (nginx) score 950 or sacrifice child',
            '2026-08-08T10:20:04 server-01 systemd[1]: nginx.service: A process of this unit has been killed by the OOM killer.'
        ]
    }
}

# Ensure both property naming conventions are available
for sc in SCENARIOS_CATALOG.values():
    if 'expected_signals_description' in sc and 'expected_signals' not in sc:
        sc['expected_signals'] = sc['expected_signals_description']
    if 'recommended_action' in sc and 'security_recommendation' not in sc:
        sc['security_recommendation'] = sc['recommended_action']
    if 'sample_logs_preview' in sc and 'sample_preview' not in sc:
        sc['sample_preview'] = "\n".join(sc['sample_logs_preview']) if isinstance(sc['sample_logs_preview'], list) else str(sc['sample_logs_preview'])


def get_scenario_or_404(scenario_id):
    """Retrieves scenario metadata or raises ValueError with supported list."""
    if scenario_id not in SCENARIOS_CATALOG:
        raise ValueError(
            f"Unknown scenario identifier '{scenario_id}'. Supported scenarios: {list(SCENARIOS_CATALOG.keys())}"
        )
    return SCENARIOS_CATALOG[scenario_id]


def get_all_scenarios_metadata():
    """Returns a list of all scenario specifications for UI and documentation."""
    return [meta for meta in SCENARIOS_CATALOG.values()]


def generate_synthetic_scenario_logs(scenario_id, base_timestamp=None):
    """
    Generates deterministic, timestamped synthetic log lines and rich telemetry records.
    Includes 2 normal baseline operational logs before the attack and 1 after, allowing
    the sliding sequence window to demonstrate the authentic transition from Normal to Anomaly.
    """
    if scenario_id not in SCENARIOS_CATALOG:
        raise ValueError(f"Unknown scenario ID: {scenario_id}. Supported: {list(SCENARIOS_CATALOG.keys())}")

    scenario_meta = SCENARIOS_CATALOG[scenario_id]
    now = base_timestamp or datetime.now()
    sim_token = f"SIM-{uuid.uuid4().hex[:6].upper()}"

    def ts_offset(seconds):
        return (now + timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%S')

    logs = []
    records = []

    # Baseline 1: Routine service start
    t0 = ts_offset(-2)
    l0 = f"{t0} server-01 systemd[1]: Started System Logging & Operational Monitor Service daemon."
    logs.append(l0)
    records.append({
        'timestamp': t0, 'hostname': 'server-01', 'service': 'systemd', 'process': 'systemd',
        'event_type': 'SYSTEM_EVENT', 'log_level': 'INFO', 'user': 'root', 'is_simulated': 1,
        'simulation_scenario': scenario_id, 'is_synthetic': True, 'simulation_token': sim_token,
        'action': 'Service Started', 'source': 'Attack Simulator (Normal Baseline)',
        'description': 'Normal baseline systemd operational service startup.'
    })

    # Baseline 2: Routine scheduled task
    t1 = ts_offset(-1)
    l1 = f"{t1} server-01 CRON[1002]: (root) CMD (sysstat-collector --interval=60)"
    logs.append(l1)
    records.append({
        'timestamp': t1, 'hostname': 'server-01', 'service': 'CRON', 'process': 'cron',
        'event_type': 'SCHEDULED_TASK', 'log_level': 'INFO', 'user': 'root', 'is_simulated': 1,
        'simulation_scenario': scenario_id, 'is_synthetic': True, 'simulation_token': sim_token,
        'action': 'Cron Execution', 'source': 'Attack Simulator (Normal Baseline)',
        'description': 'Normal routine scheduled administrative cron execution.'
    })

    # Scenario-Specific Attack Logs
    if scenario_id == 'ssh_bruteforce':
        attack_users = ['admin', 'root', 'oracle', 'postgres', 'deploy']
        for idx, u in enumerate(attack_users):
            t_sec = ts_offset(idx)
            port = 41234 + (idx * 2)
            msg = f"Failed password for invalid user {u} from 198.51.100.45 port {port} ssh2"
            line = f"{t_sec} server-01 sshd[{1489 + idx}]: {msg}"
            logs.append(line)
            records.append({
                'timestamp': t_sec, 'hostname': 'server-01', 'service': 'sshd', 'process': 'sshd',
                'event_type': 'AUTHENTICATION', 'log_level': 'ERROR', 'user': u, 'is_simulated': 1,
                'simulation_scenario': scenario_id, 'is_synthetic': True, 'simulation_token': sim_token,
                'action': 'Logon Failure', 'source': 'Attack Simulator (Simulated Threat)',
                'description': f"Simulated SSH password failure for account '{u}' from 198.51.100.45."
            })

    elif scenario_id == 'buffer_overflow':
        t_sec0 = ts_offset(0)
        payload = "0x90" * 40 + "eb1f5e89760831c088460789460c31bb895b08b00bcd80" + "90" * 20
        msg0 = f"UNKNOWN_EVENT: Buffer overflow attempt in authentication packet header from 198.51.100.80 payload_hex={payload}"
        line0 = f"{t_sec0} server-01 auth[2250]: {msg0}"
        logs.append(line0)
        records.append({
            'timestamp': t_sec0, 'hostname': 'server-01', 'service': 'auth', 'process': 'auth-daemon',
            'event_type': 'UNKNOWN_EVENT', 'log_level': 'ERROR', 'user': 'system', 'is_simulated': 1,
            'simulation_scenario': scenario_id, 'is_synthetic': True, 'simulation_token': sim_token,
            'action': 'Buffer Overflow Attack', 'source': 'Attack Simulator (Simulated Threat)',
            'description': 'Simulated oversized exploit payload submitted to authentication socket.'
        })

        t_sec1 = ts_offset(1)
        msg1 = "traps: auth-daemon[2250] general protection fault ip:7f81a201 sp:7ffe312b error:0 in libc.so.6"
        line1 = f"{t_sec1} server-01 kernel[0]: [ 412.9812] {msg1}"
        logs.append(line1)
        records.append({
            'timestamp': t_sec1, 'hostname': 'server-01', 'service': 'kernel', 'process': 'kernel',
            'event_type': 'KERNEL_AUDIT', 'log_level': 'ERROR', 'user': 'system', 'is_simulated': 1,
            'simulation_scenario': scenario_id, 'is_synthetic': True, 'simulation_token': sim_token,
            'action': 'Segmentation Fault', 'source': 'Attack Simulator (Simulated Threat)',
            'description': 'General protection fault triggered following exploit execution.'
        })

    elif scenario_id == 'privilege_escalation':
        t_sec0 = ts_offset(0)
        msg0 = "pam_unix(sudo:auth): authentication failure; logname=guest uid=1002 euid=0 tty=/dev/pts/1 ruser=guest rhost= user=root"
        line0 = f"{t_sec0} server-01 sudo[3100]: {msg0}"
        logs.append(line0)
        records.append({
            'timestamp': t_sec0, 'hostname': 'server-01', 'service': 'sudo', 'process': 'sudo',
            'event_type': 'AUTHENTICATION', 'log_level': 'ERROR', 'user': 'guest', 'is_simulated': 1,
            'simulation_scenario': scenario_id, 'is_synthetic': True, 'simulation_token': sim_token,
            'action': 'Sudo Failure', 'source': 'Attack Simulator (Simulated Threat)',
            'description': 'Unauthorized privilege escalation probe via sudo.'
        })

        t_sec1 = ts_offset(1)
        msg1 = "pam_unix(sudo:auth): conversation failed; 3 incorrect password attempts; logname=guest uid=1002 euid=0"
        line1 = f"{t_sec1} server-01 sudo[3100]: {msg1}"
        logs.append(line1)
        records.append({
            'timestamp': t_sec1, 'hostname': 'server-01', 'service': 'sudo', 'process': 'sudo',
            'event_type': 'AUTHENTICATION', 'log_level': 'ERROR', 'user': 'guest', 'is_simulated': 1,
            'simulation_scenario': scenario_id, 'is_synthetic': True, 'simulation_token': sim_token,
            'action': 'Repeated Sudo Auth Failures', 'source': 'Attack Simulator (Simulated Threat)',
            'description': 'Repeated password failures attempting to escalate to root privileges.'
        })

        t_sec2 = ts_offset(2)
        msg2 = "FAILED SU (to root) guest on /dev/pts/1"
        line2 = f"{t_sec2} server-01 su[3110]: {msg2}"
        logs.append(line2)
        records.append({
            'timestamp': t_sec2, 'hostname': 'server-01', 'service': 'su', 'process': 'su',
            'event_type': 'AUTHENTICATION', 'log_level': 'ERROR', 'user': 'guest', 'is_simulated': 1,
            'simulation_scenario': scenario_id, 'is_synthetic': True, 'simulation_token': sim_token,
            'action': 'Failed Switch User', 'source': 'Attack Simulator (Simulated Threat)',
            'description': 'Direct attempt to switch user session to root via su denied.'
        })

        t_sec3 = ts_offset(3)
        msg3 = 'audit: type=1400 audit: apparmor="DENIED" operation="open" profile="/usr/bin/python3" name="/etc/shadow" pid=3102 comm="python3" requested_mask="r" denied_mask="r"'
        line3 = f"{t_sec3} server-01 kernel[0]: [ 890.112] {msg3}"
        logs.append(line3)
        records.append({
            'timestamp': t_sec3, 'hostname': 'server-01', 'service': 'kernel', 'process': 'apparmor',
            'event_type': 'KERNEL_AUDIT', 'log_level': 'ERROR', 'user': 'guest', 'is_simulated': 1,
            'simulation_scenario': scenario_id, 'is_synthetic': True, 'simulation_token': sim_token,
            'action': 'AppArmor /etc/shadow Access Denied', 'source': 'Attack Simulator (Simulated Threat)',
            'description': 'Mandatory Access Control policy denied read attempt on /etc/shadow credential store.'
        })

        t_sec4 = ts_offset(4)
        msg4 = "UNKNOWN_EVENT: Unauthorized privilege escalation exploit probe detected from untrusted user session guest"
        line4 = f"{t_sec4} server-01 auth[3105]: {msg4}"
        logs.append(line4)
        records.append({
            'timestamp': t_sec4, 'hostname': 'server-01', 'service': 'auth', 'process': 'auth',
            'event_type': 'UNKNOWN_EVENT', 'log_level': 'ERROR', 'user': 'guest', 'is_simulated': 1,
            'simulation_scenario': scenario_id, 'is_synthetic': True, 'simulation_token': sim_token,
            'action': 'Privilege Escalation Exploit Probe', 'source': 'Attack Simulator (Simulated Threat)',
            'description': 'Heuristic privilege escalation probe identified by authentication monitor.'
        })

    elif scenario_id == 'directory_traversal':
        targets = ['/etc/shadow', '/etc/passwd', '/proc/self/environ']
        for idx, trg in enumerate(targets):
            t_sec = ts_offset(idx)
            msg = f'2026/08/08 10:15:0{idx+1} [error] 4120#0: *{104+idx} open() "{trg}" failed (13: Permission denied), client: 198.51.100.99, request: "GET /../../../../{trg[1:]} HTTP/1.1"'
            line = f"{t_sec} server-01 nginx[4120]: {msg}"
            logs.append(line)
            records.append({
                'timestamp': t_sec, 'hostname': 'server-01', 'service': 'nginx', 'process': 'nginx',
                'event_type': 'WEB_SERVICE', 'log_level': 'ERROR', 'user': 'www-data', 'is_simulated': 1,
                'simulation_scenario': scenario_id, 'is_synthetic': True, 'simulation_token': sim_token,
                'action': 'Directory Traversal Blocked', 'source': 'Attack Simulator (Simulated Threat)',
                'description': f"Web server blocked path traversal attempt querying sensitive file '{trg}'."
            })

    elif scenario_id == 'dos_burst':
        # Burst of connection warnings and OOM kill
        for idx in range(3):
            t_sec = ts_offset(idx)
            msg = f"[warn] 5001#0: *{1000+idx} 1024 worker_connections are not enough while connecting to upstream, client: 198.51.100.120"
            line = f"{t_sec} server-01 nginx[5001]: {msg}"
            logs.append(line)
            records.append({
                'timestamp': t_sec, 'hostname': 'server-01', 'service': 'nginx', 'process': 'nginx',
                'event_type': 'WEB_SERVICE', 'log_level': 'WARN', 'user': 'www-data', 'is_simulated': 1,
                'simulation_scenario': scenario_id, 'is_synthetic': True, 'simulation_token': sim_token,
                'action': 'Worker Connection Exhaustion', 'source': 'Attack Simulator (Simulated Threat)',
                'description': 'Worker connection pool exhausted under volumetric traffic surge.'
            })

        t_sec3 = ts_offset(3)
        msg3 = "[warn] TCP: request_sock_TCP: Possible SYN flooding on port 80. Sending cookies."
        line3 = f"{t_sec3} server-01 kernel[0]: [ 1520.450] {msg3}"
        logs.append(line3)
        records.append({
            'timestamp': t_sec3, 'hostname': 'server-01', 'service': 'kernel', 'process': 'kernel',
            'event_type': 'KERNEL_AUDIT', 'log_level': 'WARN', 'user': 'system', 'is_simulated': 1,
            'simulation_scenario': scenario_id, 'is_synthetic': True, 'simulation_token': sim_token,
            'action': 'SYN Flood Defense Triggered', 'source': 'Attack Simulator (Simulated Threat)',
            'description': 'Kernel activated SYN flood cookies in response to socket backlog overflow.'
        })

        t_sec4 = ts_offset(4)
        msg4 = "Out of memory: Kill process 5001 (nginx) score 950 or sacrifice child"
        line4 = f"{t_sec4} server-01 kernel[0]: [ 1522.112] {msg4}"
        logs.append(line4)
        records.append({
            'timestamp': t_sec4, 'hostname': 'server-01', 'service': 'kernel', 'process': 'kernel',
            'event_type': 'KERNEL_AUDIT', 'log_level': 'ERROR', 'user': 'system', 'is_simulated': 1,
            'simulation_scenario': scenario_id, 'is_synthetic': True, 'simulation_token': sim_token,
            'action': 'Out of Memory Process Termination', 'source': 'Attack Simulator (Simulated Threat)',
            'description': 'Kernel OOM killer terminated process due to critical memory exhaustion.'
        })

    # Trailing Baseline: Normal recovery
    t_end = ts_offset(10)
    l_end = f"{t_end} server-01 postfix/cleanup[1020]: info: system status report generated successfully."
    logs.append(l_end)
    records.append({
        'timestamp': t_end, 'hostname': 'server-01', 'service': 'postfix', 'process': 'postfix',
        'event_type': 'SYSTEM_EVENT', 'log_level': 'INFO', 'user': 'postfix', 'is_simulated': 1,
        'simulation_scenario': scenario_id, 'is_synthetic': True, 'simulation_token': sim_token,
        'action': 'Status Report Logged', 'source': 'Attack Simulator (Normal Baseline)',
        'description': 'Routine post-event status verification log.'
    })

    for idx, r in enumerate(records):
        if 'message' not in r:
            log_line = logs[idx] if idx < len(logs) else ''
            r['message'] = log_line.split(': ', 1)[1] if ': ' in log_line else log_line

    raw_log_content = "\n".join(logs)
    return {
        'scenario_id': scenario_id,
        'scenario_meta': scenario_meta,
        'simulation_token': sim_token,
        'raw_log_content': raw_log_content,
        'raw_records': records,
        'total_events': len(records),
        'attack_events_count': len(records) - 3,  # subtracting 2 prefix and 1 suffix baseline
        # Convenience aliases
        'sim_id': sim_token,
        'raw_text': raw_log_content,
        'events': records,
        'is_simulated': True,
    }


def evaluate_scenario_rule_based(scenario_id, features_dict_list):
    """
    Separate, simulation-only rule-based security assessment.
    Explicitly labeled as heuristic rule analysis to keep genuine ML predictions separate.
    Accepts list of feature dicts, a single feature dict, or a pandas DataFrame.
    """
    if hasattr(features_dict_list, 'to_dict'):
        features_dict_list = features_dict_list.to_dict('records')
    elif isinstance(features_dict_list, dict):
        features_dict_list = [features_dict_list]

    rule_results = []
    for idx, f in enumerate(features_dict_list):
        flagged = False
        rule_name = "Normal Baseline"

        if scenario_id == 'ssh_bruteforce':
            if f.get('failed_login_attempts', 0) >= 2 or f.get('login_attempts', 0) >= 3:
                flagged = True
                rule_name = "Rule: High Failed Login Attempts Burst (Brute Force Heuristic)"

        elif scenario_id == 'buffer_overflow':
            if f.get('sequence_length', 0) > 180 or f.get('error_pattern', 0) == 4 or f.get('unknown_events', 0) > 0:
                flagged = True
                rule_name = "Rule: Oversized Payload with Unknown Signature (Buffer Overflow Heuristic)"

        elif scenario_id == 'privilege_escalation':
            if f.get('error_pattern', 0) == 4 or (f.get('error_count', 0) >= 2 and f.get('unknown_events', 0) > 0):
                flagged = True
                rule_name = "Rule: Security Policy Access Denial (Privilege Escalation Heuristic)"

        elif scenario_id == 'directory_traversal':
            if f.get('error_count', 0) >= 2 and f.get('error_pattern', 0) == 4:
                flagged = True
                rule_name = "Rule: Repeated File Permission Denied (Directory Traversal Heuristic)"

        elif scenario_id == 'dos_burst':
            if f.get('event_frequency', 0) >= 4 and (f.get('error_pattern', 0) == 3 or f.get('warning_count', 0) >= 1 or f.get('error_count', 0) >= 2):
                flagged = True
                rule_name = "Rule: Volumetric Connection Storm with OOM Kill (DoS Heuristic)"

        rule_results.append({
            'event_index': idx,
            'rule_flagged_threat': flagged,
            'matched_rule': rule_name,
            'rule_type': 'Deterministic Static Signature'
        })

    any_flagged = any(r['rule_flagged_threat'] for r in rule_results)
    matched_rule = next((r['matched_rule'] for r in rule_results if r['rule_flagged_threat']), "Normal Baseline")

    return {
        'rule_analysis_type': 'Simulation-Only Static Rule-Based Assessment (Non-ML)',
        'threat_identified_by_rules': any_flagged,
        'rule_summary': (
            f"Rule-based heuristic matched scenario signature '{scenario_id}'" if any_flagged
            else "Rule-based heuristic observed standard operational baseline."
        ),
        'per_event_rules': rule_results,
        # Top-level convenience keys for unit tests and API wrappers
        'is_anomaly': any_flagged,
        'confidence': 0.90 if any_flagged else 0.10,
        'reason': matched_rule
    }
