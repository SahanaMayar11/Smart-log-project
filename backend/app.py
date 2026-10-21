import os
import sys
import json
import socket
import threading
import time
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify
from flask_cors import CORS
from database import init_db, get_db_connection
from ml_engine import run_full_pipeline
from system_log_collector import collect_windows_system_logs, collect_new_windows_events, resolve_application_name, get_system_environment_metadata
from email_alert_manager import email_alert_manager
from attack_simulator import (
    SCENARIOS_CATALOG,
    get_all_scenarios_metadata,
    generate_synthetic_scenario_logs,
    evaluate_scenario_rule_based
)

app = Flask(__name__)
CORS(app)

# Ensure database tables and schema migrations are ready on load
try:
    init_db()
except Exception as e:
    print(f"Warning during startup init_db: {e}")

# Path to sample log file
SAMPLE_LOG_PATH = os.path.join(os.path.dirname(__file__), 'sample_logs', 'server_syslog.log')

# Secret authentication token
ADMIN_SECRET_TOKEN = "smartlog_admin_sec_token_v1_2026"

def is_authenticated(req):
    """Direct access active — Login page disabled as requested."""
    return True


def seed_sample_data_if_empty():
    """Seeds SQLite database with default sample log dataset if no files uploaded."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as count FROM uploaded_files")
    count = cursor.fetchone()['count']
    conn.close()

    if count == 0 and os.path.exists(SAMPLE_LOG_PATH):
        print("Seeding database with default sample log dataset...")
        with open(SAMPLE_LOG_PATH, 'r', encoding='utf-8') as f:
            content = f.read()

        process_and_save_log_file("server_syslog.log", content)

def format_db_row_to_event(row):
    """Formats a SQLite parsed_logs + anomaly + shap row to the exact normalized event schema."""
    item = dict(row)
    is_anomaly = 1 if item.get('is_anomaly') == 1 else 0
    service = str(item.get('service') or item.get('process') or '').lower()
    source_str = str(item.get('source') or '')
    channel_str = str(item.get('channel') or '')
    provider_str = str(item.get('provider') or '')

    is_windows = (
        item.get('os_type') == 'Windows'
        or 'microsoft-windows-' in service
        or 'microsoft-windows-' in provider_str.lower()
        or 'windows' in source_str.lower()
        or channel_str in ['Security', 'System', 'Application', 'PowerShell', 'Defender', 'TaskScheduler']
    )

    is_linux = not is_windows and (
        item.get('os_type') == 'Linux'
        or 'sshd' in service
        or 'sudo' in service
        or 'kernel' in service
        or 'systemd' in service
        or 'cron' in service
        or 'linux' in source_str.lower()
    )

    comp = item.get('computer') or item.get('hostname') or (socket.gethostname() if not is_linux else 'server01') or 'server01'
    pid_v = str(item.get('pid') or item.get('process_id') or 'N/A')

    if is_linux:
        app_n = item.get('application_name') or item.get('application') or item.get('service') or 'Linux Service'
        proc_n = item.get('process_name') or item.get('process') or item.get('service') or 'sshd'
        parent_proc = item.get('parent_process_name') or item.get('parent_process') or 'systemd'
        parent_app = item.get('parent_application') or 'systemd'
        parent_pid = item.get('parent_pid') or 0
        u_name = item.get('user') or 'system'
        u_clean = str(u_name).replace('</Data', '').strip()
        if '\\' in u_clean:
            u_clean = u_clean.split('\\')[-1]
        dom = str(item.get('domain') or comp).replace('</Data', '').strip()
        evt_id = item.get('event_id') or (1001 if item.get('auth_result') == 'success' else 1002 if item.get('auth_result') == 'failure' else 1000)
        chan = item.get('channel') or item.get('service') or 'syslog'
        action = item.get('action') or ('SSH Authentication Succeeded' if 'sshd' in service and is_anomaly == 0 else 'Syslog Event')
        prov = item.get('provider') or f"Linux-{chan}"
        source_val = item.get('source') or f"Linux {item.get('service') or 'Syslog'}"
        source_lbl = item.get('source_label') or f"{comp} — LINUX SERVER"
        desc = item.get('description') or item.get('what_happened') or f"{app_n} activity on {comp}."
    else:
        app_n = item.get('application_name') or item.get('application') or resolve_application_name(item.get('process') or item.get('service'))
        proc_n = item.get('process_name') or item.get('process') or item.get('service') or 'system.exe'
        parent_proc = item.get('parent_process_name') or item.get('parent_process') or item.get('creator_process') or 'explorer.exe'
        parent_app = item.get('parent_application') or resolve_application_name(parent_proc)
        parent_pid = item.get('parent_pid') or item.get('creator_pid') or 0
        u_name = item.get('user') or 'Admin'
        u_clean = str(u_name).replace('</Data', '').strip()
        if '\\' in u_clean:
            u_clean = u_clean.split('\\')[-1]
        dom = str(item.get('domain') or (u_clean.split('\\')[0] if '\\' in str(u_name) else comp) or comp).replace('</Data', '').strip()
        evt_id = item.get('event_id') or 4688
        chan = item.get('channel') or 'Security'
        action = item.get('action') or ('Application Started' if evt_id == 4688 else 'Process Terminated' if evt_id == 4689 else 'Event Logged')
        prov = item.get('provider') or (item.get('service').split(':')[0] if item.get('service') and '[' in str(item.get('service')) else f"Microsoft-Windows-{chan}")
        source_val = item.get('source') or f"Windows {chan}"
        source_lbl = item.get('source_label') or f"{comp} — LOCAL WINDOWS MACHINE"
        desc = item.get('description') or item.get('what_happened') or f"{app_n} event logged on computer {comp}."

    sev = item.get('severity') or ('Critical' if is_anomaly == 1 else 'Normal')
    ts = str(item.get('timestamp') or datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    if 'T' in ts:
        try:
            clean_ts = ts.replace('Z', '').replace('z', '').split('.')[0]
            dt_utc = datetime.fromisoformat(clean_ts).replace(tzinfo=timezone.utc)
            ts = dt_utc.astimezone().strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            ts = ts.replace('T', ' ').split('.')[0]
    time_val = item.get('time') or (ts.split(' ')[1] if ' ' in ts else ts[-8:])

    reasons = item.get('top_3_human_reasons')
    if isinstance(reasons, str):
        try:
            reasons = json.loads(reasons)
        except Exception:
            reasons = [reasons] if reasons else []
    if not isinstance(reasons, list):
        reasons = []

    raw_p = item.get('raw_payload')
    if isinstance(raw_p, str):
        try:
            raw_p = json.loads(raw_p)
        except Exception:
            raw_p = None

    feat_contrib = item.get('feature_contributions')
    if isinstance(feat_contrib, str):
        try:
            feat_contrib = json.loads(feat_contrib)
        except Exception:
            feat_contrib = {}

    raw_desc = item.get('description') or (raw_p.get('description') if isinstance(raw_p, dict) else None)
    if raw_desc and not ('[' in raw_desc and raw_desc.endswith(']')) and not raw_desc.startswith('Microsoft-Windows-'):
        desc = str(raw_desc).replace('</Data', '').strip()
    elif not is_linux:
        if action == 'Application Started':
            desc = f"{app_n} was opened by {u_clean}."
        elif action == 'Application Closed':
            desc = f"{app_n} was closed by {u_clean}."
        elif action in ('Power Source Connected', 'Power Connected'):
            desc = "AC power was connected. The computer is running on external power."
        elif action in ('Power Source Disconnected', 'Power Disconnected'):
            desc = "AC power was disconnected. The computer is running on battery power."
        else:
            desc = f"{app_n} event logged on computer {comp}."

    what_happ = item.get('what_happened') or desc
    if not is_linux and ('[' in str(what_happ) or 'Microsoft-Windows-' in str(what_happ)):
        what_happ = desc

    app_source = item.get('application_source') or (f"Windows {chan} Log ({app_n})" if not is_linux else f"Linux {chan} ({app_n})")
    what_means = item.get('what_it_means') or ("Standard operating system activity recorded in system telemetry." if not is_linux else "Linux system telemetry.")
    why_flag = item.get('why_flagged') or item.get('why_suspicious') or ('This activity is consistent with normal system baseline behavior.' if is_anomaly == 0 else 'Unusual behavioral deviation detected.')
    evid = item.get('evidence') or f"Event ID: {evt_id} | Record ID: {item.get('id')} | User: {u_clean} | Host: {comp}"
    risk_assess = item.get('risk_assessment') or ('Low / Normal: Routine baseline system telemetry.' if is_anomaly == 0 else f"Medium to High: {sev} deviation flagged by unsupervised model.")
    limitations = item.get('limitations_uncertainty') or (
        "Log evidence verifies that this event occurred with the recorded attributes at the specified timestamp. "
        "Telemetry alone cannot establish human intent without corroborating physical presence or surrounding activity."
    )
    tech_details = item.get('technical_details')
    if isinstance(tech_details, str):
        try:
            tech_details = json.loads(tech_details)
        except Exception:
            tech_details = None
    if not tech_details:
        tech_details = {
            'model_name': 'Isolation Forest',
            'explanation_status': 'success',
            'base_value': 0.0,
            'feature_contributions': feat_contrib or {},
            'top_3_human_reasons': reasons
        }

    return {
        'id': f"sec-{evt_id}-{item.get('id')}",
        'log_id': item.get('id'),
        'file_id': item.get('file_id'),
        'timestamp': ts,
        'time': time_val,
        'event_id': evt_id,
        'channel': chan,
        'provider': prov,
        'source': source_val,
        'source_label': source_lbl,
        'computer': comp,
        'host': comp,
        'hostname': comp,
        'application': app_n,
        'application_name': app_n,
        'service': item.get('service') or proc_n,
        'log_level': item.get('log_level') or 'INFO',
        'process': proc_n,
        'process_name': proc_n,
        'pid': pid_v,
        'process_id': pid_v,
        'parent_process': parent_proc,
        'parent_process_name': parent_proc,
        'parent_application': parent_app,
        'parent_pid': parent_pid,
        'creator_pid': parent_pid,
        'creator_process': parent_proc,
        'user': u_clean,
        'account_name': u_clean,
        'domain': dom,
        'action': action,
        'status': 'ANOMALY' if is_anomaly == 1 else 'NORMAL',
        'severity': sev,
        'anomaly_score': round(float(item.get('anomaly_score') or 0.25), 4),
        'is_anomaly': is_anomaly,
        'description': desc,
        'what_happened': what_happ,
        'application_source': app_source,
        'what_it_means': what_means,
        'why_flagged': why_flag,
        'why_suspicious': why_flag,
        'evidence': evid,
        'risk_assessment': risk_assess,
        'recommended_action': item.get('recommended_action') or ('No action required. Continue standard operational monitoring.' if is_anomaly == 0 else 'Investigate event source and execution context.'),
        'limitations_uncertainty': limitations,
        'top_3_human_reasons': reasons,
        'feature_contributions': feat_contrib or {},
        'technical_details': tech_details,
        'message': item.get('message') or desc,
        'raw_process_path': item.get('raw_process_path') or item.get('executable_path', ''),
        'executable_path': item.get('executable_path') or item.get('raw_process_path', ''),
        'device': item.get('device', ''),
        'raw_payload': raw_p or item
    }


def process_and_save_log_file(filename, content, n_estimators=100, contamination=0.15, raw_records=None, is_simulated=0, simulation_scenario=None):
    """Runs ML pipeline and saves parsed logs, features, detections, and SHAP to SQLite with rich telemetry."""
    results = run_full_pipeline(content, n_estimators=n_estimators, contamination=contamination)

    parsed_logs = results['parsed_logs']
    features = results['features']
    detections = results['detection_results']
    shaps = results['shap_explanations']

    total_logs = len(parsed_logs)
    anomaly_count = sum(1 for d in detections if d['is_anomaly'] == 1)
    normal_count = total_logs - anomaly_count

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Insert file record with simulation flags
    cursor.execute('''
        INSERT INTO uploaded_files (filename, total_logs, normal_count, anomaly_count, is_simulated, simulation_scenario)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (filename, total_logs, normal_count, anomaly_count, is_simulated, simulation_scenario))
    file_id = cursor.lastrowid

    # 2. Query starting autoincrement ID for parsed_logs
    cursor.execute("SELECT COALESCE(MAX(id), 0) + 1 AS next_id FROM parsed_logs")
    start_log_id = cursor.fetchone()['next_id']

    logs_data = []
    for idx, log in enumerate(parsed_logs):
        raw_r = raw_records[idx] if raw_records and idx < len(raw_records) else {}
        service_str = str(log.get('service', '')).lower()
        is_windows_raw = bool(
            raw_r.get('channel') in ['Security', 'System', 'Application', 'PowerShell', 'Defender', 'TaskScheduler']
            or str(raw_r.get('source', '')).startswith('Windows')
            or str(raw_r.get('provider', '')).startswith('Microsoft-Windows-')
            or raw_r.get('os') == 'Windows 10/11'
            or raw_r.get('event_type') in ['USER_LOGON', 'FAILED_LOGON', 'PROCESS_START', 'PROCESS_TERMINATION', 'WORKSTATION_LOCKED', 'WORKSTATION_UNLOCKED', 'POWERSHELL_TELEMETRY', 'NETWORK_CONNECTIVITY']
        )
        is_windows_log = bool(
            log.get('os_type') == 'Windows'
            or 'microsoft-windows-' in service_str
            or log.get('channel') in ['Security', 'System', 'Application', 'PowerShell', 'Defender', 'TaskScheduler']
        )

        if is_windows_raw or is_windows_log:
            is_linux = False
        else:
            is_linux = (
                log.get('os_type') == 'Linux'
                or 'sshd' in service_str
                or 'sudo' in service_str
                or 'kernel' in service_str
                or 'systemd' in service_str
                or 'cron' in service_str
            )

        if is_linux:
            app = log.get('service') or 'Linux Service'
            proc = log.get('service') or 'sshd'
            pid_val = str(log.get('pid') or raw_r.get('pid') or 'N/A')
            p_pid = '0'
            p_proc = 'systemd'
            p_app = 'systemd'
            u_clean = str(log.get('user') or raw_r.get('user') or 'system').replace('</Data', '').strip()
            d_name = str(log.get('hostname') or 'server01').replace('</Data', '').strip()
            comp_name = log.get('hostname') or 'server01'
            act = log.get('action') or ('SSH Authentication Succeeded' if log.get('auth_result') == 'success' else 'SSH Authentication Failed' if log.get('auth_result') == 'failure' else 'Syslog Event')
            desc = log.get('description') or f"{app} activity recorded on {comp_name}."
            raw_p = raw_r.get('raw_process_path', f"/usr/sbin/{proc}")
            exe_p = raw_r.get('executable_path', f"/usr/sbin/{proc}")
            src = f"Linux {log.get('service', 'Syslog')}" if not is_simulated else 'Attack Simulator'
            src_lbl = f"{comp_name} — LINUX SERVER" if not is_simulated else f"{comp_name} — SIMULATED DEMONSTRATION"
            dev = raw_r.get('device', 'eth0')
            chan = 'syslog'
            evt_id = int(raw_r.get('event_id') or (1001 if log.get('auth_result') == 'success' else 1002 if log.get('auth_result') == 'failure' else 1000))
        else:
            app = raw_r.get('application_name') or raw_r.get('application') or resolve_application_name(log.get('service', 'System'))
            proc = raw_r.get('process_name') or raw_r.get('process') or log.get('service') or 'system.exe'
            pid_val = str(raw_r.get('pid') or raw_r.get('process_id') or log.get('pid') or 'N/A')
            p_pid = str(raw_r.get('parent_pid') or raw_r.get('creator_pid') or raw_r.get('parent_process_id') or 0)
            p_proc = raw_r.get('parent_process_name') or raw_r.get('parent_process') or raw_r.get('creator_process') or 'explorer.exe'
            p_app = raw_r.get('parent_application') or resolve_application_name(p_proc)
            u_name = str(raw_r.get('user') or raw_r.get('account_name') or f"{log['hostname']}\\Admin").replace('</Data', '').strip()
            u_clean = u_name.split('\\')[-1] if '\\' in str(u_name) else str(u_name)
            d_name = str(raw_r.get('domain') or (u_name.split('\\')[0] if '\\' in str(u_name) else log['hostname']) or log['hostname']).replace('</Data', '').strip()
            comp_name = raw_r.get('computer') or log['hostname']
            act = raw_r.get('action') or raw_r.get('event_type') or ('Application Started' if raw_r.get('event_id') == 4688 else 'Process Terminated' if raw_r.get('event_id') == 4689 else 'Event Logged')
            desc = log.get('description') or raw_r.get('description') or f"{app} was started by {u_clean} on computer {comp_name}."
            raw_p = raw_r.get('raw_process_path') or raw_r.get('executable_path', '')
            exe_p = raw_r.get('executable_path') or raw_r.get('raw_process_path', '')
            src = raw_r.get('source', 'Windows Security' if not is_simulated else 'Attack Simulator')
            src_lbl = raw_r.get('source_label', f"{comp_name} — LOCAL WINDOWS MACHINE" if not is_simulated else f"{comp_name} — SIMULATED DEMONSTRATION")
            dev = raw_r.get('device', '')
            chan = raw_r.get('channel', 'Security')
            evt_id = int(raw_r.get('event_id') or 4688)

        rec_id = int(raw_r.get('record_id') or (start_log_id + idx))
        t_str = raw_r.get('time') or (str(log['timestamp']).split('T')[1].split('.')[0] if 'T' in str(log['timestamp']) else str(log['timestamp'])[-8:])
        stat = 'ANOMALY' if detections[idx]['is_anomaly'] == 1 else 'NORMAL'
        unq_key = raw_r.get('unique_event_key') or f"{comp_name}_{chan}_{evt_id}_{rec_id}_{pid_val}_{log['timestamp']}"
        raw_pl = json.dumps(raw_r) if raw_r else None

        logs_data.append((
            file_id, log['timestamp'], log['hostname'], log['service'], log['log_level'], log['event_type'], log['message'],
            chan, evt_id, rec_id, app, app, proc, proc, pid_val, pid_val,
            p_pid, p_proc, p_proc, p_app, p_pid, p_proc, u_clean, d_name, comp_name,
            act, desc, raw_p, exe_p, src, src_lbl, dev, t_str, stat, unq_key, raw_pl,
            is_simulated, simulation_scenario
        ))

    cursor.executemany('''
        INSERT INTO parsed_logs (
            file_id, timestamp, hostname, service, log_level, event_type, message,
            channel, event_id, record_id, application, application_name, process, process_name,
            pid, process_id, parent_pid, parent_process, parent_process_name, parent_application,
            creator_pid, creator_process, user, domain, computer, action, description,
            raw_process_path, executable_path, source, source_label, device, time, status,
            unique_event_key, raw_payload, is_simulated, simulation_scenario
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', logs_data)

    # Fetch actual generated primary key IDs for parsed_logs for file_id
    cursor.execute("SELECT id FROM parsed_logs WHERE file_id = ? ORDER BY id ASC", (file_id,))
    actual_log_ids = [r['id'] for r in cursor.fetchall()]

    features_data = []
    detections_data = []
    shaps_data = []

    for idx, (log, feat, det, sh) in enumerate(zip(parsed_logs, features, detections, shaps)):
        log_db_id = actual_log_ids[idx] if idx < len(actual_log_ids) else (start_log_id + idx)
        features_data.append((file_id, log_db_id, feat['event_frequency'], feat['sequence_length'], feat['error_count'],
                              feat['error_pattern'], feat['login_attempts'], feat['failed_login_attempts'], feat['warning_count'], feat['unknown_events']))
        cons_state = det.get('consensus_state', 'Consensus Anomaly' if det['is_anomaly'] == 1 else 'Consensus Normal')
        cons_agree = 1 if det.get('consensus_agreement', True) else 0
        detections_data.append((file_id, log_db_id, det['is_anomaly'], det['anomaly_score'], det['severity'], is_simulated, simulation_scenario, cons_state, cons_agree))
        shaps_data.append((
            file_id, log_db_id,
            json.dumps(sh['feature_contributions']),
            sh['top_reason'],
            sh['natural_explanation'],
            sh.get('what_happened', ''),
            sh.get('why_suspicious', ''),
            sh.get('recommended_action', ''),
            json.dumps(sh.get('top_3_human_reasons', [])),
            sh.get('application_source', ''),
            sh.get('what_it_means', ''),
            sh.get('why_flagged', ''),
            sh.get('evidence', ''),
            sh.get('risk_assessment', ''),
            sh.get('limitations_uncertainty', ''),
            json.dumps(sh.get('technical_details', {})),
            is_simulated
        ))

    cursor.executemany('''
        INSERT INTO extracted_features (
            file_id, log_id, event_frequency, sequence_length, error_count,
            error_pattern, login_attempts, failed_login_attempts, warning_count, unknown_events
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', features_data)

    cursor.executemany('''
        INSERT INTO anomaly_results (file_id, log_id, is_anomaly, anomaly_score, severity, is_simulated, simulation_scenario, consensus_state, consensus_agreement)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', detections_data)

    cursor.executemany('''
        INSERT INTO shap_explanations (
            file_id, log_id, feature_contributions, top_reason, natural_explanation,
            what_happened, why_suspicious, recommended_action, top_3_human_reasons,
            application_source, what_it_means, why_flagged, evidence,
            risk_assessment, limitations_uncertainty, technical_details, is_simulated
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', shaps_data)

    conn.commit()
    conn.close()
    return file_id, total_logs, normal_count, anomaly_count



# API Endpoints

@app.route('/', methods=['GET'])
def root_index():
    """Root landing endpoint for the backend server."""
    if request.headers.get('Accept', '').find('text/html') != -1:
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Smart-Log Backend API</title>
            <style>
                body { background: #0B1220; color: #E2E8F0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
                .card { background: #0F172A; border: 1px solid #1E293B; border-radius: 16px; padding: 40px; max-width: 600px; text-align: center; box-shadow: 0 20px 40px rgba(0,0,0,0.5); }
                .badge { background: rgba(16, 185, 129, 0.2); color: #10B981; border: 1px solid rgba(16, 185, 129, 0.4); padding: 4px 12px; border-radius: 999px; font-size: 12px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; display: inline-block; margin-bottom: 16px; }
                h1 { color: #FFFFFF; margin: 0 0 10px 0; font-size: 24px; }
                p { color: #94A3B8; font-size: 14px; line-height: 1.6; margin: 0 0 24px 0; }
                .btn { background: #00E5FF; color: #0B1220; padding: 12px 28px; border-radius: 8px; font-weight: bold; text-decoration: none; font-size: 14px; display: inline-block; transition: all 0.2s; }
                .btn:hover { background: #38bdf8; transform: translateY(-2px); }
                .endpoints { margin-top: 28px; padding-top: 20px; border-top: 1px solid #1E293B; text-align: left; }
                .endpoints h3 { font-size: 12px; color: #64748B; text-transform: uppercase; margin: 0 0 10px 0; letter-spacing: 1px; }
                .endpoints a { color: #38BDF8; font-family: monospace; font-size: 13px; text-decoration: none; display: block; margin: 6px 0; }
                .endpoints a:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <div class="card">
                <span class="badge">● Backend Online</span>
                <h1>Smart-Log Python Backend API</h1>
                <p>The Flask API server is running successfully on <strong>port 5000</strong>. If you are looking for the interactive React dashboard, launch or navigate to the frontend server:</p>
                <a href="http://localhost:3000" class="btn">Open Frontend Dashboard (Port 3000)</a>
                <div class="endpoints">
                    <h3>Available API Endpoints</h3>
                    <a href="/api/dashboard/stats">GET /api/dashboard/stats</a>
                    <a href="/api/detection/results">GET /api/detection/results</a>
                    <a href="/api/logs/parsed">GET /api/logs/parsed</a>
                    <a href="/api/test/scenarios">GET /api/test/scenarios</a>
                </div>
            </div>
        </body>
        </html>
        ''', 200

    return jsonify({
        'status': 'online',
        'service': 'Smart-Log Backend API',
        'message': 'Flask Backend is running on port 5000. Open the frontend dashboard at http://localhost:3000',
        'version': '1.0.0',
        'endpoints': {
            'dashboard_stats': '/api/dashboard/stats',
            'detection_results': '/api/detection/results',
            'parsed_logs': '/api/logs/parsed',
            'scenarios': '/api/test/scenarios'
        }
    }), 200

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Simple Admin Authentication returning secure session token."""
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin_users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify({
            'status': 'success',
            'message': 'Admin authenticated successfully.',
            'token': ADMIN_SECRET_TOKEN
        }), 200

    return jsonify({'status': 'error', 'message': 'Invalid username or password.'}), 401

@app.route('/api/system-logs/analyze', methods=['POST', 'GET'])
def analyze_system_logs():
    """Collects actual Windows Event Logs and runs Isolation Forest + SHAP pipeline [Protected]."""
    if not is_authenticated(request):
        return jsonify({'status': 'error', 'message': 'Unauthorized. Please login.'}), 401

    try:
        data = (request.json or {}) if request.method == 'POST' else request.args
        hours = int(data.get('hours', 24))
        max_events = int(data.get('max_events', 2000))
        force_scan = bool(data.get('force_scan', False))

        now = datetime.now()
        start_cutoff = (now - timedelta(hours=hours)).isoformat()
        start_space = start_cutoff.replace('T', ' ')
        start_iso = start_cutoff.replace(' ', 'T')
        end_time = now.isoformat()
        hostname = socket.gethostname() or os.environ.get('COMPUTERNAME') or 'Rocky'

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check existing 24-hour log count in SQLite
        cursor.execute("SELECT COUNT(*) as cnt FROM parsed_logs WHERE timestamp >= ? OR timestamp >= ?", (start_space, start_iso))
        existing_cnt = cursor.fetchone()['cnt']
        conn.close()

        scanned_channels = ["Security", "System", "Application"]
        unavailable_channels = []
        scan_status = "SUCCESS"
        admin_warning = None
        channel_diagnostics = {}
        limit_reached = False
        limit_message = None
        file_id = None
        filename = f"Windows_Event_Logs_{hostname}.log"

        # Ingest fresh historical logs if requested or if database needs update
        if existing_cnt < 20 or force_scan or True:
            collector_result = collect_windows_system_logs(hours=hours, max_events=max_events)
            hostname = collector_result['hostname']
            log_content = collector_result['log_content']
            scanned_channels = collector_result['scanned_channels']
            unavailable_channels = collector_result.get('unavailable_channels', [])
            scan_status = collector_result['scan_status']
            admin_warning = collector_result['admin_warning']
            channel_diagnostics = collector_result.get('channel_diagnostics', {})
            limit_reached = collector_result.get('limit_reached', False)
            limit_message = collector_result.get('limit_message', None)

            if log_content and log_content.strip():
                file_id, _, _, _ = process_and_save_log_file(
                    filename,
                    log_content,
                    raw_records=collector_result.get('records', [])
                )

        # Retrieve all enriched historical events in the 24-hour window from SQLite
        conn = get_db_connection()
        cursor = conn.cursor()
        limit_val = max(100, min(10000, max_events))
        cursor.execute('''
            SELECT p.*,
                   a.is_anomaly, a.anomaly_score, a.severity,
                   s.what_happened, s.why_suspicious, s.recommended_action, s.top_3_human_reasons,
                   s.application_source, s.what_it_means, s.why_flagged, s.evidence,
                   s.risk_assessment, s.limitations_uncertainty, s.technical_details, s.feature_contributions
            FROM parsed_logs p
            JOIN anomaly_results a ON p.id = a.log_id
            LEFT JOIN shap_explanations s ON p.id = s.log_id
            WHERE p.timestamp >= ? OR p.timestamp >= ?
            ORDER BY p.id DESC LIMIT ?
        ''', (start_space, start_iso, limit_val))
        rows = cursor.fetchall()
        conn.close()

        historical_events = []
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Normal": 0}
        channel_distribution = {}
        level_distribution = {}
        timeline_chart = []
        shap_feature_counter = {}

        for r in rows:
            formatted_evt = format_db_row_to_event(r)
            sev = formatted_evt.get('severity') or ('Critical' if formatted_evt.get('is_anomaly') == 1 else 'Normal')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            srv = formatted_evt.get('channel') or formatted_evt.get('service') or 'Security'
            channel_distribution[srv] = channel_distribution.get(srv, 0) + 1

            lvl = r['log_level'] if 'log_level' in r.keys() else 'INFORMATION'
            level_distribution[lvl] = level_distribution.get(lvl, 0) + 1

            timeline_chart.append({
                'id': formatted_evt['id'],
                'timestamp': formatted_evt['timestamp'],
                'anomaly_score': formatted_evt['anomaly_score'],
                'is_anomaly': formatted_evt['is_anomaly']
            })

            for reason in formatted_evt.get('top_3_human_reasons', []):
                if isinstance(reason, str):
                    shap_feature_counter[reason] = shap_feature_counter.get(reason, 0) + 1

            historical_events.append(formatted_evt)

        # Apply evidence-based Windows Authentication incident correlation
        from incident_correlator import WindowsAuthenticationCorrelator
        corr_res = WindowsAuthenticationCorrelator.correlate_events(historical_events)
        correlated_events = corr_res['correlated_events']
        incidents = corr_res['incidents']

        total_logs = len(correlated_events)
        anomaly_count = sum(1 for e in correlated_events if e['is_anomaly'] == 1)
        normal_count = total_logs - anomaly_count

        top_shap_features = [
            {"reason": k, "count": v}
            for k, v in sorted(shap_feature_counter.items(), key=lambda x: x[1], reverse=True)[:5]
        ]

        return jsonify({
            'status': 'success',
            'success': True,
            'source': 'Windows Event Logs',
            'analysis_mode': 'LAST 24 HOURS',
            'start_time': start_cutoff,
            'end_time': end_time,
            'events_collected': total_logs,
            'events_processed': total_logs,
            'total_logs': total_logs,
            'normal_events': normal_count,
            'normal_count': normal_count,
            'anomaly_events': anomaly_count,
            'anomaly_count': anomaly_count,
            'anomaly_percentage': round((anomaly_count / total_logs) * 100, 2) if total_logs > 0 else 0.0,
            'computer_name': hostname,
            'computer': hostname,
            'host': hostname,
            'scanned_channels': scanned_channels,
            'unavailable_channels': unavailable_channels,
            'scan_status': scan_status,
            'admin_warning': admin_warning,
            'channel_diagnostics': channel_diagnostics,
            'limit_reached': limit_reached,
            'limit_message': limit_message,
            'file_id': file_id,
            'filename': filename,
            'severity_counts': severity_counts,
            'channel_distribution': channel_distribution,
            'level_distribution': level_distribution,
            'timeline_chart': timeline_chart,
            'top_shap_features': top_shap_features,
            'historical_events': correlated_events,
            'events': correlated_events,
            'incidents': incidents,
            'has_active_attack_pattern': corr_res['has_active_attack_pattern'],
            'model': 'IsolationForest',
            'features': 8,
            'shap': True
        }), 200
    except Exception as e:
        import traceback
        print(f"Error analyzing system logs: {e}")
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': f'System log scan failed: {str(e)}'}), 500


@app.route('/api/system-logs/historical', methods=['GET'])
def get_historical_system_logs():
    """Returns the latest 24-hour historical records directly from SQLite without interrupting live monitoring."""
    try:
        hours = int(request.args.get('hours', 24))
        now = datetime.now()
        start_cutoff = (now - timedelta(hours=hours)).isoformat()
        start_space = start_cutoff.replace('T', ' ')
        start_iso = start_cutoff.replace(' ', 'T')
        min_cutoff = min(start_space, start_iso)
        hostname = socket.gethostname() or 'Rocky'

        conn = get_db_connection()
        cursor = conn.cursor()
        limit_val = int(request.args.get('limit', 500))
        cursor.execute('''
            SELECT p.*,
                   a.is_anomaly, a.anomaly_score, a.severity,
                   s.what_happened, s.why_suspicious, s.recommended_action, s.top_3_human_reasons, s.feature_contributions,
                   s.application_source, s.what_it_means, s.why_flagged, s.evidence,
                   s.risk_assessment, s.limitations_uncertainty, s.technical_details
            FROM parsed_logs p
            JOIN anomaly_results a ON p.id = a.log_id AND p.file_id = a.file_id
            LEFT JOIN shap_explanations s ON p.id = s.log_id AND p.file_id = s.file_id
            WHERE p.timestamp >= ? OR p.timestamp >= ?
            ORDER BY p.id DESC LIMIT ?
        ''', (start_space, start_iso, limit_val))
        rows = cursor.fetchall()
        conn.close()

        raw_events = [format_db_row_to_event(r) for r in rows]

        from incident_correlator import WindowsAuthenticationCorrelator
        corr_res = WindowsAuthenticationCorrelator.correlate_events(raw_events)
        historical_events = corr_res['correlated_events']
        total_logs = len(historical_events)
        anomaly_count = sum(1 for e in historical_events if e.get('is_anomaly') == 1)
        normal_count = total_logs - anomaly_count

        return jsonify({
            'status': 'success',
            'computer_name': hostname,
            'total_logs': total_logs,
            'normal_count': normal_count,
            'anomaly_count': anomaly_count,
            'incidents': corr_res['incidents'],
            'has_active_attack_pattern': corr_res['has_active_attack_pattern'],
            'historical_events': historical_events
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


class LiveMonitorManager:
    def __init__(self):
        self.is_monitoring = True
        self.interval = 3.0
        self.thread = None
        self.lock = threading.Lock()
        self.last_scan_time = datetime.now().isoformat()
        self.total_monitored = 0
        self.last_record_ids = {}
        self.processed_keys = set()
        self.live_buffer = []
        self.scanned_channels = ["System", "Application", "Security"]
        self.unavailable_channels = []
        self.admin_warning = None
        self.hostname = socket.gethostname() or 'Rocky'
        self._start_thread_if_needed()

    def _start_thread_if_needed(self):
        if self.thread is None or not self.thread.is_alive():
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()

    def start_monitoring(self, interval=3.0):
        with self.lock:
            self.interval = max(1.0, min(10.0, float(interval)))
            self.is_monitoring = True
            self._start_thread_if_needed()

    def stop_monitoring(self):
        with self.lock:
            self.is_monitoring = False

    def _monitor_loop(self):
        while True:
            if self.is_monitoring:
                try:
                    res = collect_new_windows_events(self.last_record_ids, max_events=200)
                    self.hostname = res.get('hostname', self.hostname)
                    self.scanned_channels = res.get('scanned_channels', self.scanned_channels)
                    self.unavailable_channels = res.get('unavailable_channels', self.unavailable_channels)
                    self.admin_warning = res.get('admin_warning', self.admin_warning)
                    self.last_record_ids = res.get('last_record_ids', self.last_record_ids)

                    new_records = res.get('records', [])
                    filtered_records = []
                    skipped_duplicates = 0

                    for r in new_records:
                        key = (r['channel'], r.get('record_id', 0), r.get('pid', 0))
                        if key not in self.processed_keys:
                            self.processed_keys.add(key)
                            filtered_records.append(r)
                            if len(self.processed_keys) > 10000:
                                self.processed_keys.clear()
                        else:
                            skipped_duplicates += 1

                    if filtered_records:
                        print(f"\n[LIVE COLLECTOR]\nChannel: {', '.join(self.scanned_channels)}\nLast RecordId: {list(self.last_record_ids.values())[-1] if self.last_record_ids else 'N/A'}\nNew Events: {len(filtered_records)}")

                        for r in filtered_records:
                            if r.get('event_type') in ('PROCESS_START', 'PROCESS_TERMINATION', 'APPLICATION START', 'APPLICATION CLOSE'):
                                print(f"[PROCESS EVENT]\nApplication: {r.get('application_name') or r.get('process_name')}\nPID: {r.get('pid')}\nEvent ID: {r.get('event_id')}\nAction: {r.get('action')}")
                            elif r.get('event_type') == 'POWER_EVENT':
                                print(f"[POWER EVENT]\nAC Power: {'CONNECTED' if r.get('power_plugged') else 'DISCONNECTED'}\nBattery: {r.get('battery_percent', 0)}%")

                        print(f"[DEDUP]\nSkipped duplicate events: {skipped_duplicates}")

                        syslog_lines = [
                            f"{r.get('timestamp')} {r.get('hostname')} {r.get('provider', 'Windows')}[{r.get('event_id', 4688)}]: {r.get('level') or r.get('severity') or 'INFORMATION'} - [Channel:{r.get('channel', 'Security')}|RecordID:{r.get('record_id', 0)}] {r.get('message', r.get('description', 'Windows Event'))}"
                            for r in filtered_records
                        ]
                        content = "\n".join(syslog_lines)
                        file_id, total_logs, normal_count, anomaly_count = process_and_save_log_file(
                            f"Live_Windows_System_Logs_{self.hostname}.log",
                            content,
                            raw_records=filtered_records
                        )

                        conn = get_db_connection()
                        cursor = conn.cursor()
                        cursor.execute('''
                            SELECT p.*,
                                   a.is_anomaly, a.anomaly_score, a.severity,
                                   s.what_happened, s.why_suspicious, s.recommended_action, s.top_3_human_reasons,
                                   s.application_source, s.what_it_means, s.why_flagged, s.evidence,
                                   s.risk_assessment, s.limitations_uncertainty, s.technical_details, s.feature_contributions
                            FROM parsed_logs p
                            JOIN anomaly_results a ON p.id = a.log_id AND p.file_id = a.file_id
                            LEFT JOIN shap_explanations s ON p.id = s.log_id AND p.file_id = s.file_id
                            WHERE p.file_id = ?
                            ORDER BY p.id DESC LIMIT ?
                        ''', (file_id, len(filtered_records)))
                        rows = cursor.fetchall()
                        conn.close()

                        for row in rows:
                            item = format_db_row_to_event(row)
                            if item.get('is_anomaly') == 1:
                                email_alert_manager.send_alert_async(item)

                            with self.lock:
                                self.live_buffer.insert(0, item)
                                if len(self.live_buffer) > 300:
                                    self.live_buffer.pop()

                        with self.lock:
                            self.total_monitored += len(filtered_records)
                        print(f"[ML]\nProcessed: {len(filtered_records)}\nNormal: {normal_count}\nAnomalies: {anomaly_count}\n")
                    else:
                        print("[LIVE COLLECTOR]\nNo new Windows telemetry events detected.")

                    self.last_scan_time = datetime.now().isoformat()
                except Exception as e:
                    print(f"Live monitoring loop exception: {e}")

            time.sleep(self.interval)

live_monitor = LiveMonitorManager()

@app.route('/api/system-logs/live', methods=['GET'])
def get_live_system_logs():
    """Returns real-time buffered Windows system telemetry logs with active ML detection."""
    limit = int(request.args.get('limit', 100))
    with live_monitor.lock:
        events = list(live_monitor.live_buffer[:limit])
        normal_count = sum(1 for e in live_monitor.live_buffer if e.get('is_anomaly') == 0)
        anomaly_count = sum(1 for e in live_monitor.live_buffer if e.get('is_anomaly') == 1)
        tot_mon = live_monitor.total_monitored
        buf_len = len(live_monitor.live_buffer)

    from incident_correlator import WindowsAuthenticationCorrelator
    corr_res = WindowsAuthenticationCorrelator.correlate_events(events)

    from system_log_collector import get_system_environment_metadata
    sys_env = get_system_environment_metadata()

    return jsonify({
        'status': 'success',
        'is_monitoring': live_monitor.is_monitoring,
        'monitoring_status': 'LIVE ● Monitoring' if live_monitor.is_monitoring else 'MONITORING STOPPED',
        'interval': live_monitor.interval,
        'last_scan_time': live_monitor.last_scan_time,
        'computer_name': live_monitor.hostname,
        'computer': live_monitor.hostname,
        'hostname': live_monitor.hostname,
        'source_label': f"{live_monitor.hostname} — LOCAL WINDOWS MACHINE",
        'user': sys_env.get('user', 'Admin'),
        'domain': sys_env.get('domain', live_monitor.hostname),
        'os': sys_env.get('os', 'Windows 11'),
        'ip_address': sys_env.get('ip_address', '127.0.0.1'),
        'total_events_monitored': tot_mon,
        'total_monitored': tot_mon,
        'buffer_total': buf_len,
        'buffer_count': buf_len,
        'normal_count': normal_count,
        'anomaly_count': anomaly_count,
        'scanned_channels': live_monitor.scanned_channels,
        'unavailable_channels': live_monitor.unavailable_channels,
        'admin_warning': live_monitor.admin_warning,
        'incidents': corr_res['incidents'],
        'has_active_attack_pattern': corr_res['has_active_attack_pattern'],
        'events': corr_res['correlated_events']
    }), 200

@app.route('/api/system-logs/monitor/start', methods=['POST'])
def start_live_monitor():
    """Starts live Windows Event Log monitoring."""
    data = request.json or {}
    interval = data.get('interval', 3.0)
    live_monitor.start_monitoring(interval)
    return jsonify({
        'status': 'success',
        'message': f'Live Windows Event Log monitoring started ({interval}s interval).',
        'is_monitoring': True,
        'interval': live_monitor.interval
    }), 200

@app.route('/api/system-logs/monitor/stop', methods=['POST'])
def stop_live_monitor():
    """Stops live Windows Event Log monitoring."""
    live_monitor.stop_monitoring()
    return jsonify({
        'status': 'success',
        'message': 'Live Windows Event Log monitoring stopped.',
        'is_monitoring': False
    }), 200

@app.route('/api/system-logs/monitor/status', methods=['GET'])
def get_monitor_status():
    """Returns status of live Windows log monitoring thread."""
    return jsonify({
        'is_monitoring': live_monitor.is_monitoring,
        'monitoring_status': 'LIVE ● Monitoring' if live_monitor.is_monitoring else 'MONITORING STOPPED',
        'interval': live_monitor.interval,
        'last_scan_time': live_monitor.last_scan_time,
        'computer_name': live_monitor.hostname,
        'total_events_monitored': live_monitor.total_monitored,
        'scanned_channels': live_monitor.scanned_channels,
        'unavailable_channels': live_monitor.unavailable_channels,
        'admin_warning': live_monitor.admin_warning
    }), 200

@app.route('/api/system-logs/diagnostics', methods=['GET'])

def get_live_diagnostics():
    """Diagnostic endpoint verifying Windows Event Log channels, computer name, and live collector status."""
    hostname = socket.gethostname() or os.environ.get('COMPUTERNAME') or 'windows-server'
    diag_res = collect_windows_system_logs(hours=1, max_events=10)

    newest_timestamp = None
    if live_monitor.live_buffer:
        newest_timestamp = live_monitor.live_buffer[0].get('timestamp')
    elif diag_res.get('records'):
        newest_timestamp = diag_res['records'][0].get('timestamp')
    else:
        newest_timestamp = datetime.now().isoformat()

    return jsonify({
        'status': 'success',
        'computer_name': hostname,
        'live_collector_status': 'RUNNING' if live_monitor.is_monitoring else 'STOPPED',
        'total_events_monitored': live_monitor.total_monitored,
        'live_buffer_size': len(live_monitor.live_buffer),
        'newest_event_timestamp': newest_timestamp,
        'scanned_channels': diag_res.get('scanned_channels', []),
        'unavailable_channels': diag_res.get('unavailable_channels', []),
        'channel_diagnostics': diag_res.get('channel_diagnostics', {}),
        'admin_warning': diag_res.get('admin_warning')
    }), 200







def get_latest_file_id(cursor):
    """Returns the latest primary analysis dataset ID (preferring full analysis/upload over micro live ticks or single test logs)."""
    cursor.execute("SELECT id FROM uploaded_files WHERE filename NOT LIKE 'Live_%' AND (is_simulated = 0 OR is_simulated IS NULL) AND total_logs > 10 ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    if not row:
        cursor.execute("SELECT id FROM uploaded_files WHERE filename NOT LIKE 'Live_%' AND (is_simulated = 0 OR is_simulated IS NULL) ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
    if not row:
        cursor.execute("SELECT id FROM uploaded_files ORDER BY total_logs DESC, id DESC LIMIT 1")
        row = cursor.fetchone()
    return row['id'] if row else None


@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    """Returns KPI metrics and chart distributions [Protected]."""
    if not is_authenticated(request):
        return jsonify({'status': 'error', 'message': 'Unauthorized. Please login.'}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    file_id = request.args.get('file_id') or get_latest_file_id(cursor)
    latest_file = None
    if file_id:
        cursor.execute("SELECT * FROM uploaded_files WHERE id = ?", (file_id,))
        latest_file = cursor.fetchone()

    if not latest_file:
        cursor.execute("SELECT * FROM uploaded_files ORDER BY id DESC LIMIT 1")
        latest_file = cursor.fetchone()

    if not latest_file:
        conn.close()
        return jsonify({
            'total_logs': 0, 'normal_logs': 0, 'anomaly_logs': 0,
            'latest_file': 'None', 'recent_alerts': [], 'pie_chart': {},
            'bar_chart': {}, 'line_chart': {}, 'timeline_chart': []
        }), 200

    file_id = latest_file['id']

    cursor.execute("SELECT COUNT(*) as cnt FROM parsed_logs WHERE file_id = ?", (file_id,))
    total_logs = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM anomaly_results WHERE file_id = ? AND is_anomaly = 1", (file_id,))
    anomaly_logs = cursor.fetchone()['cnt']
    normal_logs = total_logs - anomaly_logs

    cursor.execute('''
        SELECT p.id, p.timestamp, p.hostname, p.service, p.log_level, p.event_type, p.message,
               a.anomaly_score, a.severity, s.natural_explanation
        FROM parsed_logs p
        JOIN anomaly_results a ON p.id = a.log_id AND p.file_id = a.file_id
        LEFT JOIN shap_explanations s ON p.id = s.log_id AND p.file_id = s.file_id
        WHERE p.file_id = ? AND a.is_anomaly = 1
        ORDER BY p.id DESC LIMIT 5
    ''', (file_id,))
    recent_alerts = [dict(row) for row in cursor.fetchall()]

    cursor.execute('''
        SELECT service, COUNT(*) as count
        FROM parsed_logs
        WHERE file_id = ? AND log_level = 'ERROR'
        GROUP BY service ORDER BY count DESC LIMIT 5
    ''', (file_id,))
    bar_chart_rows = cursor.fetchall()
    bar_chart = {row['service']: row['count'] for row in bar_chart_rows}

    cursor.execute('''
        SELECT p.id, p.timestamp, a.anomaly_score, a.is_anomaly
        FROM parsed_logs p
        JOIN anomaly_results a ON p.id = a.log_id AND p.file_id = a.file_id
        WHERE p.file_id = ?
        ORDER BY p.id ASC
    ''', (file_id,))
    timeline_rows = [dict(row) for row in cursor.fetchall()]

    conn.close()

    human_summary = (
        f"{total_logs} system events analyzed. "
        f"{normal_logs} events were normal. "
        f"{anomaly_logs} suspicious events were detected."
    )

    return jsonify({
        'total_logs': total_logs,
        'normal_logs': normal_logs,
        'anomaly_logs': anomaly_logs,
        'human_summary': human_summary,
        'latest_file': latest_file['filename'],
        'recent_alerts': recent_alerts,
        'pie_chart': {'Normal': normal_logs, 'Anomaly': anomaly_logs},
        'bar_chart': bar_chart,
        'timeline_chart': timeline_rows
    }), 200




@app.route('/api/logs/parsed', methods=['GET'])
def get_parsed_logs():
    """Returns paginated and filterable parsed logs for latest analyzed dataset [Protected]."""
    if not is_authenticated(request):
        return jsonify({'status': 'error', 'message': 'Unauthorized. Please login.'}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    file_id = request.args.get('file_id') or get_latest_file_id(cursor)
    if not file_id:
        conn.close()
        return jsonify([]), 200

    search = request.args.get('search', '')
    level = request.args.get('level', '')
    severity = request.args.get('severity', '')
    limit = request.args.get('limit', type=int)

    query = '''
        SELECT p.id, p.timestamp, p.hostname, p.service, p.log_level, p.event_type, p.message,
               p.channel, p.event_id, p.record_id, p.application, p.application_name,
               p.user, p.domain, p.computer, p.action, p.description,
               a.is_anomaly, a.anomaly_score, a.severity, a.consensus_state,
               s.what_happened, s.why_suspicious, s.recommended_action,
               s.top_3_human_reasons, s.risk_assessment, s.what_it_means, s.feature_contributions
        FROM parsed_logs p
        JOIN anomaly_results a ON p.id = a.log_id AND p.file_id = a.file_id
        LEFT JOIN shap_explanations s ON p.id = s.log_id AND p.file_id = s.file_id
        WHERE p.file_id = ?
    '''
    params = [file_id]

    if search:
        query += " AND (p.message LIKE ? OR p.service LIKE ? OR p.hostname LIKE ?)"
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
    if level:
        query += " AND p.log_level = ?"
        params.append(level)
    if severity:
        query += " AND a.severity = ?"
        params.append(severity)

    query += " ORDER BY p.id ASC"
    if limit:
        query += " LIMIT ?"
        params.append(limit)

    cursor.execute(query, params)
    raw_logs = [dict(row) for row in cursor.fetchall()]
    conn.close()

    logs = []
    for r in raw_logs:
        item = dict(r)
        reasons = item.get('top_3_human_reasons')
        if isinstance(reasons, str):
            try:
                item['top_3_human_reasons'] = json.loads(reasons)
            except Exception:
                item['top_3_human_reasons'] = []
        elif not isinstance(reasons, list):
            item['top_3_human_reasons'] = []

        feat_c = item.get('feature_contributions')
        if isinstance(feat_c, str):
            try:
                item['feature_contributions'] = json.loads(feat_c)
            except Exception:
                item['feature_contributions'] = {}
        elif not isinstance(feat_c, dict):
            item['feature_contributions'] = {}

        logs.append(item)

    return jsonify(logs), 200


@app.route('/api/features', methods=['GET'])
def get_extracted_features():
    """Returns 8 behavioral features for latest analyzed dataset [Protected]."""
    if not is_authenticated(request):
        return jsonify({'status': 'error', 'message': 'Unauthorized. Please login.'}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    file_id = request.args.get('file_id') or get_latest_file_id(cursor)
    if not file_id:
        conn.close()
        return jsonify([]), 200

    limit = request.args.get('limit', type=int)
    query = '''
        SELECT f.*, f.failed_login_attempts AS failed_logins, p.service, p.log_level, p.event_type, p.hostname, p.timestamp
        FROM extracted_features f
        JOIN parsed_logs p ON f.log_id = p.id AND f.file_id = p.file_id
        WHERE f.file_id = ?
        ORDER BY f.log_id ASC
    '''
    params = [file_id]
    if limit:
        query += " LIMIT ?"
        params.append(limit)

    cursor.execute(query, params)
    features = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(features), 200


@app.route('/api/detection/results', methods=['GET'])
def get_detection_results():
    """Returns Isolation Forest detection results with human-readable descriptions [Protected]."""
    if not is_authenticated(request):
        return jsonify({'status': 'error', 'message': 'Unauthorized. Please login.'}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    file_id = request.args.get('file_id') or get_latest_file_id(cursor)
    if not file_id:
        conn.close()
        return jsonify([]), 200

    limit = request.args.get('limit', type=int)
    query = '''
        SELECT a.id, a.log_id, a.is_anomaly, a.anomaly_score, a.severity,
               a.consensus_state, a.consensus_agreement, a.is_simulated,
               p.timestamp, p.hostname, p.service, p.message, p.log_level, p.event_type,
               p.simulation_scenario,
               s.what_happened, s.why_suspicious, s.recommended_action, s.top_3_human_reasons
        FROM anomaly_results a
        JOIN parsed_logs p ON a.log_id = p.id AND a.file_id = p.file_id
        LEFT JOIN shap_explanations s ON a.log_id = s.log_id AND a.file_id = s.file_id
        WHERE a.file_id = ?
        ORDER BY a.log_id ASC
    '''
    params = [file_id]
    if limit:
        query += " LIMIT ?"
        params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    results = []
    for r in rows:
        item = dict(r)
        reasons = item.get('top_3_human_reasons')
        if isinstance(reasons, str):
            try:
                item['top_3_human_reasons'] = json.loads(reasons)
            except Exception:
                item['top_3_human_reasons'] = []
        elif not isinstance(reasons, list):
            item['top_3_human_reasons'] = []
        results.append(item)

    return jsonify(results), 200


@app.route('/api/shap/explanations', methods=['GET'])
def get_shap_explanations():
    """Returns SHAP summary plots data and human-readable explanations [Protected]."""
    if not is_authenticated(request):
        return jsonify({'status': 'error', 'message': 'Unauthorized. Please login.'}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    file_id = request.args.get('file_id') or get_latest_file_id(cursor)
    if not file_id:
        conn.close()
        return jsonify([]), 200

    limit = request.args.get('limit', type=int)
    query = '''
        SELECT s.log_id, s.feature_contributions, s.top_reason, s.natural_explanation,
               s.what_happened, s.why_suspicious, s.recommended_action, s.top_3_human_reasons,
               s.application_source, s.what_it_means, s.why_flagged, s.evidence,
               s.risk_assessment, s.limitations_uncertainty, s.technical_details,
               a.is_anomaly, a.anomaly_score, a.severity, p.message, p.service, p.timestamp, p.hostname
        FROM shap_explanations s
        JOIN anomaly_results a ON s.log_id = a.log_id AND s.file_id = a.file_id
        JOIN parsed_logs p ON s.log_id = p.id AND s.file_id = p.file_id
        WHERE s.file_id = ?
        ORDER BY s.log_id ASC
    '''
    params = [file_id]
    if limit:
        query += " LIMIT ?"
        params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    explanations = []
    for r in rows:
        item = dict(r)
        try:
            item['feature_contributions'] = json.loads(item['feature_contributions'])
        except Exception:
            item['feature_contributions'] = {}

        reasons = item.get('top_3_human_reasons')
        if isinstance(reasons, str):
            try:
                item['top_3_human_reasons'] = json.loads(item['top_3_human_reasons'])
            except Exception:
                item['top_3_human_reasons'] = []
        elif not isinstance(reasons, list):
            item['top_3_human_reasons'] = []

        tech = item.get('technical_details')
        if isinstance(tech, str):
            try:
                item['technical_details'] = json.loads(tech)
            except Exception:
                item['technical_details'] = {}

        explanations.append(item)

    return jsonify(explanations), 200


@app.route('/api/model-validation', methods=['GET'])
def get_model_validation():
    """
    Returns Objective 1 & 2 Model Validation & Comparison metrics:
    Feature schema documentation, preprocessing statistics, Isolation Forest vs One-Class SVM results.
    """
    if not is_authenticated(request):
        return jsonify({'status': 'error', 'message': 'Unauthorized. Please login.'}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    file_id = request.args.get('file_id') or get_latest_file_id(cursor)
    if not file_id:
        conn.close()
        return jsonify({
            'status': 'success',
            'message': 'No dataset analyzed yet.',
            'feature_schema': FEATURE_SCHEMA,
            'feature_documentation': FEATURE_DOCUMENTATION
        }), 200

    cursor.execute("SELECT filename FROM uploaded_files WHERE id = ?", (file_id,))
    file_row = cursor.fetchone()
    filename = file_row['filename'] if file_row else 'unknown.log'

    # Retrieve features and parsed logs for latest dataset
    cursor.execute("SELECT * FROM extracted_features WHERE file_id = ? ORDER BY log_id ASC", (file_id,))
    feature_rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    if not feature_rows:
        return jsonify({
            'status': 'error',
            'message': 'No extracted features found for latest file.'
        }), 404

    # Run DataPreprocessor on extracted features
    import pandas as pd
    from ml_engine import DataPreprocessor, IsolationForestDetector, OneClassSVMValidator, FEATURE_DOCUMENTATION, FEATURE_SCHEMA

    feature_df = pd.DataFrame(feature_rows)
    cleaned_feature_df, preprocess_stats = DataPreprocessor.preprocess(feature_df)

    detector = IsolationForestDetector()
    if_results, X_df = detector.predict(cleaned_feature_df)

    ocsvm_validator = OneClassSVMValidator()
    ocsvm_results = ocsvm_validator.predict(cleaned_feature_df)

    comparison = OneClassSVMValidator.compare_models(if_results, ocsvm_results)

    return jsonify({
        'status': 'success',
        'file_id': file_id,
        'filename': filename,
        'total_records': len(cleaned_feature_df),
        'feature_schema': FEATURE_SCHEMA,
        'feature_documentation': FEATURE_DOCUMENTATION,
        'preprocessing_stats': preprocess_stats,
        'primary_model': 'IsolationForest',
        'validation_model': 'OneClassSVM',
        'model_comparison': comparison,
        'shap_compatible': True
    }), 200







@app.route('/api/reports/summary', methods=['GET'])
def get_report_summary():
    """Returns report generation summary metrics [Protected]."""
    if not is_authenticated(request):
        return jsonify({'status': 'error', 'message': 'Unauthorized. Please login.'}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    file_id = request.args.get('file_id') or get_latest_file_id(cursor)
    latest_file = None
    if file_id:
        cursor.execute("SELECT * FROM uploaded_files WHERE id = ?", (file_id,))
        latest_file = cursor.fetchone()

    if not latest_file:
        cursor.execute("SELECT * FROM uploaded_files ORDER BY id DESC LIMIT 1")
        latest_file = cursor.fetchone()

    if not latest_file:
        conn.close()
        return jsonify({'error': 'No log files available.'}), 404

    file_id = latest_file['id']

    cursor.execute("SELECT COUNT(*) as cnt FROM parsed_logs WHERE file_id = ?", (file_id,))
    total_logs = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM anomaly_results WHERE file_id = ? AND is_anomaly = 1", (file_id,))
    anomaly_count = cursor.fetchone()['cnt']
    normal_count = total_logs - anomaly_count

    cursor.execute('''
        SELECT service, COUNT(*) as count
        FROM parsed_logs
        WHERE file_id = ? AND log_level = 'ERROR'
        GROUP BY service ORDER BY count DESC LIMIT 5
    ''', (file_id,))
    top_errors = [dict(row) for row in cursor.fetchall()]

    cursor.execute('''
        SELECT event_type, COUNT(*) as count
        FROM parsed_logs
        WHERE file_id = ?
        GROUP BY event_type ORDER BY count DESC LIMIT 5
    ''', (file_id,))
    top_events = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return jsonify({
        'filename': latest_file['filename'],
        'detection_datetime': latest_file['upload_timestamp'],
        'total_logs': total_logs,
        'normal_count': normal_count,
        'anomaly_count': anomaly_count,
        'top_error_categories': top_errors,
        'top_event_types': top_events
    }), 200


@app.route('/api/model-info', methods=['GET'])
def get_model_info():
    """Returns active Isolation Forest model status and metadata for audit."""
    try:
        from ml_engine import IsolationForestDetector
        detector = IsolationForestDetector()
        model = detector.model
        n_est = len(model.estimators_) if hasattr(model, 'estimators_') else 100
        contam = float(getattr(model, 'contamination', 0.15))
        n_feat = int(getattr(model, 'n_features_in_', len(detector.feature_columns)))
        return jsonify({
            'status': 'success',
            'model_selection': detector.model_selection,
            'model_path': detector.model_path,
            'n_estimators': n_est,
            'contamination': contam,
            'n_features_in': n_feat,
            'feature_schema': detector.feature_columns
        }), 200
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500



# ==============================================================================
# ATTACK SIMULATOR & ANOMALY INJECTION ENDPOINTS
# ==============================================================================

@app.route('/api/test/scenarios', methods=['GET'])
def get_attack_scenarios():
    """Returns catalog of available attack simulator scenarios, metadata, and target signals."""
    scenarios = get_all_scenarios_metadata()
    return jsonify({
        'status': 'success',
        'success': True,
        'count': len(scenarios),
        'scenarios': scenarios
    }), 200


@app.route('/api/test/inject-anomaly', methods=['POST'])
def inject_synthetic_anomaly():
    """
    Executes a deterministic synthetic attack scenario through the genuine ML pipeline.
    Preserves model integrity: does not alter model weights, thresholds, or force scores.
    Persists simulated events to SQLite with is_simulated=1 markers.
    Returns genuine ML detection results alongside separate rule-based assessment.
    """
    data = request.json or {}
    scenario_id = data.get('scenario')

    if not scenario_id or scenario_id not in SCENARIOS_CATALOG:
        supported = list(SCENARIOS_CATALOG.keys())
        return jsonify({
            'status': 'error',
            'success': False,
            'message': f"Invalid or missing scenario identifier '{scenario_id}'. Supported scenarios: {supported}"
        }), 400

    try:
        scenario_meta = SCENARIOS_CATALOG[scenario_id]
        sim_data = generate_synthetic_scenario_logs(scenario_id)
        raw_log_content = sim_data['raw_log_content']
        raw_records = sim_data['raw_records']
        sim_token = sim_data['simulation_token']

        filename = f"Synthetic_Attack_{scenario_id}_{sim_token}.log"

        # Pass through the genuine ML detection and persistence pipeline
        file_id, total_logs, normal_count, anomaly_count = process_and_save_log_file(
            filename=filename,
            content=raw_log_content,
            raw_records=raw_records,
            is_simulated=1,
            simulation_scenario=scenario_id
        )

        # Retrieve the genuine detection and SHAP records created for this file
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT a.id, a.log_id, a.is_anomaly, a.anomaly_score, a.severity,
                   a.consensus_state, a.consensus_agreement, a.is_simulated,
                   p.timestamp, p.hostname, p.service, p.message, p.log_level, p.event_type,
                   p.action, p.description, p.source, p.simulation_scenario,
                   s.what_happened, s.why_suspicious, s.recommended_action, s.top_3_human_reasons,
                   s.feature_contributions
            FROM anomaly_results a
            JOIN parsed_logs p ON a.log_id = p.id AND a.file_id = p.file_id
            LEFT JOIN shap_explanations s ON a.log_id = s.log_id AND a.file_id = s.file_id
            WHERE a.file_id = ?
            ORDER BY a.log_id ASC
        ''', (file_id,))
        rows = cursor.fetchall()

        cursor.execute('''
            SELECT f.event_frequency, f.sequence_length, f.error_count, f.error_pattern,
                   f.login_attempts, f.failed_login_attempts, f.warning_count, f.unknown_events
            FROM extracted_features f
            WHERE f.file_id = ?
            ORDER BY f.log_id ASC
        ''', (file_id,))
        feature_rows = [dict(r) for r in cursor.fetchall()]
        conn.close()

        # Format events and identify attack core events
        events = []
        attack_events_detected = 0
        total_attack_events = sim_data['attack_events_count']

        for idx, r in enumerate(rows):
            item = dict(r)
            reasons = item.get('top_3_human_reasons')
            if isinstance(reasons, str):
                try:
                    item['top_3_human_reasons'] = json.loads(reasons)
                except Exception:
                    item['top_3_human_reasons'] = []
            elif not isinstance(reasons, list):
                item['top_3_human_reasons'] = []

            feat_c = item.get('feature_contributions')
            if isinstance(feat_c, str):
                try:
                    item['feature_contributions'] = json.loads(feat_c)
                except Exception:
                    item['feature_contributions'] = {}
            elif not isinstance(feat_c, dict):
                item['feature_contributions'] = {}

            # Check if this event corresponds to the attack phase (skipping 2 prefix baselines and 1 suffix)
            is_attack_event = (idx >= 2 and idx < len(rows) - 1)
            item['is_attack_phase_event'] = is_attack_event
            if is_attack_event and item.get('is_anomaly') == 1:
                attack_events_detected += 1

            events.append(item)

        # Separate simulation-only rule-based check
        rule_based_eval = evaluate_scenario_rule_based(scenario_id, feature_rows)

        # Genuine ML evaluation summary
        detection_established = bool(attack_events_detected > 0)
        detection_status_label = (
            "Genuine ML Detection"
            if detection_established
            else "Scenario simulated; model detection not established under current model threshold"
        )

        # Find top attack event for summary highlight (highest anomaly score)
        attack_events = [e for e in events if e.get('is_attack_phase_event') and e.get('is_anomaly') == 1]
        if attack_events:
            top_event = max(attack_events, key=lambda e: e.get('anomaly_score', 0.0))
        elif events:
            candidate_events = [e for e in events if e.get('is_attack_phase_event')] or events
            top_event = max(candidate_events, key=lambda e: e.get('anomaly_score', 0.0))
        else:
            top_event = {}

        distinct_consensus = list(dict.fromkeys(e.get('consensus_state', 'evaluated') for e in events if e.get('consensus_state')))

        sim_summary = {
            'scenario_id': scenario_id,
            'scenario_name': scenario_meta.get('name', scenario_id),
            'is_simulated': True,
            'file_id': file_id,
            'events_generated': total_logs,
            'attack_events_count': total_attack_events,
            'attack_events_detected': attack_events_detected,
            'detection_established': detection_established,
            'detection_status_label': detection_status_label,
            'rule_based_evaluation': rule_based_eval,
            'injected_results': events,
            'primary_shap_explanation': {
                'what_happened': top_event.get('what_happened', ''),
                'why_suspicious': top_event.get('why_suspicious', ''),
                'recommended_action': top_event.get('recommended_action', ''),
                'top_3_human_reasons': top_event.get('top_3_human_reasons', []),
                'feature_contributions': top_event.get('feature_contributions', {})
            },
            'detection_summary': {
                'total_analyzed': total_logs,
                'anomalies_detected': anomaly_count,
                'max_anomaly_score': max((e.get('anomaly_score', 0.0) for e in events), default=0.0),
                'consensus_states': distinct_consensus,
                'primary_consensus': (
                    "Consensus Anomaly (Isolation Forest & One-Class SVM agree)" if any(e.get('consensus_state') == 'Consensus Anomaly' for e in events)
                    else "Partial Detection (Isolation Forest flagged anomaly)" if any(e.get('is_anomaly') == 1 for e in events)
                    else "Consensus Normal Baseline"
                )
            }
        }

        return jsonify({
            'status': 'success',
            'success': True,
            'scenario': scenario_meta,
            'simulation': sim_summary,
            'simulation_id': sim_token,
            'file_id': file_id,
            'total_events': total_logs,
            'normal_count': normal_count,
            'anomaly_count': anomaly_count,
            'attack_events_count': total_attack_events,
            'attack_events_detected': attack_events_detected,
            'detection_established': detection_established,
            'detection_status_label': detection_status_label,
            'model_integrity_notice': (
                "Predictions and anomaly scores were computed by unmodified Isolation Forest "
                "and One-Class SVM models. No weights, thresholds, or synthetic labels were forced."
            ),
            'rule_based_assessment': rule_based_eval,
            'events': events,
            'message': (
                f"Successfully simulated '{scenario_meta['name']}' ({total_logs} events ingested). "
                f"ML Model Result: {detection_status_label} ({anomaly_count} flagged anomalies)."
            )
        }), 200
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'success': False,
            'message': f"Simulation execution failed: {str(e)}"
        }), 500


@app.route('/api/logs/paste-analyze', methods=['POST'])
def paste_and_analyze_log():
    """
    Accepts raw server log line(s) pasted by the user, runs them through the full ML pipeline,
    persists the results, and returns genuine anomaly detection scores and SHAP explanations.
    """
    try:
        data = request.json or {}
        raw_content = data.get('log_content', '').strip()
        if not raw_content:
            return jsonify({
                'status': 'error',
                'success': False,
                'message': 'No log content provided. Please paste one or more log lines.'
            }), 400

        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"Pasted_Log_{timestamp_str}.log"
        file_id, total_logs, normal_count, anomaly_count = process_and_save_log_file(
            filename,
            raw_content,
            is_simulated=0,
            simulation_scenario='pasted_user_log'
        )

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT p.*,
                   a.is_anomaly, a.anomaly_score, a.severity,
                   a.consensus_state, a.consensus_agreement,
                   s.what_happened, s.why_suspicious, s.recommended_action,
                   s.top_3_human_reasons, s.feature_contributions
            FROM parsed_logs p
            JOIN anomaly_results a ON p.id = a.log_id AND p.file_id = a.file_id
            LEFT JOIN shap_explanations s ON p.id = s.log_id AND p.file_id = s.file_id
            WHERE p.file_id = ?
            ORDER BY p.id ASC
        ''', (file_id,))
        rows = cursor.fetchall()
        conn.close()

        events = []
        for r in rows:
            item = format_db_row_to_event(r)
            item['consensus_state'] = r['consensus_state'] or ('Consensus Anomaly' if item['is_anomaly'] == 1 else 'Consensus Normal')
            item['consensus_agreement'] = bool(r['consensus_agreement'])
            events.append(item)

        top_event = max(events, key=lambda e: e.get('anomaly_score', 0.0)) if events else {}

        return jsonify({
            'status': 'success',
            'success': True,
            'file_id': file_id,
            'filename': filename,
            'total_events': total_logs,
            'normal_count': normal_count,
            'anomaly_count': anomaly_count,
            'top_event': top_event,
            'events': events,
            'message': f"Successfully analyzed {total_logs} log event(s): {anomaly_count} anomaly, {normal_count} normal."
        }), 200
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'success': False,
            'message': f"Log analysis failed: {str(e)}"
        }), 500


@app.route('/api/test/history', methods=['GET'])
def get_test_history():
    """Returns past simulated attack events stored in SQLite."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT a.id, a.log_id, a.is_anomaly, a.anomaly_score, a.severity,
                   a.consensus_state, a.consensus_agreement, a.is_simulated,
                   p.timestamp, p.hostname, p.service, p.message, p.log_level, p.event_type,
                   p.action, p.description, p.source, p.simulation_scenario,
                   s.what_happened, s.why_suspicious, s.recommended_action, s.top_3_human_reasons,
                   u.filename
            FROM anomaly_results a
            JOIN parsed_logs p ON a.log_id = p.id AND a.file_id = p.file_id
            JOIN uploaded_files u ON a.file_id = u.id
            LEFT JOIN shap_explanations s ON a.log_id = s.log_id AND a.file_id = s.file_id
            WHERE u.is_simulated = 1
            ORDER BY a.id DESC LIMIT 100
        ''')
        rows = cursor.fetchall()
        conn.close()

        events = []
        for r in rows:
            item = dict(r)
            reasons = item.get('top_3_human_reasons')
            if isinstance(reasons, str):
                try:
                    item['top_3_human_reasons'] = json.loads(reasons)
                except Exception:
                    item['top_3_human_reasons'] = []
            elif not isinstance(reasons, list):
                item['top_3_human_reasons'] = []

            item['application'] = 'Smart-Log Attack Simulator'
            item['application_name'] = 'Smart-Log Attack Simulator'
            item['process'] = 'synthetic_attack_simulator'
            item['is_synthetic'] = True
            events.append(item)

        return jsonify({
            'status': 'success',
            'success': True,
            'total': len(events),
            'count': len(events),
            'events': events,
            'history': events
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'success': False, 'message': str(e)}), 500


@app.route('/api/test/cleanup', methods=['POST'])
def cleanup_test_data():
    """
    Deletes all test and simulated file records, logs, features, detections, and explanations.
    Uses positive simulation markers (is_simulated = 1, file_id foreign keys) exclusively.
    Executes within an atomic transaction with automatic rollback on error.
    Real ingested records (is_simulated = 0 or NULL) are strictly protected.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        # 1. Identify simulated uploaded files via positive is_simulated marker
        cursor.execute("SELECT id FROM uploaded_files WHERE is_simulated = 1")
        simulated_file_ids = [row['id'] for row in cursor.fetchall()]

        deleted_counts = {
            'uploaded_files': 0,
            'parsed_logs': 0,
            'extracted_features': 0,
            'anomaly_results': 0,
            'shap_explanations': 0
        }

        # 2. Delete child records in FK-aware dependency order
        # A. SHAP explanations (child of anomaly_results/parsed_logs/uploaded_files)
        if simulated_file_ids:
            placeholders = ','.join('?' for _ in simulated_file_ids)
            cursor.execute(
                f"DELETE FROM shap_explanations WHERE is_simulated = 1 OR file_id IN ({placeholders})",
                simulated_file_ids
            )
        else:
            cursor.execute("DELETE FROM shap_explanations WHERE is_simulated = 1")
        deleted_counts['shap_explanations'] = cursor.rowcount

        # B. Anomaly results
        if simulated_file_ids:
            cursor.execute(
                f"DELETE FROM anomaly_results WHERE is_simulated = 1 OR file_id IN ({placeholders})",
                simulated_file_ids
            )
        else:
            cursor.execute("DELETE FROM anomaly_results WHERE is_simulated = 1")
        deleted_counts['anomaly_results'] = cursor.rowcount

        # C. Extracted features
        if simulated_file_ids:
            cursor.execute(
                f"DELETE FROM extracted_features WHERE file_id IN ({placeholders})",
                simulated_file_ids
            )
            deleted_counts['extracted_features'] = cursor.rowcount

        # D. Parsed logs
        if simulated_file_ids:
            cursor.execute(
                f"DELETE FROM parsed_logs WHERE is_simulated = 1 OR file_id IN ({placeholders})",
                simulated_file_ids
            )
        else:
            cursor.execute("DELETE FROM parsed_logs WHERE is_simulated = 1")
        deleted_counts['parsed_logs'] = cursor.rowcount

        # E. Uploaded files (parent)
        if simulated_file_ids:
            cursor.execute(
                f"DELETE FROM uploaded_files WHERE is_simulated = 1"
            )
            deleted_counts['uploaded_files'] = cursor.rowcount

        # Commit atomic transaction
        conn.commit()

        total_deleted = sum(deleted_counts.values())
        deleted_counts['files'] = deleted_counts['uploaded_files']
        deleted_counts['logs'] = deleted_counts['parsed_logs']
        deleted_counts['total_records'] = total_deleted

        return jsonify({
            'status': 'success',
            'success': True,
            'message': f"Cleaned up {deleted_counts['uploaded_files']} simulation run(s) and {total_deleted} total associated records.",
            'deleted': deleted_counts
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({
            'status': 'error',
            'success': False,
            'message': f"Failed to execute atomic simulation cleanup: {str(e)}"
        }), 500
    finally:
        conn.close()


if __name__ == '__main__':
    init_db()
    seed_sample_data_if_empty()
    port = int(os.environ.get('PORT', 5000))
    print(f"Smart-Log Backend Server starting on port {port}...")
    app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False, threaded=True)

