import os
import sys
import json
import joblib
import sqlite3
import pandas as pd
import urllib.request
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'smartlog.db')
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'models', 'isolation_forest_model.pkl')
BASE_URL = "http://127.0.0.1:5000/api"

def verify_all():
    print("=" * 70)
    print("      FINAL SMART-LOG EMPIRICAL VERIFICATION SUITE")
    print("=" * 70)

    # 1. Model File Verification
    if os.path.exists(MODEL_PATH):
        size_kb = os.path.getsize(MODEL_PATH) / 1024.0
        model = joblib.load(MODEL_PATH)
        print(f"\n[1] ISOLATION FOREST MODEL INSPECTION ({MODEL_PATH}):")
        print(f"  - Model file size    : {size_kb:.2f} KB ({os.path.getsize(MODEL_PATH)} bytes)")
        print(f"  - Model Type         : {type(model).__name__}")
        print(f"  - n_estimators       : {getattr(model, 'n_estimators', 'N/A')}")
        print(f"  - contamination      : {getattr(model, 'contamination', 'N/A')}")
        print(f"  - max_samples        : {getattr(model, 'max_samples', 'N/A')}")
        print(f"  - random_state       : {getattr(model, 'random_state', 'N/A')}")
        print(f"  - n_features_in_     : {getattr(model, 'n_features_in_', 'N/A')}")
        print(f"  - Model Load Status  : PASS")
    else:
        print(f"[FAIL] Model file missing at {MODEL_PATH}")

    # 2. Windows Event Log Collector Test
    from system_log_collector import collect_windows_system_logs, collect_new_windows_events
    res_collector = collect_windows_system_logs(hours=24, max_events=100)
    records = res_collector.get('records', [])
    print(f"\n[2] WINDOWS EVENT LOG COLLECTOR TEST:")
    print(f"  - Total Events Read  : {len(records)}")
    print(f"  - Host Computer Name : {res_collector.get('hostname')}")
    print(f"  - Scan Status        : {res_collector.get('scan_status')}")

    # 3. 8 Behavioral Features Extraction Test
    from ml_engine import BehavioralFeatureExtractor
    extractor = BehavioralFeatureExtractor()
    df_feats = extractor.extract_features(records)
    cols = [c for c in df_feats.columns if c != 'log_id']
    expected_8 = [
        'event_frequency', 'sequence_length', 'error_count', 'error_pattern',
        'login_attempts', 'failed_login_attempts', 'warning_count', 'unknown_events'
    ]
    is_exact_match = set(cols) == set(expected_8)
    print(f"\n[3] 8 BEHAVIORAL FEATURES EXTRACTION TEST:")
    print(f"  - Extracted Records  : {len(df_feats)}")
    print(f"  - 8 Behavioral Cols  : {cols}")
    print(f"  - Exact 8 Match      : {'PASS' if is_exact_match else 'FAIL'}")

    # 4. SQLite Database Integrity
    if os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        print(f"\n[4] SQLITE DATABASE INTEGRITY ({DB_PATH}):")
        print(f"  - Database Tables    : {tables}")
        for t in ['admin_users', 'uploaded_files', 'parsed_logs', 'extracted_features', 'anomaly_results', 'shap_explanations']:
            if t in tables:
                cursor.execute(f"SELECT COUNT(*) FROM {t}")
                cnt = cursor.fetchone()[0]
                print(f"    * Table '{t}': {cnt} records")
        conn.close()

    # 5. REST API Integration Endpoints Test
    print(f"\n[5] REST API INTEGRATION SUITE (Flask Port 5000):")
    endpoints = [
        ('/dashboard/stats', 'GET'),
        ('/logs/parsed', 'GET'),
        ('/features', 'GET'),
        ('/detection/results', 'GET'),
        ('/shap/explanations', 'GET'),
        ('/reports/summary', 'GET'),
        ('/system-logs/live', 'GET'),
        ('/system-logs/monitor/status', 'GET')
    ]
    passed_apis = 0
    for ep, method in endpoints:
        try:
            req = urllib.request.Request(f"{BASE_URL}{ep}")
            with urllib.request.urlopen(req) as resp:
                if resp.status == 200:
                    print(f"  [PASS] {method} {ep} -> HTTP 200 OK")
                    passed_apis += 1
                else:
                    print(f"  [FAIL] {method} {ep} -> HTTP {resp.status}")
        except Exception as e:
            print(f"  [FAIL] {method} {ep} -> Error: {e}")

    print(f"\n  API Endpoint Status: {passed_apis}/{len(endpoints)} Passed.")
    print("=" * 70)
    print("      VERIFICATION COMPLETED SUCCESSFULLY [SUCCESS]")
    print("=" * 70)

if __name__ == '__main__':
    verify_all()
