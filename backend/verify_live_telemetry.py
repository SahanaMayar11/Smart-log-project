import os
import sys
import time
import json
import subprocess
import urllib.request

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

def run_test():
    print("=" * 80)
    print("SMART-LOG REAL WINDOWS TELEMETRY LIVE VERIFICATION")
    print("=" * 80)

    # 1. Start Notepad
    print("\n[STEP 1] Launching Notepad...")
    np_proc = subprocess.Popen(["notepad.exe"])
    print(f"  -> Notepad launched with PID: {np_proc.pid}")
    time.sleep(3.5)

    # 2. Start Calculator
    print("\n[STEP 2] Launching Calculator...")
    try:
        calc_proc = subprocess.Popen(["calc.exe"])
        print(f"  -> Calculator launched with PID: {calc_proc.pid}")
    except Exception as e:
        print(f"  -> Calculator launch notice: {e}")
        calc_proc = None
    time.sleep(3.5)

    # 3. Close Notepad
    print("\n[STEP 3] Closing Notepad...")
    try:
        np_proc.terminate()
        print("  -> Notepad terminated.")
    except Exception as e:
        print(f"  -> Notepad close notice: {e}")
    time.sleep(3.5)

    # 4. Close Calculator if possible
    if calc_proc:
        print("\n[STEP 4] Closing Calculator...")
        try:
            calc_proc.terminate()
            print("  -> Calculator terminated.")
        except Exception:
            pass
    time.sleep(3.5)

    # 5. Query /api/system-logs/live
    print("\n[STEP 5] Querying Smart-Log Live API (http://127.0.0.1:5000/api/system-logs/live)...")
    try:
        resp = urllib.request.urlopen("http://127.0.0.1:5000/api/system-logs/live?limit=30")
        data = json.loads(resp.read().decode())
        print(f"  - Monitoring Status  : {data.get('monitoring_status')}")
        print(f"  - Total Monitored    : {data.get('total_events_monitored')}")
        print(f"  - Normal Events      : {data.get('normal_count')}")
        print(f"  - Anomaly Events     : {data.get('anomaly_count')}")
        print(f"  - Scanned Channels   : {data.get('scanned_channels')}")
        print(f"  - Live Buffer Size   : {len(data.get('events', []))}")

        print("\n" + "=" * 80)
        print("REAL TELEMETRY EVENTS IN LIVE BUFFER (Newest First):")
        print("=" * 80)
        events = data.get("events", [])
        for i, ev in enumerate(events[:15]):
            app = ev.get('application_name') or ev.get('service')
            proc = ev.get('process_name') or 'N/A'
            pid = ev.get('pid') or ev.get('process_id') or 'N/A'
            action = ev.get('action') or 'EVENT_LOGGED'
            is_anom = ev.get('is_anomaly')
            score = ev.get('anomaly_score')
            sev = ev.get('severity')
            desc = ev.get('description') or ev.get('what_happened') or ev.get('message')
            status_str = "ANOMALY DETECTED" if is_anom == 1 else "NORMAL"

            print(f"{i+1:2d}. [{action:<18}] App: {app:<18} | Proc: {proc:<15} | PID: {str(pid):<6} | ML: {status_str:<16} (Score: {score}, {sev})")
            print(f"    Description: {desc}")
            print("-" * 80)

    except Exception as ex:
        print(f"API Query failed: {ex}")

if __name__ == '__main__':
    run_test()
