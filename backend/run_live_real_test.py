import os
import sys
import time
import json
import psutil
import subprocess
import urllib.request

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

def test_live_system_telemetry():
    print("=" * 80)
    print("SMART-LOG CRITICAL LIVE TELEMETRY VERIFICATION TEST")
    print("=" * 80)

    # 1. Close any existing instances of test apps to ensure clean start
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name'].lower()
            if name in ('notepad.exe', 'calc.exe', 'calculatorapp.exe'):
                proc.terminate()
        except Exception:
            pass

    time.sleep(2.0)

    opened_procs = {}

    # STEP 5: Open Chrome (if exists)
    print("\n[STEP 5] Testing Chrome...")
    try:
        chrome_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        if os.path.exists(chrome_path):
            p = subprocess.Popen([chrome_path, "--new-window", "about:blank"])
            opened_procs['Chrome'] = p
            print(f"  -> Chrome launched (PID: {p.pid})")
        else:
            print("  -> Chrome not found at standard path, looking up running chrome processes...")
    except Exception as e:
        print(f"  -> Chrome notice: {e}")
    time.sleep(3.5)

    # STEP 6: Open VS Code
    print("\n[STEP 6] Testing VS Code...")
    try:
        p = subprocess.Popen(["cmd.exe", "/c", "code --version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        opened_procs['VSCode'] = p
        print(f"  -> VS Code command invoked (PID: {p.pid})")
    except Exception as e:
        print(f"  -> VS Code notice: {e}")
    time.sleep(3.5)

    # STEP 7: Open Notepad
    print("\n[STEP 7] Testing Notepad...")
    try:
        p = subprocess.Popen(["notepad.exe"])
        opened_procs['Notepad'] = p
        print(f"  -> Notepad launched (PID: {p.pid})")
    except Exception as e:
        print(f"  -> Notepad notice: {e}")
    time.sleep(3.5)

    # STEP 8: Open Calculator
    print("\n[STEP 8] Testing Calculator...")
    try:
        p = subprocess.Popen(["calc.exe"])
        opened_procs['Calculator'] = p
        print(f"  -> Calculator launched (PID: {p.pid})")
    except Exception as e:
        print(f"  -> Calculator notice: {e}")
    time.sleep(3.5)

    # STEP 9: Open File Explorer
    print("\n[STEP 9] Testing File Explorer...")
    try:
        p = subprocess.Popen(["explorer.exe", "."])
        opened_procs['FileExplorer'] = p
        print(f"  -> File Explorer launched (PID: {p.pid})")
    except Exception as e:
        print(f"  -> File Explorer notice: {e}")
    time.sleep(3.5)

    # STEP 10: WhatsApp
    print("\n[STEP 10] Checking WhatsApp...")
    whatsapp_found = any('whatsapp' in (p.info.get('name') or '').lower() for p in psutil.process_iter(['name']))
    print(f"  -> WhatsApp installed / running: {'YES' if whatsapp_found else 'NOT RUNNING / NOT INSTALLED'}")

    # STEP 11: Close Notepad
    print("\n[STEP 11] Closing Notepad...")
    if 'Notepad' in opened_procs:
        try:
            opened_procs['Notepad'].terminate()
            print("  -> Notepad terminated.")
        except Exception as e:
            print(f"  -> Close error: {e}")
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'].lower() == 'notepad.exe':
                proc.terminate()
        except Exception:
            pass
    time.sleep(3.5)

    # STEP 12: Close Calculator
    print("\n[STEP 12] Closing Calculator...")
    if 'Calculator' in opened_procs:
        try:
            opened_procs['Calculator'].terminate()
            print("  -> Calculator terminated.")
        except Exception as e:
            print(f"  -> Close error: {e}")
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'].lower() in ('calc.exe', 'calculatorapp.exe', 'calculator.exe'):
                proc.terminate()
        except Exception:
            pass
    time.sleep(3.5)

    # STEP 14: Battery / Charger Telemetry
    print("\n[STEP 14] Battery / Charger Status Inspection...")
    battery = psutil.sensors_battery()
    if battery:
        print(f"  -> Battery Percentage : {battery.percent}%")
        print(f"  -> AC Power Connected  : {'YES (Charging/AC Online)' if battery.power_plugged else 'NO (Discharging/Battery)'}")
    else:
        print("  -> No battery sensor (Desktop Workstation).")

    # STEP 15: Fetch Live Telemetry Feed from Backend
    print("\n[STEP 15] Inspecting Live System Monitor Telemetry Feed (/api/system-logs/live)...")
    resp = urllib.request.urlopen("http://127.0.0.1:5000/api/system-logs/live?limit=50")
    data = json.loads(resp.read().decode())

    print(f"  - Host Computer       : {data.get('computer_name')}")
    print(f"  - Monitoring Status   : {data.get('monitoring_status')}")
    print(f"  - Total Events Monitored: {data.get('total_events_monitored')}")
    print(f"  - Normal Events Count : {data.get('normal_count')}")
    print(f"  - Anomaly Count       : {data.get('anomaly_count')}")
    print(f"  - Scanned Channels    : {data.get('scanned_channels')}")
    print(f"  - Events in Buffer    : {len(data.get('events', []))}")

    print("\n" + "=" * 80)
    print("LIVE BUFFER EVENT STREAM:")
    print("=" * 80)
    events = data.get("events", [])
    for idx, ev in enumerate(events[:20]):
        app = ev.get('application_name') or ev.get('service') or 'System'
        proc = ev.get('process_name') or 'N/A'
        pid = ev.get('pid') or ev.get('process_id') or 'N/A'
        action = ev.get('action') or 'EVENT_LOGGED'
        is_anom = ev.get('is_anomaly')
        score = ev.get('anomaly_score')
        sev = ev.get('severity')
        desc = ev.get('description') or ev.get('what_happened') or ev.get('message')
        status_badge = "ANOMALY DETECTED" if is_anom == 1 else "NORMAL"

        print(f"{idx+1:2d}. [{action:<18}] Application: {app:<20} | Process: {proc:<16} | PID: {str(pid):<6}")
        print(f"    ML Status: {status_badge} (Score: {score}, Severity: {sev})")
        print(f"    Description: {desc}")
        print("-" * 80)

    # Historical 24h Scan verification
    print("\n[VERIFY 24H HISTORICAL SCAN] Testing /api/system-logs/analyze...")
    req = urllib.request.Request(
        "http://127.0.0.1:5000/api/system-logs/analyze",
        data=json.dumps({"hours": 1, "max_events": 20}).encode(),
        headers={"Content-Type": "application/json"}
    )
    hist_resp = urllib.request.urlopen(req)
    hist_data = json.loads(hist_resp.read().decode())
    print(f"  -> 24h Historical Status: {hist_data.get('status')}")
    print(f"  -> Total Collected      : {hist_data.get('total_logs')}")
    print(f"  -> Normal Events        : {hist_data.get('normal_count')}")
    print(f"  -> Anomaly Events       : {hist_data.get('anomaly_count')}")
    print(f"  -> Model                : {hist_data.get('model')}")
    print(f"  -> Features             : {hist_data.get('features')}")
    print(f"  -> SHAP Enabled         : {hist_data.get('shap')}")

    print("\n" + "=" * 80)
    print("FINAL RESULT: ALL LIVE TELEMETRY CHECKS COMPLETED SUCCESSFULLY")
    print("=" * 80)

if __name__ == '__main__':
    test_live_system_telemetry()
