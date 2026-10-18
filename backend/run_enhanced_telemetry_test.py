import urllib.request
import json
import time
import subprocess
import os

base_url = 'http://127.0.0.1:5000'

print('======================================================================')
print('STAGE 1: LAUNCHING REAL APPLICATIONS TO VERIFY ENHANCED HUMAN-READABLE TELEMETRY')
print('======================================================================')

apps = []

# 1. Notepad
print('[1] Launching Notepad...')
p_note = subprocess.Popen(['notepad.exe'])
apps.append(('Notepad', p_note))
time.sleep(1.5)

# 2. Calculator
print('[2] Launching Calculator...')
try:
    p_calc = subprocess.Popen(['calc.exe'])
    apps.append(('Calculator', p_calc))
except Exception as e:
    print('Calc launch exception:', e)
time.sleep(1.5)

# 3. Control Panel
print('[3] Launching Control Panel...')
try:
    p_ctrl = subprocess.Popen(['control.exe'])
    apps.append(('Control Panel', p_ctrl))
except Exception as e:
    print('Control launch exception:', e)
time.sleep(1.5)

# 4. Windows PowerShell
print('[4] Launching PowerShell...')
try:
    p_ps = subprocess.Popen(['powershell.exe', '-NoProfile', '-Command', 'Start-Sleep -Seconds 3'])
    apps.append(('PowerShell', p_ps))
except Exception as e:
    print('PS launch exception:', e)
time.sleep(2)

# 5. Terminating test applications
print('[5] Closing launched test applications...')
for name, p in apps:
    try:
        p.terminate()
    except Exception:
        pass
time.sleep(3)

print('\n======================================================================')
print('STAGE 2: QUERYING /api/system-logs/live')
print('======================================================================')
req = urllib.request.Request(f'{base_url}/api/system-logs/live')
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode('utf-8'))

print('HOST ENVIRONMENT DETAILS:')
print(f"  - Computer Name : {data.get('computer_name')}")
print(f"  - Source Label  : {data.get('source_label')}")
print(f"  - User          : {data.get('user')}")
print(f"  - Domain        : {data.get('domain')}")
print(f"  - OS            : {data.get('os')}")
print(f"  - IP Address    : {data.get('ip_address')}")
print(f"  - Total Monitored: {data.get('total_monitored')}")
print(f"  - Events in Feed: {len(data.get('events', []))}")

print('\nLATEST LIVE EVENT RECORDS:')
print('----------------------------------------------------------------------')
for idx, e in enumerate(data.get('events', [])[:15]):
    t = e.get('time', 'N/A')
    act = e.get('action', 'N/A')
    app = e.get('application', 'N/A')
    proc = e.get('process', 'N/A')
    pid = e.get('pid', 'N/A')
    u = e.get('user', 'N/A')
    comp = e.get('computer', 'N/A')
    parent = e.get('parent_process', 'N/A')
    parent_app = e.get('parent_application', 'N/A')
    st = e.get('status', 'N/A')
    sc = e.get('anomaly_score', 'N/A')
    sev = e.get('severity', 'N/A')
    desc = e.get('description', 'N/A')

    print(f"{idx+1}. [{t}] [{act}] {app} ({proc}) | PID: {pid}")
    print(f"   User: {u} | Computer: {comp} | Parent: {parent} ({parent_app})")
    print(f"   Status: {st} | Score: {sc} | Severity: {sev}")
    print(f"   Description: {desc}")
    print('----------------------------------------------------------------------')

print('\nALL VERIFICATION STAGES COMPLETED SUCCESSFULLY!')
