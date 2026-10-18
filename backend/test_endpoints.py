import urllib.request
import urllib.error
import json

endpoints = [
    '/api/dashboard/stats',
    '/api/logs/parsed',
    '/api/features',
    '/api/detection/results',
    '/api/shap/explanations',
    '/api/model-validation',
    '/api/reports/summary',
    '/api/email/config',
    '/api/model-info',
    '/api/system-logs/historical',
    '/api/system-logs/live',
    '/api/system-logs/monitor/status',
    '/api/system-logs/diagnostics',
    '/api/test/history'
]

print("Scanning all GET endpoints on http://127.0.0.1:5000 ...")
for ep in endpoints:
    url = f"http://127.0.0.1:5000{ep}"
    try:
        req = urllib.request.urlopen(url)
        print(f"  [OK 200] {ep}")
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore')
        print(f"  [HTTP {e.code}] {ep} -> {body}")
    except Exception as e:
        print(f"  [FAIL] {ep} -> {e}")

# Test POST endpoints
post_endpoints = [
    ('/api/auth/login', {'username': 'admin', 'password': 'password'}),
    ('/api/system-logs/analyze', {'sample_size': 10}),
    ('/api/test/inject-anomaly', {'scenario': 'ssh_bruteforce', 'count': 3})
]

print("\nScanning common POST endpoints ...")
for ep, payload in post_endpoints:
    url = f"http://127.0.0.1:5000{ep}"
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'}, method='POST')
        resp = urllib.request.urlopen(req)
        print(f"  [OK {resp.status}] POST {ep}")
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore')
        print(f"  [HTTP {e.code}] POST {ep} -> {body}")
    except Exception as e:
        print(f"  [FAIL] POST {ep} -> {e}")
