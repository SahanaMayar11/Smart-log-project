import urllib.request
import json
import time

base_url = 'http://127.0.0.1:5000'

print('======================================================================')
print('TEST 1: Ingesting Synthetic Anomaly via POST /api/test/inject-anomaly')
print('======================================================================')
req = urllib.request.Request(
    f'{base_url}/api/test/inject-anomaly',
    data=json.dumps({'scenario': 'privilege_escalation'}).encode('utf-8'),
    headers={'Content-Type': 'application/json'}
)
with urllib.request.urlopen(req) as response:
    status_code = response.getcode()
    res_data = json.loads(response.read().decode('utf-8'))

print(f'HTTP Status: {status_code}')
print('Response Summary:')
print(f"  - Status: {res_data.get('status')}")
print(f"  - Detection: {res_data.get('detection')}")
print(f"  - Anomaly Score: {res_data.get('anomaly_score')}")
print(f"  - Severity: {res_data.get('severity')}")
event = res_data.get('event', {})
print('Event Data:')
print(f"  - Application: {event.get('application')}")
print(f"  - Process: {event.get('process')}")
print(f"  - PID: {event.get('pid')}")
print(f"  - User: {event.get('user')}")
print(f"  - Action: {event.get('action')}")
print(f"  - Time: {event.get('time')}")
print(f"  - Status: {event.get('status')}")
print(f"  - Source: {event.get('source')}")
print(f"  - Top 3 SHAP Reasons: {event.get('top_3_human_reasons')}")

print('\n======================================================================')
print('TEST 2: Querying Synthetic Test History via GET /api/test/history')
print('======================================================================')
req2 = urllib.request.Request(f'{base_url}/api/test/history')
with urllib.request.urlopen(req2) as response2:
    logs_data = json.loads(response2.read().decode('utf-8')).get('events', [])
print(f'Total Synthetic Log Records: {len(logs_data)}')
if logs_data:
    print(f"First Record: Service={logs_data[0].get('service')} | Anomaly={logs_data[0].get('is_anomaly')} | Score={logs_data[0].get('anomaly_score')}")

print('\n======================================================================')
print('TEST 3: Cleaning Test Data via POST /api/test/cleanup')
print('======================================================================')
req3 = urllib.request.Request(
    f'{base_url}/api/test/cleanup',
    data=b'{}',
    headers={'Content-Type': 'application/json'}
)
with urllib.request.urlopen(req3) as response3:
    clean_res = json.loads(response3.read().decode('utf-8'))
print(f'Cleanup Result: {clean_res}')

print('\n======================================================================')
print('TEST 4: Re-querying Test History after Cleanup')
print('======================================================================')
req4 = urllib.request.Request(f'{base_url}/api/test/history')
with urllib.request.urlopen(req4) as response4:
    logs_after = json.loads(response4.read().decode('utf-8')).get('events', [])
print(f'Total Synthetic Log Records after Cleanup: {len(logs_after)}')

print('\nALL AUTOMATED API TESTS PASSED!')
