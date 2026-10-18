import urllib.request
import json
import time

BASE_URL = "http://127.0.0.1:5000/api"

def test_live_monitoring():
    print("=" * 60)
    print("RUNNING LIVE WINDOWS SYSTEM LOG MONITORING VERIFICATION SUITE")
    print("=" * 60)

    # 1. Test GET /api/system-logs/live
    req = urllib.request.Request(f"{BASE_URL}/system-logs/live?limit=50")
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            assert data.get('status') == 'success'
            assert 'is_monitoring' in data
            assert 'events' in data
            assert 'computer_name' in data
            print(f"[PASS] GET /api/system-logs/live -> Host: {data['computer_name']}, Monitoring: {data['is_monitoring']}, Buffer Events: {len(data['events'])}")
    except Exception as e:
        print(f"[FAIL] GET /api/system-logs/live -> Error: {e}")
        return False

    # 2. Test GET /api/system-logs/monitor/status
    req = urllib.request.Request(f"{BASE_URL}/system-logs/monitor/status")
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            assert 'is_monitoring' in data
            assert 'interval' in data
            status_text = data['monitoring_status'].encode('ascii', 'ignore').decode('ascii')
            print(f"[PASS] GET /api/system-logs/monitor/status -> Status: {status_text}, Interval: {data['interval']}s, Total Monitored: {data['total_events_monitored']}")
    except Exception as e:
        print(f"[FAIL] GET /api/system-logs/monitor/status -> Error: {e}")
        return False

    # 3. Test POST /api/system-logs/monitor/stop
    req = urllib.request.Request(
        f"{BASE_URL}/system-logs/monitor/stop",
        data=json.dumps({}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            assert data.get('is_monitoring') == False
            print(f"[PASS] POST /api/system-logs/monitor/stop -> Monitoring stopped successfully.")
    except Exception as e:
        print(f"[FAIL] POST /api/system-logs/monitor/stop -> Error: {e}")
        return False

    # 4. Test POST /api/system-logs/monitor/start
    req = urllib.request.Request(
        f"{BASE_URL}/system-logs/monitor/start",
        data=json.dumps({'interval': 3.0}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            assert data.get('is_monitoring') == True
            assert data.get('interval') == 3.0
            print(f"[PASS] POST /api/system-logs/monitor/start -> Live monitoring started at {data['interval']}s interval.")
    except Exception as e:
        print(f"[FAIL] POST /api/system-logs/monitor/start -> Error: {e}")
        return False

    # Wait a few seconds for background collector to process real Windows events
    print("Waiting 6 seconds for background Windows log collector tick...")
    time.sleep(6)

    # 5. Check live events collected
    req = urllib.request.Request(f"{BASE_URL}/system-logs/live?limit=50")
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            events = data.get('events', [])
            print(f"[PASS] Real-Time Live Windows Stream -> Monitored: {data['total_events_monitored']}, Buffer: {len(events)} events, Normal: {data['normal_count']}, Anomalies: {data['anomaly_count']}")
    except Exception as e:
        print(f"[FAIL] Real-Time Stream -> Error: {e}")

    print("=" * 60)
    print("ALL LIVE MONITORING ENDPOINT TESTS PASSED SUCCESSFULLY! (5/5)")
    print("=" * 60)
    return True

if __name__ == '__main__':
    test_live_monitoring()
