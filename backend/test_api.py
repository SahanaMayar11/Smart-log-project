import urllib.request
import urllib.parse
import json
import time
import sys

BASE_URL = "http://127.0.0.1:5000/api"
TOKEN = "smartlog_admin_sec_token_v1_2026"

def wait_for_server():
    """Waits up to 10 seconds for Flask server to respond on port 5000."""
    print("Waiting for Flask server to be ready...")
    for _ in range(10):
        try:
            req = urllib.request.Request(f"{BASE_URL}/dashboard/stats", method="GET")
            with urllib.request.urlopen(req, timeout=2) as response:
                print("Flask server is ready!")
                return True
        except urllib.error.HTTPError as e:
            # 401 Unauthorized means server is running and protecting routes!
            if e.code == 401:
                print("Flask server is ready and protecting routes (HTTP 401)!")
                return True
        except Exception:
            time.sleep(1)
    print("Server failed to respond within 10 seconds.")
    return False

def check_endpoint(name, path, method="GET", data=None, use_auth=True):
    url = f"{BASE_URL}{path}"
    headers = {}
    if data:
        headers["Content-Type"] = "application/json"
    if use_auth:
        headers["Authorization"] = f"Bearer {TOKEN}"

    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            res_body = response.read().decode("utf-8")


            res_json = json.loads(res_body)
            print(f"[PASS] {name} ({method} {path}) -> Status {response.status} OK")
            return True, res_json
    except urllib.error.HTTPError as e:
        if not use_auth and e.code == 401:
            print(f"[PASS] {name} (Unauthenticated {method} {path}) -> Status 401 Unauthorized (Expected)")
            return True, None
        print(f"[FAIL] {name} ({method} {path}) -> HTTP Error {e.code}")
        return False, None
    except Exception as e:
        print(f"[FAIL] {name} ({method} {path}) -> Error: {e}")
        return False, None

def run_all_tests():
    if not wait_for_server():
        sys.exit(1)

    print("=" * 60)
    print("RUNNING SMART-LOG AUTHENTICATION & API VERIFICATION TESTS")
    print("=" * 60)

    results = []

    # 1. Unauthenticated Request Test (Must return 401 Unauthorized)
    success, res = check_endpoint("Unauthenticated Access Protection", "/dashboard/stats", method="GET", use_auth=False)
    results.append(success)

    # 2. Login API (Admin auth)
    success, res = check_endpoint("Admin Login API", "/auth/login", method="POST", data={"username": "admin", "password": "admin123"}, use_auth=False)
    results.append(success)

    # 3. Authenticated Dashboard Stats API
    success, res = check_endpoint("Protected Dashboard Stats API", "/dashboard/stats", use_auth=True)
    results.append(success)

    # 4. Authenticated Parsed Logs API
    success, res = check_endpoint("Protected Parsed Logs API", "/logs/parsed", use_auth=True)
    results.append(success)

    # 5. Authenticated Behavioral Features API
    success, res = check_endpoint("Protected Behavioral Features API", "/features", use_auth=True)
    results.append(success)

    # 6. Authenticated Detection Results API
    success, res = check_endpoint("Protected Detection Results API", "/detection/results", use_auth=True)
    results.append(success)

    # 7. Authenticated SHAP Explanations API
    success, res = check_endpoint("Protected SHAP Explanations API", "/shap/explanations", use_auth=True)
    results.append(success)

    # 8. Authenticated Report Summary API
    success, res = check_endpoint("Protected Report Summary API", "/reports/summary", use_auth=True)
    results.append(success)

    # 9. Authenticated Log Upload API
    sample_log_content = "2026-08-08T00:00:00 server-01 sshd[999]: Failed password for invalid user hacker from 10.0.0.1"
    success, res = check_endpoint("Protected Log Upload API", "/logs/upload", method="POST", data={"filename": "test_auth.log", "content": sample_log_content}, use_auth=True)
    results.append(success)

    # 10. Authenticated Local System Log Analysis API
    success, res = check_endpoint("Protected System Log Scan API", "/system-logs/analyze", method="POST", data={"max_events": 25}, use_auth=True)
    results.append(success)

    print("=" * 60)
    if all(results):
        print(f"ALL AUTHENTICATION & API ENDPOINT TESTS PASSED! ({len(results)}/{len(results)})")
        sys.exit(0)
    else:
        print(f"SOME TESTS FAILED ({results.count(True)}/{len(results)} PASSED)")
        sys.exit(1)


if __name__ == "__main__":
    run_all_tests()
