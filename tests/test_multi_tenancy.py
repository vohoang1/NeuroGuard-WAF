import os
import time
import requests

API_URL = "http://localhost:8081"
API_AUTH_URL = f"{API_URL}/api/login"
ENVOY_URL = "http://localhost:8080" # Assuming Envoy listens on 8080

def print_result(msg, ok):
    color = "\033[92m" if ok else "\033[91m"
    print(f"{color}[{'PASS' if ok else 'FAIL'}] {msg}\033[0m")

def test_rbac_viewer():
    print("--- Testing RBAC (Viewer Role) ---")
    res = requests.post(API_AUTH_URL, json={"username": "viewer", "password": "admin123"})
    if res.status_code != 200:
        print_result("Viewer login failed", False)
        return False
    
    token = res.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Try to write settings
    res = requests.post(f"{API_URL}/api/settings", json={"threshold": 10}, headers=headers)
    print_result(f"Viewer POST /settings -> Status {res.status_code}", res.status_code == 403)

def test_tenant_isolation():
    print("\n--- Testing Tenant Data Isolation (Row-Level Security) ---")
    
    # Login
    t1_res = requests.post(API_AUTH_URL, json={"username": "admin", "password": "admin123"})
    t1_token = t1_res.json()["token"]
    t1_id = t1_res.json()["tenant_id"]

    t2_res = requests.post(API_AUTH_URL, json={"username": "cyberadmin", "password": "admin123"})
    t2_token = t2_res.json()["token"]
    t2_id = t2_res.json()["tenant_id"]

    t1_headers = {"Authorization": f"Bearer {t1_token}"}
    t2_headers = {"Authorization": f"Bearer {t2_token}"}

    print(f"Tenant 1 ID: {t1_id}")
    print(f"Tenant 2 ID: {t2_id}")

    # Generate WAF Logs by hitting Envoy
    requests.get(f"{ENVOY_URL}/health?cmd=cat /etc/passwd", headers={"X-Tenant-ID": t1_id})
    requests.get(f"{ENVOY_URL}/health?query=DROP TABLE users", headers={"X-Tenant-ID": t2_id})
    
    print("Waiting 3 seconds for WAF to asynchronously log to ClickHouse...")
    time.sleep(3)
    
    t1_logs = requests.get(f"{API_URL}/api/logs", headers=t1_headers).json()
    t2_logs = requests.get(f"{API_URL}/api/logs", headers=t2_headers).json()

    print(f"Tenant 1 logs found: {len(t1_logs)}")
    print(f"Tenant 2 logs found: {len(t2_logs)}")

    t1_isolation_ok = all(log["tenant_id"] == t1_id for log in t1_logs) if t1_logs else False
    t2_isolation_ok = all(log["tenant_id"] == t2_id for log in t2_logs) if t2_logs else False
    
    t1_saw_t2 = any("DROP TABLE" in log["uri"] for log in t1_logs)
    t2_saw_t1 = any("cat /etc/passwd" in log["uri"] for log in t2_logs)

    print_result("Tenant 1 only sees Tenant 1 logs", t1_isolation_ok and not t1_saw_t2)
    print_result("Tenant 2 only sees Tenant 2 logs", t2_isolation_ok and not t2_saw_t1)

if __name__ == "__main__":
    test_rbac_viewer()
    test_tenant_isolation()
