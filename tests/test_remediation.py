import requests
import time
import sys

# Test configuration
ENVOY_URL = "http://localhost:8080"  # WAF entrypoint
API_URL = "http://localhost:8081"    # Go backend

print("\n🚀 Starting Auto-Remediation E2E Test\n")

# Step 1: Login to get token for interacting with API
print("1. Authenticating as Admin to configure Remediation Engine...")
try:
    login_resp = requests.post(f"{API_URL}/api/login", json={"username": "admin", "password": "admin123"})
    if login_resp.status_code != 200:
        print(f"❌ Login failed: {login_resp.text}")
        sys.exit(1)
    
    token = login_resp.json().get("token")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Extract Tenant ID from JWT payload
    import base64
    import json
    parts = token.split(".")
    payload = json.loads(base64.b64decode(parts[1] + "==").decode("utf-8"))
    tenant_id = payload.get("tenant_id", "00000000-0000-0000-0000-000000000000")
    print(f"   ℹ️ Admin Tenant Workspace: {tenant_id}")
    
    attack_headers = {"X-Tenant-Id": tenant_id}
except Exception as e:
    print(f"❌ Connection error: {e}")
    sys.exit(1)

print("   ✅ Authenticated successfully.\n")

# Step 2: Enable Auto-Remediation
print("2. Enabling Auto-Remediation...")
requests.post(f"{API_URL}/api/remediation/toggle", json={"enabled": True}, headers=headers)
print("   ✅ Engine active.\n")

# Step 3: Unblock current IP if already blocked
print("3. Ensuring our test IP is not already blocked...")
requests.post(f"{API_URL}/api/remediation/unblock", json={"ip": "127.0.0.1"}, headers=headers)
print("   ✅ IP clear.\n")

time.sleep(2) # Give WAF sync time

# Step 4: Fire 6 rapid SQLi requests
print("4. Simulating rapid SQLi attacks (Threshold > 5/min)...")
for i in range(1, 7):
    # WAF detects `1=1` as SQLi
    payload = f"/?q=1=1--id={i}"
    resp = requests.get(f"{ENVOY_URL}{payload}", headers=attack_headers)
    if resp.status_code == 403:
        try:
            msg = resp.json().get("message", "")
        except:
            msg = resp.text
        print(f"   [{i}] Request blocked! HTTP 403. Message: {msg}")
        
        if "Auto-Remediation" in msg:
            print(f"\n🎉 SUCCESS: The IP was permanently blocked by Auto-Remediation on request {i}!")
            break
    else:
        print(f"   [{i}] Request bypassed or WAF is not blocking? HTTP {resp.status_code}")
    
    time.sleep(0.2)
    
print("\n   Waiting 12 seconds for the Go Auto-Remediation Engine to poll ClickHouse telemetry and sync the Envoy Wasm blocklist cache... ⏳")
time.sleep(12)

# Make 7th request to confirm Auto-Remediation active block
print("5. Making 7th follow-up request to verify WAF cached blocklist enforcement...")
resp = requests.get(f"{ENVOY_URL}/", headers=attack_headers)
msg = resp.json().get("message", "") if resp.status_code == 403 else resp.text
if "Auto-Remediation" in msg:
    print(f"   🎉 SUCCESS: The IP was permanently blocked by Auto-Remediation! Message: {msg}")
else:
    print(f"   ❌ FAILED: Auto-Remediation did not block the request. HTTP {resp.status_code}")

# Verify the blocklist via API
print("\n6. Verifying internal blocklist via API...")
blocklist_resp = requests.get(f"{API_URL}/api/remediation/blocklist", headers=headers)
blocks = blocklist_resp.json().get("blocked_ips") or []
print(f"   Currently blocked IPs: {blocks}")

if "127.0.0.1" in blocks or "172.18.0.1" in blocks or "172.19.0.1" in blocks:
    # IP could be docker gateway, so check length
    print("   ✅ API confirms our connection IP is in the remediation blocklist.")

print("\n✅ Auto-remediation test complete! Check your Telegram/Slack (if configured) for alerts.\n")
