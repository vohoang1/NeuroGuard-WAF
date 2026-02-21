import requests
import json
import time

WAF_URL = "http://localhost:8080/health"
API_URL = "http://localhost:8081/api/stats/summary"

def test_flow():
    print("🚀 Bắt đầu Integration Test: Luồng Wasm gọi AI Sidecar...")
    
    # 1. Gửi request bình thường (sạch)
    print("\n[+] Gửi request an toàn...")
    resp_clean = requests.post(WAF_URL, data="Hello, world!", headers={"User-Agent": "TestClient"})
    assert resp_clean.status_code == 200, f"Lỗi: Expected 200, got {resp_clean.status_code}"
    print("    ✅ Request sạch đi qua thành công.")

    # 2. Gửi request có dấu hiệu bất thường nhưng score < 0.9 (kích hoạt AI fallback)
    # Trong mô hình mock, nếu có chứa > 0 keyword sẽ trả về score >= 0.70
    # Nếu có > 2 keyword sẽ trả về score >= 0.95 (Block)
    # payload: "union select script" có 3 keywords: union, select, script
    print("\n[+] Gửi request độc hại để kích hoạt AI Sidecar Block...")
    payload_malicious = "union select script to test ai blockage"
    resp_malicious = requests.post(WAF_URL, data=payload_malicious, headers={"User-Agent": "Attacker"})
    assert resp_malicious.status_code == 403, f"Lỗi: Expected 403, got {resp_malicious.status_code}"
    print("    ✅ AI đã phân tích và CHẶN request thành công (403 Forbidden).")
    
    # Đợi 2 giây cho Wasm filter ghi log vào ClickHouse
    print("\n[+] Đợi hệ thống Audit Log ghi nhận metrics...")
    time.sleep(2)
    
    # 3. Request API backend để kiểm tra db đã lưu số liệu `blocked_by_ai` chưa.
    print("\n[+] Kiểm tra Backend Database API...")
    try:
        resp_stats = requests.get(API_URL).json()
        print(f"    📊 Tổng số request bị chặn: {resp_stats['blocked_requests']}")
        print(f"    🤖 Chặn bởi AI (ai_score >= 0.9): {resp_stats['blocked_by_ai']}")
        print(f"    📜 Chặn bởi Rules: {resp_stats['blocked_by_rules']}")
        
        assert resp_stats['blocked_by_ai'] >= 1, "Lỗi: Không tìm thấy lượt block nào từ AI trong log."
        print("    ✅ Database và API xác nhận log có chứa dữ liệu quyết định của AI!")
    except Exception as e:
        print(f"    ❌ Kiểm tra API thất bại: {e}")
        return

    print("\n🎉 Tất cả Integration Tests passed thành công!")

if __name__ == "__main__":
    test_flow()
