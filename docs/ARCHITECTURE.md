
```markdown
# 🏗️ NeuroGuard WAF: Architecture Deep Dive

Tài liệu này phân tích chi tiết các quyết định thiết kế kiến trúc, sự đánh đổi (trade-offs) và lý do lựa chọn công nghệ đằng sau NeuroGuard WAF. Mục tiêu là xây dựng một hệ thống cân bằng giữa **Hiệu năng (Performance)**, **Bảo mật (Security)** và **Khả năng mở rộng (Scalability)**.

---

## 1. Triết lý Thiết kế (Design Philosophy)

NeuroGuard được xây dựng dựa trên 3 nguyên tắc cốt lõi:

1.  **Fail-Closed by Default, Fail-Open for Availability:** Trong chế độ bảo mật cao, nếu hệ thống gặp lỗi không xác định, request sẽ bị chặn. Tuy nhiên, nếu AI Sidecar bị timeout hoặc lỗi, hệ thống tự động chuyển sang chế độ "Rule-only" để đảm bảo dịch vụ không bị gián đoạn (Availability).
2.  **Defense in Depth (Phòng thủ chiều sâu):** Không phụ thuộc vào một lớp bảo vệ duy nhất. Kết hợp Signature-based (nhanh, chính xác với known attacks) và AI-based (chậm hơn nhưng phát hiện được unknown attacks).
3.  **Edge-First:** Đẩy logic xử lý ra sát biên (Edge/Proxy) để chặn tấn công trước khi nó chạm tới ứng dụng core, giảm tải cho backend.

---

## 2. Phân tích Lựa chọn Công nghệ (Technology Choices)

### A. WAF Core: Tại sao là Rust + WebAssembly (Wasm)?

| Yêu cầu | Giải pháp truyền thống (Lua/Nginx) | Giải pháp NeuroGuard (Rust/Wasm) | Lý do chọn Rust/Wasm |
| :--- | :--- | :--- | : |
| **An toàn bộ nhớ** | Dễ bị lỗi buffer overflow, segfault. | **Memory Safety** tuyệt đối nhờ Rust compiler. | Giảm thiểu lỗ hổng ngay trong chính công cụ bảo mật. |
| **Hiệu năng** | Lua chạy trên VM, có overhead GC (Garbage Collection). | Biên dịch sang mã máy (AOT), không có GC, tốc độ gần ngang C++. | Đảm bảo độ trễ <5ms ngay cả dưới tải cao. |
| **Cô lập (Isolation)** | Chạy cùng tiến trình với Proxy, crash có thể làm sập cả Proxy. | **Sandboxed**: Chạy trong môi trường ảo hóa nhẹ, crash không ảnh hưởng host. | Tăng tính ổn định cho toàn hệ thống Envoy. |
| **Di động** | Phụ thuộc vào version Nginx/Lua cụ thể. | Chuẩn **Proxy-Wasm ABI**: Chạy được trên Envoy, Istio, và bất kỳ proxy nào hỗ trợ Wasm. | Tương lai-proof, dễ dàng tích hợp vào Kubernetes service mesh. |

### B. AI Engine: Tại sao lại là Sidecar Pattern thay vì nhúng trực tiếp?

Chúng ta đã cân nhắc hai phương án:
1.  **Nhúng ONNX Runtime trực tiếp vào Wasm:**
    *   *Ưu điểm:* Độ trễ thấp nhất (no network hop).
    *   *Nhược điểm:* Kích thước binary Wasm tăng vọt (>20MB), thời gian khởi động chậm, khó cập nhật model mà không rebuild toàn bộ WAF, hạn chế về thư viện Python phong phú.
2.  **Sidecar Pattern (Lựa chọn của NeuroGuard):**
    *   *Cơ chế:* WAF (Rust) giao tiếp với AI Service (Python) qua HTTP/gRPC nội bộ (localhost).
    *   *Ưu điểm:*
        *   **Tách biệt quan tâm (Separation of Concerns):** Đội AI có thể dùng Python, PyTorch, Scikit-learn mà không cần biết Rust.
        *   **Hot-Reload Model:** Có thể cập nhật file `.onnx` mới và restart service Python trong vài giây mà không cần restart Envoy hay compile lại Wasm.
        *   **Tài nguyên linh hoạt:** Có thể cấp phát nhiều CPU/RAM hơn cho container AI mà không ảnh hưởng đến container Proxy.
    *   *Nhược điểm:* Thêm độ trễ mạng nội bộ (~1-2ms).
    *   *Giải pháp khắc phục:* Sử dụng cơ chế **Async Dispatch** trong Proxy-Wasm. Request không bị block hoàn toàn; trong khi chờ AI phản hồi, các request khác vẫn được xử lý. Hơn nữa, chỉ những request "nghi ngờ" (sau khi lọc qua Rule) mới được gửi đi AI, giảm thiểu số lượng call.

### C. Database: Tại sao là ClickHouse?

*   **Vấn đề:** WAF sinh ra lượng log khổng lồ (hàng triệu dòng/giây). Các DB quan hệ truyền thống (PostgreSQL, MySQL) sẽ bị quá tải khi insert và truy vấn thời gian thực. Elasticsearch thì tốn RAM khủng khiếp.
*   **Giải pháp ClickHouse:**
    *   **Column-oriented Storage:** Tối ưu cực tốt cho các truy vấn aggregation (ví dụ: "Đếm số lần tấn công theo IP trong 5 phút qua").
    *   **Tốc độ Insert:** Có thể xử lý hàng trăm nghìn dòng log mỗi giây trên một node đơn.
    *   **Nén dữ liệu:** Tiết kiệm chi phí lưu trữ disk so với các giải pháp khác.

### D. Backend API: Tại sao là Go (Golang)?

*   **Concurrency:** Go nổi tiếng với Goroutines, xử lý hàng nghìn kết nối đồng thời đến Dashboard và API mà không tốn nhiều tài nguyên.
*   **Ecosystem:** Thư viện mạnh mẽ cho ClickHouse (`clickhouse-go`) và Networking.
*   **Binary Single File:** Dễ dàng đóng gói vào Docker image nhỏ gọn (Distroless), giảm surface attack của chính API server.

---

## 3. Luồng Dữ liệu & Xử lý Bất đồng bộ (Data Flow & Async Handling)

Đây là phần phức tạp nhất của hệ thống. Chúng ta xử lý bài toán "Làm sao để gọi AI mà không làm chậm request?" như sau:

### Cơ chế "Pause & Resume" trong Proxy-Wasm

1.  **Giai đoạn 1: Fast Path Check**
    *   Request đến -> Wasm kích hoạt `on_http_request_body`.
    *   Quét Regex nhanh.
    *   Nếu **Match rõ ràng** -> Trả về `Action::Deny` ngay lập tức (2ms).
    *   Nếu **Safe rõ ràng** -> Trả về `Action::Continue` ngay lập tức (2ms).
    *   Nếu **Nghi ngờ (Uncertain)** -> Chuyển sang Giai đoạn 2.

2.  **Giai đoạn 2: Async AI Inference**
    *   Wasm gọi `dispatch_http_call` đến AI Sidecar.
    *   **Quan trọng:** Wasm trả về `Action::Pause`. Envoy giữ nguyên connection của client, chưa gửi response, cũng chưa forward lên backend.
    *   Wasm chờ callback `on_http_call_response`.

3.  **Giai đoạn 3: Decision & Resume**
    *   Khi AI Sidecar trả về score (ví dụ: 0.85):
    *   Wasm nhận callback, tổng hợp điểm số.
    *   Nếu Score > Threshold -> `send_http_response(403)` và log hành động.
    *   Nếu Score < Threshold -> `resume_request()` để Envoy forward traffic lên backend.
    *   Toàn bộ quá trình Pause này diễn ra trong vòng <10ms, người dùng cuối hầu như không cảm nhận được.

---

## 4. Chiến lược Auto-Remediation & Đồng bộ trạng thái

Làm thế nào để chặn một IP trên toàn bộ cụm cluster (nhiều node Envoy)?

1.  **Phát hiện cục bộ:** Mỗi node WAF phát hiện tấn công và gửi log về ClickHouse.
2.  **Aggregation toàn cục:** Go API liên tục query ClickHouse (mỗi 5s) để tìm các IP có tần suất tấn công cao vượt ngưỡng.
3.  **Ra quyết định:** Go API thêm IP vào danh sách đen (Blacklist) trong Database và gửi thông báo Telegram.
4.  **Đồng bộ xuống Edge (Pull Model):**
    *   Thay vì đẩy (Push) từ API xuống từng node (khó quản lý khi scale), các node WAF sẽ **kéo (Pull)**.
    *   Một luồng nền trong Wasm (chạy mỗi 30s) gọi API `/api/blocklist` để tải danh sách IP mới nhất về lưu trong bộ nhớ đệm (Cache) cục bộ.
    *   **Trade-off:** Có độ trễ đồng bộ tối đa 30s. Đây là sự đánh đổi chấp nhận được để đổi lấy tính đơn giản và khả năng mở rộng cực cao (không cần Message Queue phức tạp như Kafka cho việc sync blocklist).

---

## 5. Bảo mật của chính hệ thống (Securing the WAF)

Một công cụ bảo mật cũng phải được bảo mật:

*   **Biến môi trường:** Tất cả secret (DB password, API token) được inject qua Docker Secrets hoặc Env Vars, không hard-code.
*   **Read-Only Filesystem:** Container Envoy và WAF chạy với filesystem chỉ đọc (trừ thư mục temp), ngăn chặn attacker ghi file malicious nếu có lỗ hổng RCE.
*   **Non-Root User:** Tất cả services chạy dưới user không phải root, giảm thiểu thiệt hại nếu bị compromise.
*   **Network Policies:** Chỉ cho phép traffic cần thiết giữa các service (ví dụ: WAF chỉ gọi được AI Sidecar, không gọi được internet tùy ý).

---

## 6. Hướng mở rộng trong tương lai (Future Scalability)

*   **Multi-Tenancy:** Thêm trường `tenant_id` vào log và API để phục vụ nhiều khách hàng trên cùng một hạ tầng (SaaS mode).
*   **eBPF Integration:** Kết hợp với eBPF để lấy thông tin ở tầng Kernel (network packet) bổ sung cho thông tin tầng Application, tăng độ chính xác phát hiện DDoS.
*   **Federated Learning:** Cho phép các node WAF học hỏi từ các cuộc tấn công cục bộ và cập nhật model AI chung mà không cần chia sẻ dữ liệu nhạy cảm (bảo vệ quyền riêng tư).

---

*Kiến trúc này là kết quả của quá trình nghiên cứu và thử nghiệm nhiều phương án khác nhau, nhằm đạt được điểm cân bằng tối ưu cho một hệ thống WAF hiện đại năm 2026.*
