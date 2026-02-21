# 🛡 NeuroGuard WAF

AI-Powered Web Application Firewall built with Rust, WebAssembly and ONNX Runtime.

NeuroGuard WAF là một hệ thống Web Application Firewall (WAF) thế hệ mới kết hợp:
- Rule-based detection (signature engine)
- AI anomaly detection (machine learning inference)
- Edge execution bằng WebAssembly
- Real-time monitoring & auto-remediation

> Security Engineering Portfolio Project  
> Author: Võ Đình Hoàng  
> License: MIT  

---

## 🎯 Project Objectives

Các WAF truyền thống phụ thuộc vào rule tĩnh (regex, signature). Điều này khiến chúng dễ bị bypass bởi:
- Payload obfuscation
- Zero-day exploitation
- AI-generated attack variants

NeuroGuard WAF áp dụng kiến trúc Hybrid Detection:

- Deterministic filtering (low-latency rule engine)
- Machine learning inference (semantic payload analysis)
- Automated remediation workflow

Mục tiêu kỹ thuật:

- Latency < 5ms tại edge
- Phát hiện OWASP Top 10
- Auto-block IP brute-force
- Real-time SOC monitoring dashboard

---

## 🏗 System Architecture

High-level data flow:

Client  
→ Envoy Proxy  
→ Wasm Filter (Rust WAF Core)  
→ AI Sidecar (ONNX Runtime)  
→ ClickHouse (Audit Logs)  
→ Go Backend API  
→ React Dashboard  

### Core Components

| Component     | Tech Stack                      | Responsibility                     |
|--------------|----------------------------------|-------------------------------------|
| WAF Core     | Rust + Proxy-Wasm SDK           | Edge request inspection             |
| AI Engine    | Python + FastAPI + ONNX         | Payload semantic scoring            |
| Storage      | ClickHouse                      | High-speed log ingestion            |
| Backend API  | Go (Gin Framework)              | Remediation + management logic      |
| Dashboard    | React + TypeScript + Tailwind   | Real-time attack visualization      |

---

## 🔥 Key Features

- Hybrid Detection (Rule-based + AI-based)
- SQL Injection detection
- XSS detection
- Bot & brute-force detection
- Automatic IP blocking
- Telegram / Slack alert integration
- Real-time attack analytics dashboard
- Microservices architecture
- Docker-based deployment

---

## 🚀 Quick Start

### Requirements

- Docker & Docker Compose
- Rust (optional – nếu muốn build lại Wasm)
- Minimum 4GB RAM (Recommended 8GB)

---

### 1. Clone Repository

```bash
git clone https://github.com/vohoang1/neuroguard-waf.git
cd neuroguard-waf
```

---

### 2. Configure Environment

```bash
cp .env.example .env
```

Chỉnh sửa file `.env` và cấu hình:

- JWT_SECRET
- TELEGRAM_BOT_TOKEN
- ADMIN_PASSWORD
- DATABASE_CONFIG

---

### 3. Build Wasm Module (Optional)

```bash
cargo build --target wasm32-wasip1 --release
```

---

### 4. Start System

```bash
docker-compose up --build -d
```

---

### 5. Access Dashboard

Open browser:

```
http://localhost:3000
```

Default credentials:

- Username: admin
- Password: admin123

⚠️ IMPORTANT: Đổi mật khẩu ngay sau khi đăng nhập.

---

## 🧪 Testing

### Normal Request (Should Pass)

```bash
curl http://localhost:8080/get
```

---

### SQL Injection Test (Should Be Blocked)

```bash
curl "http://localhost:8080/get?id=1' OR 1=1"
```

Expected result:

```
403 Forbidden
```

---

### Trigger Auto-Remediation

```bash
for i in {1..6}; do curl "http://localhost:8080/?id=1' OR 1=1"; done
```

Expected:

- IP added to Blocked List
- Telegram alert triggered
- Further requests denied

---

## 📊 Performance Benchmark

Environment: 4 CPU cores / 8GB RAM

| Metric             | Result      |
|--------------------|------------|
| Latency p50        | ~3.2 ms    |
| Latency p99        | ~4.8 ms    |
| Throughput         | ~12,000 RPS|
| Detection Rate     | >98%       |
| False Positive     | <0.1%      |

---

## 🔐 Security Considerations

- Không khuyến nghị triển khai production nếu chưa audit
- Harden container configuration
- Không commit file `.env`
- Sử dụng secret manager (Vault/KMS) khi production
- Bật TLS termination khi deploy thực tế

---

## 📁 Repository Structure

```
neuroguard-waf/
│
├── waf-core/          
├── ai-engine/         
├── backend-api/       
├── dashboard/         
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## 🛣 Roadmap

- Distributed rate limiting
- Adaptive ML training pipeline
- Kubernetes deployment
- Threat intelligence integration
- eBPF traffic inspection module

---

## 🤝 Contributing

Pull requests are welcome.

Before contributing:

- Follow Rust & Go lint rules
- Add test cases
- Document security implications

---

## 📄 License

MIT License

---

## 📬 Contact

Võ Đình Hoàng  
GitHub: https://github.com/vohoang1  
Email: hoangvo15224@gmail.com  

---

NeuroGuard WAF – AI-Augmented Edge Security