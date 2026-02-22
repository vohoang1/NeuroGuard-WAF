# 🔌 NeuroGuard WAF - API Documentation

Tài liệu này mô tả chi tiết tất cả các endpoint RESTful API của NeuroGuard WAF. API được xây dựng bằng **Go (Gin Framework)** và cung cấp giao tiếp giữa Dashboard, hệ thống giám sát và các service bên ngoài.

---

## 📋 Mục lục

1. [Tổng quan](#tổng-quan)
2. [Xác thực (Authentication)](#xác-thực-authentication)
3. [Thống kê (Statistics)](#thống-kê-statistics)
4. [Nhật ký tấn công (Attack Logs)](#nhật-ký-tấn-công-attack-logs)
5. [Auto-Remediation](#auto-remediation)
6. [Hệ thống (System)](#hệ-thống-system)
7. [Mã lỗi (Error Codes)](#mã-lỗi-error-codes)

---

## Tổng quan

| Thông tin | Chi tiết |
| :--- | :--- |
| **Base URL** | `http://localhost:8080/api` |
| **Định dạng** | JSON (`application/json`) |
| **Xác thực** | JWT Bearer Token (cho hầu hết endpoint) |
| **Phiên bản API** | `v1` |
| **Rate Limiting** | 100 requests/phút cho mỗi IP |

### Cấu trúc Response chuẩn

**Thành công (2xx):**
```json
{
  "success": true,
  "data": { ... },
  "message": "Operation completed successfully",
  "timestamp": "2026-02-21T10:30:00Z"
}
```

**Lỗi (4xx/5xx):**
```json
{
  "success": false,
  "error": {
    "code": "ERR_INVALID_TOKEN",
    "message": "Mô tả lỗi chi tiết",
    "details": { ... }
  },
  "timestamp": "2026-02-21T10:30:00Z"
}
```

---

## Xác thực (Authentication)

### 1. Đăng nhập (Login)

Lấy JWT token để truy cập các endpoint bảo vệ.

| | |
| :--- | :--- |
| **Method** | `POST` |
| **Endpoint** | `/v1/auth/login` |
| **Auth Required** | ❌ No |

**Request Body:**
```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user": {
      "id": 1,
      "username": "admin",
      "role": "administrator"
    }
  },
  "timestamp": "2026-02-21T10:30:00Z"
}
```

**Response (401 Unauthorized):**
```json
{
  "success": false,
  "error": {
    "code": "ERR_INVALID_CREDENTIALS",
    "message": "Username hoặc password không đúng"
  },
  "timestamp": "2026-02-21T10:30:00Z"
}
```

---

### 2. Làm mới Token (Refresh Token)

| | |
| :--- | :--- |
| **Method** | `POST` |
| **Endpoint** | `/v1/auth/refresh` |
| **Auth Required** | ✅ Yes (Bearer Token) |

**Request Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 3600
  },
  "timestamp": "2026-02-21T10:30:00Z"
}
```

---

## Thống kê (Statistics)

### 3. Lấy thống kê tổng quan (Summary Stats)

Lấy số liệu tổng hợp cho dashboard (KPI cards).

| | |
| :--- | :--- |
| **Method** | `GET` |
| **Endpoint** | `/v1/stats/summary` |
| **Auth Required** | ✅ Yes |

**Query Parameters:**
| Param | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `time_range` | string | No | `1h`, `24h`, `7d`, `30d` (default: `24h`) |

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "total_requests": 152847,
    "blocked_requests": 3421,
    "block_rate": 2.24,
    "active_threats": 15,
    "unique_attackers": 87,
    "blocked_by_rules": 2890,
    "blocked_by_ai": 531,
    "top_attack_types": [
      { "type": "SQL Injection", "count": 1523 },
      { "type": "XSS", "count": 892 },
      { "type": "Bot", "count": 654 },
      { "type": "RCE", "count": 352 }
    ]
  },
  "timestamp": "2026-02-21T10:30:00Z"
}
```

---

### 4. Lấy dữ liệu biểu đồ thời gian (Time Series)

Dữ liệu cho biểu đồ đường (attacks over time).

| | |
| :--- | :--- |
| **Method** | `GET` |
| **Endpoint** | `/v1/stats/timeseries` |
| **Auth Required** | ✅ Yes |

**Query Parameters:**
| Param | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `interval` | string | No | `1m`, `5m`, `1h`, `1d` (default: `5m`) |
| `time_range` | string | No | `1h`, `24h`, `7d` (default: `24h`) |

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "labels": ["10:00", "10:05", "10:10", "10:15", ...],
    "series": {
      "total_requests": [1200, 1350, 1100, 1450, ...],
      "blocked_requests": [25, 32, 18, 41, ...],
      "ai_detections": [5, 8, 3, 12, ...]
    }
  },
  "timestamp": "2026-02-21T10:30:00Z"
}
```

---

## Nhật ký tấn công (Attack Logs)

### 5. Lấy danh sách log (Get Logs)

Truy vấn nhật ký tấn công với phân trang và lọc.

| | |
| :--- | :--- |
| **Method** | `GET` |
| **Endpoint** | `/v1/logs` |
| **Auth Required** | ✅ Yes |

**Query Parameters:**
| Param | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `page` | integer | No | Số trang (default: 1) |
| `limit` | integer | No | Số lượng mỗi trang (default: 50, max: 500) |
| `attack_type` | string | No | Lọc theo loại tấn công (`SQLi`, `XSS`, `Bot`) |
| `source_ip` | string | No | Lọc theo IP nguồn |
| `action` | string | No | `blocked`, `allowed`, `flagged` |
| `time_from` | string | No | ISO 8601 datetime (e.g., `2026-02-21T00:00:00Z`) |
| `time_to` | string | No | ISO 8601 datetime |

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "logs": [
      {
        "id": "log_123456",
        "timestamp": "2026-02-21T10:25:33Z",
        "source_ip": "192.168.1.100",
        "country_code": "VN",
        "method": "GET",
        "uri": "/api/user?id=1' OR 1=1",
        "attack_type": "SQL Injection",
        "confidence": 0.95,
        "ai_score": 0.88,
        "action": "blocked",
        "rule_id": 2,
        "user_agent": "Mozilla/5.0...",
        "correlation_id": "corr_abc123"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 50,
      "total_records": 3421,
      "total_pages": 69
    }
  },
  "timestamp": "2026-02-21T10:30:00Z"
}
```

---

### 6. Lấy chi tiết một log (Get Log Detail)

| | |
| :--- | :--- |
| **Method** | `GET` |
| **Endpoint** | `/v1/logs/:id` |
| **Auth Required** | ✅ Yes |

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "id": "log_123456",
    "timestamp": "2026-02-21T10:25:33Z",
    "source_ip": "192.168.1.100",
    "geo_location": {
      "country": "Vietnam",
      "city": "Ho Chi Minh City",
      "lat": 10.8231,
      "lon": 106.6297
    },
    "request": {
      "method": "GET",
      "uri": "/api/user?id=1' OR 1=1",
      "headers": { ... },
      "body": null
    },
    "detection": {
      "attack_type": "SQL Injection",
      "confidence": 0.95,
      "ai_score": 0.88,
      "rule_id": 2,
      "rule_name": "OR Tautology Detection",
      "evidence": "' OR 1=1"
    },
    "action": {
      "type": "blocked",
      "response_code": 403,
      "remediation_applied": true,
      "ip_blocked": true
    }
  },
  "timestamp": "2026-02-21T10:30:00Z"
}
```

---

## Auto-Remediation

### 7. Lấy trạng thái Auto-Remediation

| | |
| :--- | :--- |
| **Method** | `GET` |
| **Endpoint** | `/v1/remediation/status` |
| **Auth Required** | ✅ Yes |

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "enabled": true,
    "block_threshold": 5,
    "time_window_seconds": 60,
    "block_duration_minutes": 60,
    "total_blocked_ips": 23,
    "last_triggered": "2026-02-21T10:25:33Z"
  },
  "timestamp": "2026-02-21T10:30:00Z"
}
```

---

### 8. Bật/Tắt Auto-Blocking

| | |
| :--- | :--- |
| **Method** | `POST` |
| **Endpoint** | `/v1/remediation/toggle` |
| **Auth Required** | ✅ Yes |

**Request Body:**
```json
{
  "enabled": true
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "enabled": true,
    "updated_at": "2026-02-21T10:30:00Z"
  },
  "message": "Auto-remediation has been enabled",
  "timestamp": "2026-02-21T10:30:00Z"
}
```

---

### 9. Lấy danh sách IP bị chặn (Blocklist)

| | |
| :--- | :--- |
| **Method** | `GET` |
| **Endpoint** | `/v1/remediation/blocklist` |
| **Auth Required** | ✅ Yes |

**Query Parameters:**
| Param | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `page` | integer | No | Số trang (default: 1) |
| `limit` | integer | No | Số lượng mỗi trang (default: 50) |

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "blocked_ips": [
      {
        "ip": "192.168.1.100",
        "reason": "Brute-force attack detected",
        "triggered_by_rule_id": 2,
        "blocked_at": "2026-02-21T10:25:33Z",
        "expires_at": "2026-02-21T11:25:33Z",
        "attack_count": 15
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 50,
      "total_records": 23,
      "total_pages": 1
    }
  },
  "timestamp": "2026-02-21T10:30:00Z"
}
```

---

### 10. Unblock IP (Tháo chặn)

| | |
| :--- | :--- |
| **Method** | `POST` |
| **Endpoint** | `/v1/remediation/unblock` |
| **Auth Required** | ✅ Yes |

**Request Body:**
```json
{
  "ip": "192.168.1.100",
  "reason": "False positive - verified by admin"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "ip": "192.168.1.100",
    "unblocked_at": "2026-02-21T10:30:00Z",
    "operator": "admin"
  },
  "message": "IP 192.168.1.100 has been unblocked",
  "timestamp": "2026-02-21T10:30:00Z"
}
```

---

### 11. Quản lý Whitelist

**Thêm IP vào Whitelist:**

| | |
| :--- | :--- |
| **Method** | `POST` |
| **Endpoint** | `/v1/remediation/whitelist` |
| **Auth Required** | ✅ Yes |

**Request Body:**
```json
{
  "action": "add",
  "ip": "10.0.0.0/8",
  "reason": "Internal network"
}
```

**Xóa IP khỏi Whitelist:**
```json
{
  "action": "remove",
  "ip": "10.0.0.0/8"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "whitelist": [
      { "ip": "10.0.0.0/8", "reason": "Internal network", "added_at": "2026-02-20T08:00:00Z" },
      { "ip": "192.168.1.50", "reason": "Monitoring server", "added_at": "2026-02-21T09:00:00Z" }
    ]
  },
  "message": "Whitelist updated successfully",
  "timestamp": "2026-02-21T10:30:00Z"
}
```

---

### 12. Lấy lịch sử hành động (Action History)

| | |
| :--- | :--- |
| **Method** | `GET` |
| **Endpoint** | `/v1/remediation/actions` |
| **Auth Required** | ✅ Yes |

**Query Parameters:**
| Param | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `page` | integer | No | Số trang (default: 1) |
| `action_type` | string | No | `block`, `unblock`, `alert_sent` |

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "actions": [
      {
        "id": "act_789",
        "timestamp": "2026-02-21T10:25:33Z",
        "action_type": "block",
        "ip": "192.168.1.100",
        "reason": "Brute-force attack detected (>5 attempts in 1min)",
        "triggered_by_rule_id": 2,
        "operator": "auto",
        "notification_sent": true
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 50,
      "total_records": 156,
      "total_pages": 4
    }
  },
  "timestamp": "2026-02-21T10:30:00Z"
}
```

---

## Hệ thống (System)

### 13. Health Check

Kiểm tra tình trạng hoạt động của API server.

| | |
| :--- | :--- |
| **Method** | `GET` |
| **Endpoint** | `/v1/health` |
| **Auth Required** | ❌ No |

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "version": "1.0.0",
    "uptime_seconds": 86400,
    "services": {
      "clickhouse": "connected",
      "ai_engine": "connected",
      "telegram_bot": "connected"
    }
  },
  "timestamp": "2026-02-21T10:30:00Z"
}
```

---

### 14. Thông tin hệ thống (System Info)

| | |
| :--- | :--- |
| **Method** | `GET` |
| **Endpoint** | `/v1/system/info` |
| **Auth Required** | ✅ Yes (Admin only) |

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "version": "1.0.0",
    "build_date": "2026-02-21",
    "go_version": "1.21",
    "waf_version": "0.1.0",
    "model_version": "sqli_v2.3.onnx",
    "deployment": {
      "environment": "development",
      "region": "local"
    }
  },
  "timestamp": "2026-02-21T10:30:00Z"
}
```

---

## Mã lỗi (Error Codes)

| Code | HTTP Status | Description |
| :--- | :--- | :--- |
| `ERR_INVALID_TOKEN` | 401 | Token JWT không hợp lệ hoặc hết hạn |
| `ERR_INVALID_CREDENTIALS` | 401 | Username/password sai |
| `ERR_FORBIDDEN` | 403 | Người dùng không có quyền truy cập |
| `ERR_NOT_FOUND` | 404 | Resource không tìm thấy |
| `ERR_INVALID_INPUT` | 400 | Dữ liệu đầu vào không hợp lệ |
| `ERR_RATE_LIMITED` | 429 | Vượt quá giới hạn request |
| `ERR_INTERNAL_SERVER` | 500 | Lỗi server nội bộ |
| `ERR_SERVICE_UNAVAILABLE` | 503 | Service phụ thuộc (ClickHouse, AI) không khả dụng |

---

## 🔐 Bảo mật API

1.  **HTTPS:** Luôn sử dụng HTTPS trong production.
2.  **JWT Expiry:** Token hết hạn sau 1 giờ. Sử dụng refresh token để lấy token mới.
3.  **Rate Limiting:** 100 requests/phút cho mỗi IP để chống brute-force API.
4.  **Input Validation:** Tất cả input đều được validate và sanitize trước khi xử lý.
5.  **Audit Logging:** Mọi hành động admin (unblock, toggle settings) đều được ghi log.

---

## 🧪 Ví dụ sử dụng với cURL

### Đăng nhập và lấy token:
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

### Lấy thống kê với token:
```bash
curl -X GET http://localhost:8080/api/v1/stats/summary \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Unblock IP:
```bash
curl -X POST http://localhost:8080/api/v1/remediation/unblock \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.100","reason":"False positive"}'
```

---

## 📬 Hỗ trợ

Có vấn đề với API? Tạo Issue trên GitHub hoặc liên hệ:
- Email: hoangvo15224@gmail.com
- GitHub: [@vohoang1](https://github.com/vohoang1)

---
*API Version: 1.0.0 | Last Updated: February 2026*
