
```markdown
# 🧠 AI Model Training & Export Guide

Hướng dẫn này dành cho các kỹ sư muốn tùy chỉnh, huấn luyện lại hoặc thay thế mô hình AI phát hiện tấn công của NeuroGuard bằng dữ liệu đặc thù của chính họ.

## 1. Tổng quan Mô hình (Model Overview)

NeuroGuard sử dụng mô hình phân loại nhị phân (Binary Classification) để xác định xem một payload HTTP là **Bình thường (0)** hay **Độc hại (1)**.

- **Kiến trúc:** DistilBERT (hoặc Logistic Regression cho MVP nhẹ) fine-tuned trên tập dữ liệu OWASP.
- **Đầu vào (Input):** Chuỗi text (URL, Query Params, Body).
- **Đầu ra (Output):** Probability score (0.0 - 1.0).
- **Định dạng triển khai:** ONNX (.onnx) để tương thích với ONNX Runtime trong Python Sidecar.

## 2. Chuẩn bị Dữ liệu (Data Preparation)

Chất lượng mô hình phụ thuộc vào dữ liệu. Bạn cần thu thập hai loại样本:

### A. Nguồn dữ liệu gợi ý
1.  **Tấn công (Malicious):**
    - [OWASP Core Rule Set Test Data](https://github.com/coreruleset/coreruleset/tree/main/tests/regression/tests)
    - [SecRepo Sample Files](https://www.secrepo.com/)
    - Log tấn công thực tế từ hệ thống NeuroGuard (xuất từ ClickHouse).
2.  **Bình thường (Benign):**
    - Log traffic thật từ website của bạn (đã làm sạch).
    - Dataset [CSIC 2010](https://www.isi.csic.es/dataset/).

### B. Định dạng Dataset
Tạo file `dataset.csv` với cấu trúc sau:
```csv
payload,label
"SELECT * FROM users WHERE id=1",1
"GET /index.html",0
"' OR 1=1 --",1
"username=admin&password=123",0
```
*(Label: 1 = Attack, 0 = Safe)*

## 3. Môi trường Huấn luyện (Training Environment)

Cài đặt các thư viện cần thiết trong môi trường Python (khuyến nghị dùng virtualenv):

```bash
pip install pandas scikit-learn torch transformers onnx onnxruntime
```

## 4. Quy trình Huấn luyện (Training Script)

Dưới đây là script mẫu `train_model.py` sử dụng mô hình **Logistic Regression với TF-IDF** (nhẹ, nhanh, phù hợp cho MVP) hoặc bạn có thể nâng cấp lên **DistilBERT**.

### Phiên bản Lightweight (TF-IDF + Logistic Regression)
*Phù hợp cho CPU, tốc độ inference <5ms.*

```python
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import onnx
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import StringTensorType

# 1. Load dữ liệu
print("Loading dataset...")
df = pd.read_csv('dataset.csv')
X = df['payload'].fillna('').values
y = df['label'].values

# 2. Tiền xử lý & Trích xuất đặc trưng (TF-IDF)
print("Vectorizing text...")
vectorizer = TfidfVectorizer(ngram_range=(1, 3), max_features=5000)
X_vec = vectorizer.fit_transform(X)

# 3. Chia tập Train/Test
X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.2, random_state=42)

# 4. Huấn luyện mô hình
print("Training model...")
model = LogisticRegression(max_iter=1000, class_weight='balanced')
model.fit(X_train, y_train)

# 5. Đánh giá
y_pred = model.predict(X_test)
print("Classification Report:\n", classification_report(y_test, y_pred))

# 6. Export sang ONNX
print("Exporting to ONNX...")
# Lưu ý: Cần chuyển đổi input type phù hợp cho chuỗi string
initial_type = [('float_input', FloatTensorType([None, X_vec.shape[1]]))]
onnx_model = convert_sklearn(model, initial_types=initial_type)

# Lưu model và vectorizer (dùng pickle cho vectorizer)
import pickle
with open("ai_engine/model.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())
    
with open("ai_engine/vectorizer.pkl", "wb") as f:
    pickle.dump(vectorizer, f)

print("✅ Model saved successfully to ai_engine/")
```

> 💡 **Nâng cao:** Nếu muốn dùng Transformer (BERT), hãy sử dụng thư viện `transformers` của HuggingFace và export qua `torch.onnx.export`. Tuy nhiên, cần cân nhắc kỹ về tài nguyên CPU khi chạy inference thời gian thực.

## 5. Tích hợp vào NeuroGuard Sidecar

Sau khi có file `model.onnx` mới:

1.  **Thay thế file:** Copy file `model.onnx` và `vectorizer.pkl` mới vào thư mục `ai_engine/` trong dự án.
2.  **Khởi động lại Service:**
    ```bash
    docker-compose restart ai-engine
    ```
3.  **Kiểm tra Log:** Xem log của AI Engine để đảm bảo model đã được load thành công:
    ```bash
    docker-compose logs -f ai-engine
    # Tìm dòng: "Model loaded successfully with ONNX Runtime"
    ```

## 6. Kiểm thử Mô hình Mới (Validation)

Trước khi đưa vào production, hãy chạy script test đơn giản để đảm bảo model hoạt động đúng:

```python
# test_inference.py
import onnxruntime as ort
import pickle
import numpy as np

# Load resources
sess = ort.InferenceSession("ai_engine/model.onnx")
with open("ai_engine/vectorizer.pkl", "rb") as f:
    vec = pickle.load(f)

# Test payload
payload = ["1 UNION SELECT password FROM users"]
input_vec = vec.transform(payload).toarray().astype(np.float32)

# Inference
inputs = {sess.get_inputs()[0].name: input_vec}
result = sess.run(None, inputs)[0]

print(f"Risk Score: {result[0][1]:.4f}") # Xác suất là Attack
# Kết quả mong đợi: > 0.8
```

## 7. Best Practices & Lưu ý

- **Class Imbalance:** Dữ liệu tấn công thường ít hơn dữ liệu sạch. Hãy dùng `class_weight='balanced'` hoặc kỹ thuật oversampling (SMOTE) khi train.
- **Drift Detection:** Theo dõi phân bố điểm số AI theo thời gian. Nếu tỷ lệ false positive tăng cao, cần re-train model với dữ liệu mới nhất.
- **Quantization:** Để tăng tốc độ inference trên CPU, hãy áp dụng Quantization (INT8) cho model ONNX trước khi deploy.
    ```python
    from onnxruntime.quantization import quantize_dynamic, QuantType
    quantize_dynamic("model.onnx", "model_quantized.onnx", weight_type=QuantType.QUInt8)
    ```

---
*Bằng cách tự train model, bạn đang biến NeuroGuard từ một công cụ chung chung thành một "hệ miễn dịch" đặc thù cho hạ tầng của chính mình.*
```
