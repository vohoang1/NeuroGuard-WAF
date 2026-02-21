import logging
import random

# A stub model loader. In production, this would initialize onnxruntime.InferenceSession("model.onnx")
# and tokenize the payload. 

logger = logging.getLogger("model_loader")

def analyze_payload(payload: str) -> float:
    # MVP Dummy Heuristic (Replace with actual ONNX model inference)
    # E.g.: session.run(None, {"input_ids": tokenized})
    
    suspicious_keywords = ["union", "select", "script", "alert(", "eval", "<svg", "base64", "cmd.exe", "/bin/sh"]
    
    payload_lower = payload.lower()
    matches = sum(1 for kw in suspicious_keywords if kw in payload_lower)
    
    if matches > 2:
        return min(0.95 + random.uniform(0.01, 0.04), 1.0)
    elif matches > 0:
        return 0.70 + random.uniform(0.05, 0.1)
    
    # Random baseline noise
    return random.uniform(0.01, 0.15)
