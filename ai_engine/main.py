from fastapi import FastAPI, Request
from pydantic import BaseModel
import time
import logging
from model_loader import analyze_payload

app = FastAPI(title="NeuroGuard AI Engine")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ai_engine")

class PayloadRequest(BaseModel):
    payload: str
    user_agent: str | None = None
    method: str | None = None
    uri: str | None = None

class ScoreResponse(BaseModel):
    risk_score: float
    latency_ms: float

@app.post("/analyze", response_model=ScoreResponse)
async def analyze_traffic(req: PayloadRequest):
    start_time = time.time()
    
    # Run payload through the ONNX model loader function
    risk_score = analyze_payload(req.payload)
    
    latency = (time.time() - start_time) * 1000
    logger.info(f"Analyzed payload length {len(req.payload)} | Score: {risk_score:.3f} | Latency: {latency:.2f}ms")
    
    return ScoreResponse(risk_score=risk_score, latency_ms=latency)

@app.get("/health")
def health_check():
    return {"status": "ok", "plugin": "onnx"}
