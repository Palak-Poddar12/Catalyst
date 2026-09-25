from fastapi import FastAPI, HTTPException
from app.schemas import PredictRequest, PredictResponse
from app.predictor import predictor

app = FastAPI(
    title="SIH26106 ML Service",
    version="3.0.0",
    description="Real DistilBERT phishing-email inference service."
)

@app.get("/")
def root():
    return {"service": "SIH26106 ML", "status": "running", "model": predictor.status()}

@app.get("/health")
def health():
    state = predictor.status()
    return {
        "status": "healthy" if state["loaded"] else "degraded",
        "model": state,
    }

@app.post("/predict", response_model=PredictResponse)
def predict(request: PredictRequest):
    try:
        return predictor.predict(request.features)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
