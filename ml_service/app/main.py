from fastapi import FastAPI
from app.schemas import PredictRequest, PredictResponse
from app.predictor import predictor

app = FastAPI(
    title="SIH26106 ML Service",
    version="2.0.0",
    description="Independent ML inference service."
)

@app.get("/")
def root():
    return {"service": "SIH26106 ML", "status": "running"}

@app.get("/health")
def health():
    return {"status": "healthy", "model": predictor.status()}

@app.post("/predict", response_model=PredictResponse)
def predict(request: PredictRequest):
    return predictor.predict(request.features)
