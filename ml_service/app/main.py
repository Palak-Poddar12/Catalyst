from fastapi import FastAPI
from pydantic import BaseModel

from app.modules.ml.nlp_classifier import NLPPhishingClassifier

app = FastAPI(title="SIH26106 NLP ML Service")

classifier = NLPPhishingClassifier(
    weights_path="models/best_model.pt"
)


class PredictionRequest(BaseModel):
    email_text: str


@app.get("/health")
def health():
    return {
        "status": "ok",
        "model": "NLPPhishingClassifier"
    }


@app.post("/predict")
def predict(request: PredictionRequest):
    return classifier.predict(request.email_text)