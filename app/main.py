from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.api.router import api_router
from app.core.config import settings
from app.database.database import Base, engine
from app.database import models  # noqa: F401

@asynccontextmanager
async def lifespan(app: FastAPI):
    # MVP bootstrap. Replace with Alembic migrations for production.
    Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(
    title="SIH26106 Backend",
    version="2.0.0",
    description="Central orchestration API for cases, EML forensics, ML inference and analysis."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")

@app.get("/")
def root():
    return {"project": "SIH26106", "status": "running", "service": "backend"}

@app.get("/health")
def health():
    db_status = "connected"
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        db_status = "disconnected"

    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "database": db_status,
        "ml_service": settings.ml_service_url or "not_configured",
    }
