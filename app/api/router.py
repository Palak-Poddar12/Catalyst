from fastapi import APIRouter
from app.cases.router import router as cases_router
from app.emails.router import router as emails_router
from app.analysis.router import router as analysis_router
from app.reports.router import router as reports_router

api_router = APIRouter()
api_router.include_router(cases_router)
api_router.include_router(emails_router)
api_router.include_router(analysis_router)
api_router.include_router(reports_router)
