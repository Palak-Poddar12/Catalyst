from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.database import Base, get_db
from app.main import app


engine = create_engine(
    "sqlite:///./test_smoke.db",
    connect_args={"check_same_thread": False},
)
TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)


def override_get_db():
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


def test_root_returns_200():
    response = client.get("/")

    assert response.status_code == 200


def test_cases_list_returns_json():
    response = client.get("/api/v1/cases")

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_create_case():
    response = client.post(
        "/api/v1/cases",
        json={
            "title": "Smoke Test Case",
            "name": "Smoke Test",
            "description": "Created by CI smoke test",
        },
    )

    assert response.status_code in (200, 201)
    assert response.json()["title"] == "Smoke Test Case"


def test_get_case_not_found():
    response = client.get("/api/v1/cases/99999")

    assert response.status_code == 404


def test_upload_missing_file_returns_422():
    response = client.post("/api/v1/emails/upload/1")

    assert response.status_code == 422


def test_ml_unavailable_does_not_crash_upload():
    case_response = client.post(
        "/api/v1/cases",
        json={"title": "ML Unavailable Test", "name": "ML Test"},
    )
    case_id = case_response.json()["id"]
    eml_content = (
        b"From: test@example.com\r\n"
        b"To: victim@company.com\r\n"
        b"Subject: Test email\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"This is a test email body."
    )

    response = client.post(
        f"/api/v1/emails/upload/{case_id}",
        files={"file": ("test.eml", eml_content, "message/rfc822")},
    )

    assert response.status_code == 200
    assert response.json()["ml_status"] in ("unavailable", "success")


def test_analysis_case_endpoint_exists():
    response = client.get("/api/v1/analysis/case/99999")

    assert response.status_code in (200, 404)