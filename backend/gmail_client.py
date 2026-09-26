import os
import base64
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import AuthorizedSession

load_dotenv()

GMAIL_CLIENT_ID = os.getenv("GMAIL_CLIENT_ID")
GMAIL_CLIENT_SECRET = os.getenv("GMAIL_CLIENT_SECRET")
GMAIL_REDIRECT_URI = os.getenv(
    "GMAIL_REDIRECT_URI",
    "http://127.0.0.1:8000/api/v1/gmail/callback",
)
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def _get_flow() -> Flow:
    client_config = {
        "web": {
            "client_id": GMAIL_CLIENT_ID,
            "client_secret": GMAIL_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [GMAIL_REDIRECT_URI],
        }
    }
    flow = Flow.from_client_config(client_config, scopes=GMAIL_SCOPES)
    flow.redirect_uri = GMAIL_REDIRECT_URI
    return flow


def get_gmail_authorization_url() -> tuple[str, str, str]:
    flow = _get_flow()
    authorization_url, state = flow.authorization_url(
        prompt="consent", access_type="offline", include_granted_scopes="true"
    )
    if not flow.code_verifier:
        raise RuntimeError("Google OAuth did not provide a PKCE code verifier")
    return authorization_url, state, flow.code_verifier


def exchange_code_for_tokens(code: str, code_verifier: str) -> Credentials:
    flow = _get_flow()
    flow.code_verifier = code_verifier
    flow.fetch_token(code=code, code_verifier=code_verifier)
    return flow.credentials


def _build_gmail_service(credentials: Credentials):
    return build("gmail", "v1", credentials=credentials)


def get_gmail_profile_email(credentials: Credentials) -> str:
    session = AuthorizedSession(credentials)
    response = session.get(
        "https://gmail.googleapis.com/gmail/v1/users/me/profile", timeout=15
    )
    response.raise_for_status()
    return str(response.json().get("emailAddress") or "")


def list_recent_message_ids(credentials: Credentials, user_id: str = "me", max_results: int = 10, label_ids: Optional[List[str]] = None) -> List[str]:
    session = AuthorizedSession(credentials)
    response = session.get(
        f"https://gmail.googleapis.com/gmail/v1/users/{user_id}/messages",
        params={"maxResults": max_results, "labelIds": label_ids or ["INBOX"]},
        timeout=15,
    )
    response.raise_for_status()
    return [m["id"] for m in response.json().get("messages", [])]


def get_message_raw(credentials: Credentials, message_id: str, user_id: str = "me") -> bytes:
    session = AuthorizedSession(credentials)
    response = session.get(
        f"https://gmail.googleapis.com/gmail/v1/users/{user_id}/messages/{message_id}",
        params={"format": "raw"}, timeout=15,
    )
    response.raise_for_status()
    raw_b64 = response.json()["raw"]
    return base64.urlsafe_b64decode(raw_b64)


def get_credentials_from_token(token_data: Dict[str, Any]) -> Credentials:
    return Credentials(
        token=token_data.get("token"),
        refresh_token=token_data.get("refresh_token"),
        token_uri=token_data.get("token_uri", "https://oauth2.googleapis.com/token"),
        client_id=token_data.get("client_id"),
        client_secret=token_data.get("client_secret"),
        scopes=token_data.get("scopes", GMAIL_SCOPES),
    )
