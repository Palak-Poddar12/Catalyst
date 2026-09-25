import os
import base64
import threading
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import AuthorizedSession

load_dotenv()

# Adjust these to match your OAuth setup
GMAIL_CLIENT_ID = os.getenv("GMAIL_CLIENT_ID")
GMAIL_CLIENT_SECRET = os.getenv("GMAIL_CLIENT_SECRET")
GMAIL_REDIRECT_URI = os.getenv(
    "GMAIL_REDIRECT_URI",
    "http://127.0.0.1:8000/api/v1/gmail/callback",
)
GMAIL_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
]
_OAUTH_VERIFIERS: Dict[str, str] = {}
_OAUTH_LOCK = threading.Lock()


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

    flow = Flow.from_client_config(
        client_config,
        scopes=GMAIL_SCOPES,
    )
    flow.redirect_uri = GMAIL_REDIRECT_URI
    return flow


def get_gmail_authorization_url() -> str:
    flow = _get_flow()
    flow.redirect_uri = GMAIL_REDIRECT_URI
    authorization_url, state = flow.authorization_url(
        prompt="consent",
        access_type="offline",
        include_granted_scopes="true",
    )
    if not flow.code_verifier:
        raise RuntimeError("Google OAuth did not provide a PKCE code verifier")
    with _OAUTH_LOCK:
        _OAUTH_VERIFIERS[state] = flow.code_verifier
    return authorization_url


def exchange_code_for_tokens(code: str, state: str) -> Credentials:
    """
    Exchange OAuth2 authorization code for tokens and return Credentials.
    """
    with _OAUTH_LOCK:
        code_verifier = _OAUTH_VERIFIERS.get(state)
    if not code_verifier:
        raise ValueError("OAuth state is missing or expired. Start a new Gmail connection.")

    flow = _get_flow()
    flow.redirect_uri = GMAIL_REDIRECT_URI
    flow.code_verifier = code_verifier
    flow.fetch_token(code=code, code_verifier=code_verifier)
    with _OAUTH_LOCK:
        _OAUTH_VERIFIERS.pop(state, None)
    return flow.credentials


def _build_gmail_service(credentials: Credentials):
    return build("gmail", "v1", credentials=credentials)


def list_recent_message_ids(
    credentials: Credentials,
    user_id: str = "me",
    max_results: int = 10,
    label_ids: Optional[List[str]] = None,
) -> List[str]:
    """
    List recent message IDs from Gmail.
    """
    session = AuthorizedSession(credentials)
    response = session.get(
        "https://gmail.googleapis.com/gmail/v1/users/{}/messages".format(user_id),
        params={
            "maxResults": max_results,
            "labelIds": label_ids or ["INBOX"],
        },
        timeout=15,
    )
    response.raise_for_status()
    response = response.json()

    messages = response.get("messages", [])
    return [m["id"] for m in messages]


def get_message_raw(
    credentials: Credentials,
    message_id: str,
    user_id: str = "me",
) -> str:
    """
    Fetch a Gmail message as raw RFC822 MIME bytes (base64 decoded).
    This can be passed directly into your existing email parser.
    """
    session = AuthorizedSession(credentials)
    response = session.get(
        "https://gmail.googleapis.com/gmail/v1/users/{}/messages/{}".format(
            user_id,
            message_id,
        ),
        params={"format": "raw"},
        timeout=15,
    )
    response.raise_for_status()
    msg = response.json()

    raw_b64 = msg["raw"]
    # Gmail uses URL-safe base64
    raw_bytes = base64.urlsafe_b64decode(raw_b64)
    return raw_bytes


def get_credentials_from_token(token_data: Dict[str, Any]) -> Credentials:
    """
    Build a Credentials object from a stored token dict.
    token_data should contain at least:
      - token
      - refresh_token
      - token_uri
      - client_id
      - client_secret
      - scopes
    """
    return Credentials(
        token=token_data.get("token"),
        refresh_token=token_data.get("refresh_token"),
        token_uri=token_data.get("token_uri", "https://oauth2.googleapis.com/token"),
        client_id=token_data.get("client_id"),
        client_secret=token_data.get("client_secret"),
        scopes=token_data.get("scopes", []),
    )