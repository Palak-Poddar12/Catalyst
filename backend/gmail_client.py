import os
import base64
from typing import Any, Dict, List, Optional

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import AuthorizedSession

# Adjust these to match your OAuth setup
GMAIL_CLIENT_ID = os.getenv("GMAIL_CLIENT_ID")
GMAIL_CLIENT_SECRET = os.getenv("GMAIL_CLIENT_SECRET")
GMAIL_REDIRECT_URI = os.getenv(
    "GMAIL_REDIRECT_URI",
    "http://localhost:8000/auth/gmail/callback",
)
GMAIL_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
]


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
    authorization_url, _ = flow.authorization_url(
        prompt="consent",
        access_type="offline",
        include_granted_scopes="true",
    )
    return authorization_url


def exchange_code_for_tokens(code: str) -> Credentials:
    """
    Exchange OAuth2 authorization code for tokens and return Credentials.
    """
    flow = _get_flow()
    flow.redirect_uri = GMAIL_REDIRECT_URI
    flow.fetch_token(code=code)
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
    service = _build_gmail_service(credentials)

    query = ""
    if label_ids:
        # You can filter by label, e.g. ["INBOX"]
        pass

    response = (
        service.users()
        .messages()
        .list(
            userId=user_id,
            maxResults=max_results,
            q=query,
            labelIds=label_ids or ["INBOX"],
        )
        .execute()
    )

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
    service = _build_gmail_service(credentials)

    msg = (
        service.users()
        .messages()
        .get(
            userId=user_id,
            id=message_id,
            format="raw",
        )
        .execute()
    )

    raw_b64 = msg["raw"]
    # Gmail uses URL-safe base64
    raw_bytes = base64.urlsafe_b64decode(raw_b64)
    return raw_bytes.decode("utf-8", errors="replace")


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