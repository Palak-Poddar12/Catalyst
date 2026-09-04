from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

def parse_eml_bytes(content: bytes) -> dict:
    message = BytesParser(policy=policy.default).parsebytes(content)

    def header(name):
        return message.get(name, "")

    sender_name, sender_email = parseaddr(header("From"))
    recipient_name, recipient_email = parseaddr(header("To"))

    plain_body = ""
    html_body = ""
    attachments = []

    if message.is_multipart():
        for part in message.walk():
            if part.is_attachment() or part.get_filename():
                payload = part.get_payload(decode=True) or b""
                import hashlib
                attachments.append({
                    "filename": part.get_filename() or "unknown",
                    "content_type": part.get_content_type(),
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                })
            elif part.get_content_type() == "text/plain":
                try:
                    plain_body += part.get_content()
                except Exception:
                    pass
            elif part.get_content_type() == "text/html":
                try:
                    html_body += part.get_content()
                except Exception:
                    pass
    else:
        try:
            if message.get_content_type() == "text/html":
                html_body = message.get_content()
            else:
                plain_body = message.get_content()
        except Exception:
            pass

    headers = {k: str(v) for k, v in message.items()}

    return {
        "from": header("From"),
        "sender_email": sender_email,
        "sender_name": sender_name,
        "to": header("To"),
        "recipient_email": recipient_email,
        "subject": header("Subject"),
        "date": header("Date"),
        "message_id": header("Message-ID"),
        "reply_to": header("Reply-To"),
        "return_path": header("Return-Path"),
        "headers": headers,
        "received": message.get_all("Received", []),
        "authentication_results": header("Authentication-Results"),
        "received_spf": header("Received-SPF"),
        "dkim_signature": header("DKIM-Signature"),
        "plain_body": plain_body,
        "html_body": html_body,
        "attachments": attachments,
    }
