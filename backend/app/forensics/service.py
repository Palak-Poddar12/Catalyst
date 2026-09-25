from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from member1_forensic_analyzer import analyze_eml_file
from app.forensics.member1_adapter import normalize_member1_result


def analyze_eml_bytes(content: bytes, filename: str) -> dict[str, Any]:
    """Run Member 1's forensic engine against uploaded EML bytes."""
    suffix = Path(filename).suffix.lower() or ".eml"
    if suffix != ".eml":
        suffix = ".eml"

    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as handle:
            handle.write(content)
            temp_path = Path(handle.name)

        raw_result = analyze_eml_file(temp_path)
        normalized = normalize_member1_result(raw_result)
        normalized["raw_forensic_result"] = raw_result
        return normalized
    finally:
        if temp_path and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


# Backwards-compatible alias for code that expects a forensic function.
def build_forensic_result(email: dict[str, Any]) -> dict[str, Any]:
    """Compatibility wrapper for the old generic parser path."""
    raise RuntimeError(
        "build_forensic_result(email) is deprecated. "
        "Use analyze_eml_bytes(content, filename)."
    )
