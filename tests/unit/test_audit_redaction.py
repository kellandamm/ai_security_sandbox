import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../app"))

from audit import redact_audit_event_dict, redact_sensitive_text


def test_redact_sensitive_text_masks_email_and_ssn():
    text = "Contact jane.doe@example.com with SSN 123-45-6789"
    redacted = redact_sensitive_text(text)
    assert "jane.doe@example.com" not in redacted
    assert "123-45-6789" not in redacted
    assert "[REDACTED_EMAIL]" in redacted
    assert "[REDACTED_SSN]" in redacted


def test_redact_audit_event_dict_masks_sensitive_fields():
    event = {
        "path": "/workspace/abc/write/jane.doe@example.com.txt",
        "destination": "https://api.example.com?phone=555-123-4567",
        "error_code": "payload had AccountKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "parent_run_id": "ghp_abcdefghijklmnopqrstuvwxyz123456",
    }
    redacted = redact_audit_event_dict(event)
    assert "jane.doe@example.com" not in redacted["path"]
    assert "555-123-4567" not in redacted["destination"]
    assert "AccountKey=" in redacted["error_code"]
    assert "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" not in redacted["error_code"]
    assert "ghp_" not in redacted["parent_run_id"]
