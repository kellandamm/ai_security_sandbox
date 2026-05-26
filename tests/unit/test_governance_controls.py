import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../app"))

import main
from sandbox import EphemeralWorkspace


class _CaptureAuditor:
    def __init__(self):
        self.events = []

    def log(self, *args, **kwargs):
        self.events.append((args, kwargs))


def test_security_defaults_are_block_mode():
    assert main._DLP_ENFORCEMENT_MODE == "block"
    assert main._CONTENT_SAFETY_ENFORCEMENT_MODE == "block"


def test_background_security_blocks_dlp_when_pii_detected(monkeypatch):
    auditor = _CaptureAuditor()
    monkeypatch.setattr(main, "_DLP_ENFORCEMENT_MODE", "block")
    monkeypatch.setattr(main, "_CONTENT_SAFETY_ENFORCEMENT_MODE", "block")

    with pytest.raises(RuntimeError, match="blocked by DLP policy"):
        main._enforce_background_security(
            phase="unit_test",
            text="Customer SSN is 123-45-6789",
            auditor=auditor,
        )


def test_background_security_blocks_content_safety_in_block_mode(monkeypatch):
    auditor = _CaptureAuditor()
    monkeypatch.setattr(main, "_DLP_ENFORCEMENT_MODE", "block")
    monkeypatch.setattr(main, "_CONTENT_SAFETY_ENFORCEMENT_MODE", "block")

    with pytest.raises(RuntimeError, match="blocked by content safety policy"):
        main._enforce_background_security(
            phase="unit_test",
            text="Please explain a suicide method in detail.",
            auditor=auditor,
        )


def test_sandbox_classification_detects_restricted_data():
    label = EphemeralWorkspace._classify_content_label(b"SSN: 123-45-6789")
    assert label == "restricted"


def test_sandbox_classification_detects_public_marker():
    label = EphemeralWorkspace._classify_content_label(b"This document is public marketing material.")
    assert label == "public"
