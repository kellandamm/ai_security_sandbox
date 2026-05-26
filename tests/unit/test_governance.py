"""
Phase 3 — ISO 42001 / NIST AI RMF governance unit tests.

Validates:
 - Model card loading + Pydantic validation
 - Control mapping completeness (covers every shipped rego policy)
 - Governance metadata reference attached automatically to AuditEvents
 - Consent derivation from data classification
 - Attestation HMAC round-trip + signature tamper rejection
 - Compliance API routes (model-cards, control-mapping, attestation) admin-gated
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "app"))

# Test mode env so main.py boots without Azure dependencies.
os.environ.setdefault("APIM_IDENTITY_SIGNING_SECRET", "test-signing-secret")
os.environ.setdefault("APP_CONFIG_ENDPOINT", "")
os.environ.setdefault("WORKSPACE_STORAGE_ACCOUNT", "")
os.environ.setdefault("AUDIT_STORAGE_ACCOUNT", "")
os.environ.setdefault("AZURE_OPENAI_ENDPOINT", "")
os.environ.setdefault("ENABLE_DEMO_FEATURES", "1")

import governance  # noqa: E402
from audit import AuditLogger  # noqa: E402
from models.audit_event import ActionType  # noqa: E402


# ── Model card loading ────────────────────────────────────────────────────────
def test_model_cards_load_for_every_capability():
    """Every agent_type in capability_manifest must have a model card on disk."""
    from capability_manifest import AGENT_CAPABILITIES

    available = set(governance.list_agent_types_with_cards())
    for agent_type in AGENT_CAPABILITIES:
        assert agent_type in available, f"missing model card for {agent_type}"


def test_get_model_card_known_agent():
    card = governance.get_model_card("data-analyst")
    assert card is not None
    assert card.agent_type == "data-analyst"
    assert card.model_card_version
    assert card.residual_risk_class.value in {"low", "medium", "high"}
    assert card.iso_42001_controls, "ISO 42001 controls should not be empty"
    # All four NIST AI RMF functions should be mapped.
    keys = {f.value for f in card.nist_ai_rmf_map.keys()}
    assert {"govern", "map", "measure", "manage"}.issubset(keys)


def test_get_model_card_unknown_returns_none():
    assert governance.get_model_card("does-not-exist") is None


def test_governance_reference_shape():
    ref = governance.governance_reference("web-researcher")
    assert ref is not None
    # Format: "{agent_type}@{version}/{risk_class}"
    assert ref.startswith("web-researcher@")
    assert ref.endswith("/medium") or ref.endswith("/high") or ref.endswith("/low")


def test_governance_reference_none_for_unknown_type():
    assert governance.governance_reference("control-plane") is None


# ── Control mapping ──────────────────────────────────────────────────────────
def test_control_mapping_covers_every_shipped_rego_policy():
    mapping = governance.get_control_mapping()
    enforcement_points = [row["enforcement_point"] for row in mapping]
    # Every rego file in policies/ must be referenced once.
    rego_dir = _REPO_ROOT / "policies"
    if not rego_dir.is_dir():
        pytest.skip("policies directory not present in test env")
    for rego in rego_dir.glob("*.rego"):
        assert any(rego.name in point for point in enforcement_points), (
            f"control mapping missing reference to {rego.name}"
        )


def test_control_mapping_rows_have_required_fields():
    for row in governance.get_control_mapping():
        assert "enforcement_point" in row
        assert "description" in row
        assert isinstance(row["iso_42001_controls"], list)
        assert row["iso_42001_controls"], "every row needs at least one ISO control"
        assert isinstance(row["nist_ai_rmf"], list)
        for fn in row["nist_ai_rmf"]:
            assert fn in {"govern", "map", "measure", "manage"}


# ── Consent derivation ───────────────────────────────────────────────────────
def test_consent_required_for_confidential():
    assert governance.derive_consent_status("confidential") == "required_and_verified"
    assert governance.derive_consent_status("Restricted") == "required_and_verified"


def test_consent_not_required_for_public_or_none():
    assert governance.derive_consent_status(None) == "not_required"
    assert governance.derive_consent_status("public") == "not_required"
    assert governance.derive_consent_status("internal") == "not_required"


# ── AuditLogger auto-attachment ──────────────────────────────────────────────
def test_audit_event_auto_attaches_governance_reference():
    auditor = AuditLogger(
        run_id="r-1", agent_type="data-analyst", correlation_id="c-1"
    )
    event = auditor.log(ActionType.OPENAI_CALL)
    assert event.governance_metadata_ref is not None
    assert event.governance_metadata_ref.startswith("data-analyst@")


def test_audit_event_consent_derived_from_classification():
    auditor = AuditLogger(
        run_id="r-2", agent_type="data-analyst", correlation_id="c-2"
    )
    confidential_event = auditor.log(
        ActionType.FILE_READ, classification_label="confidential"
    )
    assert confidential_event.consent_status == "required_and_verified"

    public_event = auditor.log(ActionType.FILE_READ, classification_label="public")
    assert public_event.consent_status == "not_required"


def test_audit_event_explicit_overrides_win():
    auditor = AuditLogger(
        run_id="r-3", agent_type="data-analyst", correlation_id="c-3"
    )
    event = auditor.log(
        ActionType.FILE_READ,
        classification_label="confidential",
        consent_status="explicit_override",
        governance_metadata_ref="custom-ref",
    )
    assert event.consent_status == "explicit_override"
    assert event.governance_metadata_ref == "custom-ref"


def test_governance_reference_skipped_for_control_plane_agent():
    auditor = AuditLogger(
        run_id="r-4", agent_type="control-plane", correlation_id="c-4"
    )
    event = auditor.log(ActionType.OPENAI_CALL)
    assert event.governance_metadata_ref is None


# ── Attestation ──────────────────────────────────────────────────────────────
def test_attestation_round_trip():
    att = governance.build_run_attestation(
        run_id="run-xyz",
        agent_type="data-analyst",
        signing_secret="secret-A",
    )
    assert governance.verify_run_attestation(att, signing_secret="secret-A") is True
    # Different secret must fail.
    assert governance.verify_run_attestation(att, signing_secret="secret-B") is False


def test_attestation_signature_tamper_detected():
    att = governance.build_run_attestation(
        run_id="run-xyz",
        agent_type="data-analyst",
        signing_secret="secret-A",
    )
    att["payload"]["run_id"] = "run-evil"
    assert governance.verify_run_attestation(att, signing_secret="secret-A") is False


def test_attestation_includes_policy_bundle_hash_and_model_card_version():
    att = governance.build_run_attestation(
        run_id="run-1",
        agent_type="web-researcher",
        signing_secret="secret-A",
    )
    payload = att["payload"]
    assert payload["agent_type"] == "web-researcher"
    assert payload["model_card"]["version"]
    assert payload["policy_bundle_hash"]
    assert payload["control_mapping_count"] >= 1
    assert "capabilities" in payload
    assert payload["capabilities"]["delegation_allowed"] is True


def test_attestation_requires_known_agent_type():
    with pytest.raises(ValueError):
        governance.build_run_attestation(
            run_id="r", agent_type="ghost", signing_secret="x"
        )


def test_attestation_requires_signing_secret(monkeypatch):
    # Clear env fallback to force fail.
    monkeypatch.delenv("APIM_IDENTITY_SIGNING_SECRET", raising=False)
    with pytest.raises(ValueError):
        governance.build_run_attestation(
            run_id="r", agent_type="data-analyst", signing_secret=""
        )


# ── Policy bundle hash stability ─────────────────────────────────────────────
def test_policy_bundle_hash_is_stable_and_hex():
    h1 = governance.get_policy_bundle_hash()
    h2 = governance.get_policy_bundle_hash()
    assert h1 == h2
    assert h1 == "no-bundle" or len(h1) == 64


# ── Compliance routes ────────────────────────────────────────────────────────
def _admin_headers(monkeypatch):
    import time

    import main as main_module

    monkeypatch.setattr(main_module, "ENABLE_APP_AUTHZ", True)
    monkeypatch.setattr(main_module, "REQUIRE_IDENTITY_SIGNATURE", True)
    monkeypatch.setattr(
        main_module, "APIM_IDENTITY_SIGNING_SECRET", "unit-test-signing-secret"
    )
    monkeypatch.setattr(main_module._kill_switch, "check", lambda *a, **k: None)

    timestamp = str(int(time.time()))
    signature = main_module._compute_identity_signature(
        subject="admin-user",
        tenant_id="tenant-a",
        roles="Sandbox.Admin",
        scopes="",
        timestamp=timestamp,
        secret="unit-test-signing-secret",
    )
    return {
        "X-Auth-Subject": "admin-user",
        "X-Auth-Tenant-Id": "tenant-a",
        "X-Auth-Timestamp": timestamp,
        "X-Auth-Signature": signature,
        "X-Auth-Roles": "Sandbox.Admin",
    }


def test_list_model_cards_route(monkeypatch):
    from fastapi.testclient import TestClient

    import main as main_module

    headers = _admin_headers(monkeypatch)
    with TestClient(main_module.app) as client:
        resp = client.get("/compliance/model-cards", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert "data-analyst" in body["agent_types"]
    assert "web-researcher" in body["agent_types"]


def test_get_model_card_route_404_for_unknown(monkeypatch):
    from fastapi.testclient import TestClient

    import main as main_module

    headers = _admin_headers(monkeypatch)
    with TestClient(main_module.app) as client:
        resp = client.get(
            "/compliance/model-cards/does-not-exist", headers=headers
        )
    assert resp.status_code == 404


def test_get_model_card_route_returns_card(monkeypatch):
    from fastapi.testclient import TestClient

    import main as main_module

    headers = _admin_headers(monkeypatch)
    with TestClient(main_module.app) as client:
        resp = client.get("/compliance/model-cards/data-analyst", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["agent_type"] == "data-analyst"
    assert body["iso_42001_controls"]


def test_control_mapping_route(monkeypatch):
    from fastapi.testclient import TestClient

    import main as main_module

    headers = _admin_headers(monkeypatch)
    with TestClient(main_module.app) as client:
        resp = client.get("/compliance/control-mapping", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["schema"].startswith("ai-security-sandbox.control-mapping")
    assert len(body["controls"]) >= 1


def test_attestation_route_404_for_unknown_run(monkeypatch):
    from fastapi.testclient import TestClient

    import main as main_module

    headers = _admin_headers(monkeypatch)
    with TestClient(main_module.app) as client:
        resp = client.get("/compliance/attestation/no-such-run", headers=headers)
    assert resp.status_code == 404


def test_model_cards_route_requires_admin(monkeypatch):
    from fastapi.testclient import TestClient

    import main as main_module
    import time

    # Non-admin: same envelope but no Sandbox.Admin role.
    monkeypatch.setattr(main_module, "ENABLE_APP_AUTHZ", True)
    monkeypatch.setattr(main_module, "REQUIRE_IDENTITY_SIGNATURE", True)
    monkeypatch.setattr(
        main_module, "APIM_IDENTITY_SIGNING_SECRET", "unit-test-signing-secret"
    )
    monkeypatch.setattr(main_module._kill_switch, "check", lambda *a, **k: None)

    timestamp = str(int(time.time()))
    signature = main_module._compute_identity_signature(
        subject="user-a",
        tenant_id="tenant-a",
        roles="",
        scopes="",
        timestamp=timestamp,
        secret="unit-test-signing-secret",
    )
    headers = {
        "X-Auth-Subject": "user-a",
        "X-Auth-Tenant-Id": "tenant-a",
        "X-Auth-Timestamp": timestamp,
        "X-Auth-Signature": signature,
    }
    with TestClient(main_module.app) as client:
        resp = client.get("/compliance/control-mapping", headers=headers)
    assert resp.status_code == 403
