import os
import sys
import time

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../app"))

import main


def _auth_header(subject: str, tenant_id: str, roles: list[str] | None = None) -> dict[str, str]:
    roles_raw = ",".join(roles) if roles else ""
    scopes_raw = ""
    timestamp = str(int(time.time()))
    signature = main._compute_identity_signature(
        subject=subject,
        tenant_id=tenant_id,
        roles=roles_raw,
        scopes=scopes_raw,
        timestamp=timestamp,
        secret=main.APIM_IDENTITY_SIGNING_SECRET,
    )
    headers = {
        "X-Auth-Subject": subject,
        "X-Auth-Tenant-Id": tenant_id,
        "X-Auth-Timestamp": timestamp,
        "X-Auth-Signature": signature,
    }
    if roles:
        headers["X-Auth-Roles"] = roles_raw
    return headers


def test_compliance_reporting_queries_requires_admin(monkeypatch):
    monkeypatch.setattr(main, "ENABLE_APP_AUTHZ", True)
    monkeypatch.setattr(main, "REQUIRE_IDENTITY_SIGNATURE", True)
    monkeypatch.setattr(main, "APIM_IDENTITY_SIGNING_SECRET", "unit-test-signing-secret")
    monkeypatch.setattr(main._kill_switch, "check", lambda *args, **kwargs: None)

    with TestClient(main.app) as client:
        response = client.get(
            "/compliance/reporting/queries",
            headers=_auth_header("user-a", "tenant-a"),
        )

    assert response.status_code == 403


def test_compliance_reporting_queries_returns_pack_for_admin(monkeypatch):
    monkeypatch.setattr(main, "ENABLE_APP_AUTHZ", True)
    monkeypatch.setattr(main, "REQUIRE_IDENTITY_SIGNATURE", True)
    monkeypatch.setattr(main, "APIM_IDENTITY_SIGNING_SECRET", "unit-test-signing-secret")
    monkeypatch.setattr(main._kill_switch, "check", lambda *args, **kwargs: None)

    with TestClient(main.app) as client:
        response = client.get(
            "/compliance/reporting/queries",
            headers=_auth_header("admin-user", "tenant-a", roles=["Sandbox.Admin"]),
        )

    assert response.status_code == 200
    payload = response.json()
    assert "queries" in payload
    assert "processing_basis" in payload["queries"]
    assert "classification_posture" in payload["queries"]
    assert "dsar_exports" in payload["queries"]
