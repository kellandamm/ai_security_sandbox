import os
import sys
import time

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../app"))

import main


class _DummyTask:
    def cancel(self):
        return None

    def done(self):
        return False


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


<<<<<<< HEAD
def _approver_header(
    subject: str, tenant_id: str, roles: list[str] | None = None
) -> dict[str, str]:
    """Build the Phase 5 dual-control approver headers (second admin)."""
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
        "X-Approver-Subject": subject,
        "X-Approver-Tenant-Id": tenant_id,
        "X-Approver-Timestamp": timestamp,
        "X-Approver-Signature": signature,
    }
    if roles:
        headers["X-Approver-Roles"] = roles_raw
    return headers


=======
>>>>>>> origin/main
@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(main, "ENABLE_APP_AUTHZ", True)
    monkeypatch.setattr(main, "REQUIRE_IDENTITY_SIGNATURE", True)
    monkeypatch.setattr(main, "APIM_IDENTITY_SIGNING_SECRET", "unit-test-signing-secret")
    monkeypatch.setattr(main._kill_switch, "check", lambda *args, **kwargs: None)

    main._runs.clear()
    main._run_tasks.clear()
    main._run_event_queues.clear()

    with TestClient(main.app) as test_client:
        yield test_client

    main._runs.clear()
    main._run_tasks.clear()
    main._run_event_queues.clear()


@pytest.fixture
def telemetry_events(monkeypatch: pytest.MonkeyPatch):
    events: list[dict[str, object]] = []

    def _capture(req, **kwargs):
        events.append(kwargs)

    monkeypatch.setattr(main, "_emit_request_audit_event", _capture)
    return events


def _seed_run(run_id: str = "run-1") -> None:
    main._runs[run_id] = {
        "run_id": run_id,
        "status": main.RunStatus.QUEUED,
        "agent_type": "data-analyst",
        "result": None,
        "error": None,
        "created_at": "2026-05-13T00:00:00+00:00",
        "updated_at": "2026-05-13T00:00:00+00:00",
        "correlation_id": "corr-1",
        "owner_subject": "user-a",
        "owner_tenant_id": "tenant-a",
    }


def test_start_run_requires_identity(client: TestClient):
    response = client.post(
        "/runs",
        json={"agent_type": "data-analyst", "task": "hello"},
    )

    assert response.status_code == 401
    assert "Validated identity headers are required" in response.json()["detail"]


def test_start_run_rejects_missing_signature(client: TestClient):
    response = client.post(
        "/runs",
        json={"agent_type": "data-analyst", "task": "hello"},
        headers={
            "X-Auth-Subject": "user-a",
            "X-Auth-Tenant-Id": "tenant-a",
        },
    )

    assert response.status_code == 401


def test_start_run_rejects_tampered_signature(client: TestClient, telemetry_events):
    headers = _auth_header("user-a", "tenant-a")
    headers["X-Auth-Signature"] = "deadbeef"

    response = client.post(
        "/runs",
        json={"agent_type": "data-analyst", "task": "hello"},
        headers=headers,
    )

    assert response.status_code == 401
    assert telemetry_events
    assert telemetry_events[-1]["action_type"] == main.ActionType.SIGNATURE_VERIFICATION_FAILURE
    assert str(telemetry_events[-1]["error_code"]).startswith("AUTHN_FAIL_")


def test_start_run_stamps_owner_identity(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    def _fake_create_task(coro):
        coro.close()
        return _DummyTask()

    monkeypatch.setattr(main.asyncio, "create_task", _fake_create_task)

    response = client.post(
        "/runs",
        json={"agent_type": "data-analyst", "task": "hello"},
        headers=_auth_header("user-a", "tenant-a"),
    )

    assert response.status_code == 202
    run_id = response.json()["run_id"]
    assert main._runs[run_id]["owner_subject"] == "user-a"
    assert main._runs[run_id]["owner_tenant_id"] == "tenant-a"


def test_get_run_denies_non_owner(client: TestClient, telemetry_events):
    _seed_run()

    response = client.get("/runs/run-1", headers=_auth_header("user-b", "tenant-a"))

    assert response.status_code == 404
    assert telemetry_events
    assert telemetry_events[-1]["action_type"] == main.ActionType.CROSS_TENANT_ACCESS_ATTEMPT
    assert telemetry_events[-1]["error_code"] == "AUTHZ_DENY_CROSS_TENANT_ACCESS"


def test_get_run_allows_owner(client: TestClient):
    _seed_run()

    response = client.get("/runs/run-1", headers=_auth_header("user-a", "tenant-a"))

    assert response.status_code == 200
    assert response.json()["run_id"] == "run-1"


def test_get_run_allows_admin(client: TestClient):
    _seed_run()

    response = client.get(
        "/runs/run-1",
        headers=_auth_header("admin-user", "tenant-z", roles=["Sandbox.Admin"]),
    )

    assert response.status_code == 200


def test_toggle_kill_switch_requires_admin(client: TestClient):
    response = client.put(
        "/kill-switches/agent-execution-enabled",
        headers=_auth_header("user-a", "tenant-a"),
        json={"enabled": True},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Admin privileges required"


def test_toggle_kill_switch_allows_admin(client: TestClient, telemetry_events):
    response = client.put(
        "/kill-switches/agent-execution-enabled",
        headers=_auth_header("admin-user", "tenant-a", roles=["Sandbox.Admin"]),
        json={"enabled": True},
    )

    assert response.status_code == 204
    assert telemetry_events
    assert telemetry_events[-1]["action_type"] == main.ActionType.ADMIN_KILL_SWITCH_TOGGLE
    assert str(telemetry_events[-1]["error_code"]).startswith(
        "ADMIN_ACTION_KILL_SWITCH_TOGGLE:"
    )


def test_kill_run_admin_emits_admin_delete_event(
    client: TestClient, telemetry_events
):
    _seed_run(run_id="run-2")

    response = client.request(
        method="DELETE",
        url="/runs/run-2",
        headers=_auth_header("admin-user", "tenant-a", roles=["Sandbox.Admin"]),
        json={"reason": "incident response"},
    )

    assert response.status_code == 204
    assert telemetry_events
    assert telemetry_events[-1]["action_type"] == main.ActionType.ADMIN_RUN_DELETE
    assert str(telemetry_events[-1]["error_code"]).startswith("ADMIN_ACTION_RUN_KILL:")


def test_dsar_export_requires_admin(client: TestClient):
    _seed_run(run_id="run-dsar")
    response = client.get(
        "/compliance/dsar/subject/user-a?tenant_id=tenant-a",
        headers=_auth_header("user-a", "tenant-a"),
    )
    assert response.status_code == 403


def test_dsar_export_returns_matching_subject_runs(client: TestClient, telemetry_events):
    _seed_run(run_id="run-dsar-a")
    _seed_run(run_id="run-dsar-b")
    main._runs["run-dsar-b"]["owner_subject"] = "user-b"

<<<<<<< HEAD
    headers = _auth_header("admin-user", "tenant-a", roles=["Sandbox.Admin"])
    headers.update(
        _approver_header("approver-user", "tenant-a", roles=["Sandbox.Admin"])
    )
    response = client.get(
        "/compliance/dsar/subject/user-a?tenant_id=tenant-a",
        headers=headers,
=======
    response = client.get(
        "/compliance/dsar/subject/user-a?tenant_id=tenant-a",
        headers=_auth_header("admin-user", "tenant-a", roles=["Sandbox.Admin"]),
>>>>>>> origin/main
    )

    assert response.status_code == 200
    payload = response.json()
<<<<<<< HEAD
    # Phase 5 — DSAR response now keys on subject_hash, not raw subject.
    assert payload["subject_hash"] == main.dsar.subject_hash(
        "user-a", "tenant-a"
    )
    assert payload["tenant_id"] == "tenant-a"
    assert payload["manifest"]["total_matched_in_page"] == 1
    assert payload["manifest"]["runs"][0]["run_id"] == "run-dsar-a"
    assert payload["manifest_sha256"]
    assert payload["approved_by"]["subject"] == "approver-user"
=======
    assert payload["subject"] == "user-a"
    assert payload["tenant_id"] == "tenant-a"
    assert payload["run_count"] == 1
    assert payload["runs"][0]["run_id"] == "run-dsar-a"
>>>>>>> origin/main
    assert telemetry_events
    assert telemetry_events[-1]["action_type"] == main.ActionType.ADMIN_DSAR_EXPORT
    assert str(telemetry_events[-1]["error_code"]).startswith("ADMIN_ACTION_DSAR_EXPORT:")
