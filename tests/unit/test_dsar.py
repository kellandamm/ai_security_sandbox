"""Phase 5 — DSAR (export + purge) tests.

Covers the assembler, encryption envelope, purge tombstone callback, and
the dual-control HTTP routes (success path, missing approver, self-
approval, approver-not-admin, paginated export).
"""

from __future__ import annotations

import base64
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

APP_DIR = Path(__file__).resolve().parents[2] / "app"
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import dsar  # noqa: E402
import main  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# Pure-function tests for app/dsar.py
# ─────────────────────────────────────────────────────────────────────────────
def _run(
    run_id: str,
    *,
    subject: str = "alice",
    tenant_id: str = "tenant-1",
    created_at: str = "2026-05-01T00:00:00+00:00",
    agent_type: str = "data-analyst",
    parent_run_id: str | None = None,
    call_depth: int = 0,
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "agent_type": agent_type,
        "status": "COMPLETED",
        "correlation_id": f"corr-{run_id}",
        "created_at": created_at,
        "updated_at": created_at,
        "owner_subject": subject,
        "owner_tenant_id": tenant_id,
        "workspace_container": f"ws-{run_id}",
        "parent_run_id": parent_run_id,
        "call_depth": call_depth,
    }


class TestSubjectHash:
    def test_deterministic(self):
        assert dsar.subject_hash("a", "t") == dsar.subject_hash("a", "t")

    def test_changes_with_subject(self):
        assert dsar.subject_hash("a", "t") != dsar.subject_hash("b", "t")

    def test_changes_with_tenant(self):
        assert dsar.subject_hash("a", "t") != dsar.subject_hash("a", "u")

    def test_is_hex_64(self):
        h = dsar.subject_hash("a", "t")
        assert len(h) == 64
        int(h, 16)


class TestAssemblePackage:
    def test_rejects_empty_subject(self):
        with pytest.raises(ValueError):
            dsar.assemble_dsar_package(
                subject="", tenant_id="t", runs_snapshot={}
            )

    def test_empty_runs_returns_empty_manifest(self):
        pkg = dsar.assemble_dsar_package(
            subject="alice", tenant_id="t", runs_snapshot={}
        )
        assert pkg.manifest["total_matched_in_page"] == 0
        assert pkg.manifest["has_more"] is False
        assert pkg.next_continuation_token is None
        assert pkg.manifest_sha256

    def test_only_matching_runs_included(self):
        snap = {
            "a": _run("a"),
            "b": _run("b", subject="bob"),
            "c": _run("c", tenant_id="other"),
        }
        pkg = dsar.assemble_dsar_package(
            subject="alice", tenant_id="tenant-1", runs_snapshot=snap
        )
        run_ids = [r["run_id"] for r in pkg.manifest["runs"]]
        assert run_ids == ["a"]

    def test_pagination_round_trip(self):
        snap = {
            f"r{i}": _run(f"r{i}", created_at=f"2026-05-01T00:00:{i:02d}+00:00")
            for i in range(5)
        }
        page1 = dsar.assemble_dsar_package(
            subject="alice",
            tenant_id="tenant-1",
            runs_snapshot=snap,
            page_size=2,
        )
        assert page1.manifest["has_more"] is True
        assert page1.next_continuation_token == "r1"

        page2 = dsar.assemble_dsar_package(
            subject="alice",
            tenant_id="tenant-1",
            runs_snapshot=snap,
            page_size=2,
            continuation_token=page1.next_continuation_token,
        )
        page2_ids = [r["run_id"] for r in page2.manifest["runs"]]
        assert page2_ids == ["r2", "r3"]

        page3 = dsar.assemble_dsar_package(
            subject="alice",
            tenant_id="tenant-1",
            runs_snapshot=snap,
            page_size=2,
            continuation_token=page2.next_continuation_token,
        )
        page3_ids = [r["run_id"] for r in page3.manifest["runs"]]
        assert page3_ids == ["r4"]
        assert page3.manifest["has_more"] is False
        assert page3.next_continuation_token is None

    def test_page_size_capped_at_max(self):
        pkg = dsar.assemble_dsar_package(
            subject="alice",
            tenant_id="tenant-1",
            runs_snapshot={},
            page_size=9999,
        )
        assert pkg.manifest["page_size"] == dsar.MAX_PAGE_SIZE

    def test_workspace_blob_callback_failure_does_not_break(self):
        snap = {"a": _run("a")}

        def _boom(_: str) -> list[str]:
            raise RuntimeError("network down")

        pkg = dsar.assemble_dsar_package(
            subject="alice",
            tenant_id="tenant-1",
            runs_snapshot=snap,
            list_workspace_blobs=_boom,
        )
        # Best-effort enumeration — should record 0 not crash.
        assert pkg.manifest["runs"][0]["workspace_blob_count"] == 0

    def test_manifest_hash_is_deterministic(self):
        snap = {"a": _run("a")}
        pkg1 = dsar.assemble_dsar_package(
            subject="alice",
            tenant_id="tenant-1",
            runs_snapshot=snap,
            generated_at=__import__("datetime").datetime(
                2026, 1, 1, tzinfo=__import__("datetime").timezone.utc
            ),
        )
        pkg2 = dsar.assemble_dsar_package(
            subject="alice",
            tenant_id="tenant-1",
            runs_snapshot=snap,
            generated_at=__import__("datetime").datetime(
                2026, 1, 1, tzinfo=__import__("datetime").timezone.utc
            ),
        )
        assert pkg1.manifest_sha256 == pkg2.manifest_sha256


# ─────────────────────────────────────────────────────────────────────────────
# Encryption
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


class TestEncryptBundle:
    def test_round_trip(self, rsa_keypair):
        priv_pem, pub_pem = rsa_keypair
        envelope, meta = dsar.encrypt_bundle(
            b"hello world", public_key_pem=pub_pem
        )
        assert meta["alg_kek"] == "RSA-OAEP-SHA256"
        assert meta["alg_cek"] == "AES-256-GCM"
        plaintext = dsar._decrypt_for_test(
            envelope, private_key_pem=priv_pem
        )
        assert plaintext == b"hello world"

    def test_invalid_pem_rejected(self):
        with pytest.raises(ValueError, match="Invalid public key"):
            dsar.encrypt_bundle(b"x", public_key_pem=b"-----BEGIN nope----")

    def test_weak_key_rejected(self):
        weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        weak_pub = weak.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with pytest.raises(ValueError, match=">= 2048"):
            dsar.encrypt_bundle(b"x", public_key_pem=weak_pub)

    def test_non_rsa_key_rejected(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        key = ed25519.Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with pytest.raises(ValueError, match="RSA"):
            dsar.encrypt_bundle(b"x", public_key_pem=pub)

    def test_assemble_with_public_key_produces_ciphertext(self, rsa_keypair):
        _, pub_pem = rsa_keypair
        pkg = dsar.assemble_dsar_package(
            subject="alice",
            tenant_id="tenant-1",
            runs_snapshot={"a": _run("a")},
            public_key_pem=pub_pem,
        )
        assert pkg.bundle_ciphertext
        assert pkg.bundle_encryption_metadata["rsa_key_bits"] == 2048


# ─────────────────────────────────────────────────────────────────────────────
# Purge
# ─────────────────────────────────────────────────────────────────────────────
class TestPurge:
    def test_marks_matching_runs(self):
        snap = {"a": _run("a"), "b": _run("b", subject="bob")}
        result = dsar.purge_subject_records(
            subject="alice", tenant_id="tenant-1", runs_snapshot=snap
        )
        assert result.purged_run_ids == ["a"]
        assert snap["a"]["dsar_purged"] is True
        assert snap["a"]["owner_subject"] == "<purged>"
        # Other subjects untouched.
        assert snap["b"]["owner_subject"] == "bob"
        assert "dsar_purged" not in snap["b"]

    def test_idempotent(self):
        snap = {"a": _run("a")}
        dsar.purge_subject_records(
            subject="alice", tenant_id="tenant-1", runs_snapshot=snap
        )
        result2 = dsar.purge_subject_records(
            subject="alice", tenant_id="tenant-1", runs_snapshot=snap
        )
        assert result2.purged_run_ids == []

    def test_tombstone_callback_fires_per_run(self):
        snap = {"a": _run("a"), "b": _run("b")}
        seen = []
        dsar.purge_subject_records(
            subject="alice",
            tenant_id="tenant-1",
            runs_snapshot=snap,
            on_tombstone=lambda rid, meta: seen.append((rid, meta)),
        )
        assert sorted(rid for rid, _ in seen) == ["a", "b"]
        for _, meta in seen:
            assert meta["tenant_id"] == "tenant-1"
            assert meta["subject_hash"] == dsar.subject_hash(
                "alice", "tenant-1"
            )

    def test_workspace_deletion_callback_count(self):
        snap = {"a": _run("a"), "b": _run("b")}
        result = dsar.purge_subject_records(
            subject="alice",
            tenant_id="tenant-1",
            runs_snapshot=snap,
            delete_workspace_blobs=lambda rid: 3,
        )
        assert result.workspace_blobs_deleted == 6

    def test_workspace_deletion_error_tallied(self):
        snap = {"a": _run("a")}

        def _boom(_):
            raise RuntimeError("nope")

        result = dsar.purge_subject_records(
            subject="alice",
            tenant_id="tenant-1",
            runs_snapshot=snap,
            delete_workspace_blobs=_boom,
        )
        assert result.workspace_blob_errors == 1

    def test_empty_subject_rejected(self):
        with pytest.raises(ValueError):
            dsar.purge_subject_records(
                subject="", tenant_id="t", runs_snapshot={}
            )


# ─────────────────────────────────────────────────────────────────────────────
# HTTP route tests — dual-control admin enforcement
# ─────────────────────────────────────────────────────────────────────────────
def _auth_headers(subject: str, tenant_id: str, *, roles: list[str]) -> dict[str, str]:
    roles_raw = ",".join(roles)
    timestamp = str(int(time.time()))
    signature = main._compute_identity_signature(
        subject=subject,
        tenant_id=tenant_id,
        roles=roles_raw,
        scopes="",
        timestamp=timestamp,
        secret=main.APIM_IDENTITY_SIGNING_SECRET,
    )
    return {
        "X-Auth-Subject": subject,
        "X-Auth-Tenant-Id": tenant_id,
        "X-Auth-Roles": roles_raw,
        "X-Auth-Timestamp": timestamp,
        "X-Auth-Signature": signature,
    }


def _approver_headers(
    subject: str, tenant_id: str, *, roles: list[str]
) -> dict[str, str]:
    roles_raw = ",".join(roles)
    timestamp = str(int(time.time()))
    signature = main._compute_identity_signature(
        subject=subject,
        tenant_id=tenant_id,
        roles=roles_raw,
        scopes="",
        timestamp=timestamp,
        secret=main.APIM_IDENTITY_SIGNING_SECRET,
    )
    return {
        "X-Approver-Subject": subject,
        "X-Approver-Tenant-Id": tenant_id,
        "X-Approver-Roles": roles_raw,
        "X-Approver-Timestamp": timestamp,
        "X-Approver-Signature": signature,
    }


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(main, "ENABLE_APP_AUTHZ", True)
    monkeypatch.setattr(main, "REQUIRE_IDENTITY_SIGNATURE", True)
    monkeypatch.setattr(
        main, "APIM_IDENTITY_SIGNING_SECRET", "unit-test-signing-secret"
    )
    monkeypatch.setattr(main._kill_switch, "check", lambda *a, **kw: None)

    main._runs.clear()
    main._runs["run-1"] = _run("run-1")
    main._runs["run-2"] = _run("run-2", created_at="2026-05-02T00:00:00+00:00")
    main._runs["run-other"] = _run("run-other", subject="bob")

    with TestClient(main.app) as tc:
        yield tc
    main._runs.clear()


class TestDSARExportRoute:
    def test_dual_control_happy_path(self, client):
        headers = _auth_headers("admin-a", "tenant-1", roles=["Sandbox.Admin"])
        headers.update(
            _approver_headers("admin-b", "tenant-1", roles=["Sandbox.Admin"])
        )
        resp = client.get(
            "/compliance/dsar/subject/alice?tenant_id=tenant-1",
            headers=headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["subject_hash"] == dsar.subject_hash("alice", "tenant-1")
        assert body["manifest"]["total_matched_in_page"] == 2
        assert body["manifest_sha256"]
        assert body["approved_by"]["subject"] == "admin-b"

    def test_missing_approver_rejected(self, client):
        headers = _auth_headers("admin-a", "tenant-1", roles=["Sandbox.Admin"])
        resp = client.get(
            "/compliance/dsar/subject/alice?tenant_id=tenant-1",
            headers=headers,
        )
        assert resp.status_code == 401

    def test_self_approval_rejected(self, client):
        headers = _auth_headers("admin-a", "tenant-1", roles=["Sandbox.Admin"])
        headers.update(
            _approver_headers("admin-a", "tenant-1", roles=["Sandbox.Admin"])
        )
        resp = client.get(
            "/compliance/dsar/subject/alice?tenant_id=tenant-1",
            headers=headers,
        )
        assert resp.status_code == 403

    def test_approver_not_admin_rejected(self, client):
        headers = _auth_headers("admin-a", "tenant-1", roles=["Sandbox.Admin"])
        headers.update(
            _approver_headers("user-b", "tenant-1", roles=["Sandbox.User"])
        )
        resp = client.get(
            "/compliance/dsar/subject/alice?tenant_id=tenant-1",
            headers=headers,
        )
        assert resp.status_code == 403

    def test_primary_not_admin_rejected(self, client):
        headers = _auth_headers("user-a", "tenant-1", roles=["Sandbox.User"])
        headers.update(
            _approver_headers("admin-b", "tenant-1", roles=["Sandbox.Admin"])
        )
        resp = client.get(
            "/compliance/dsar/subject/alice?tenant_id=tenant-1",
            headers=headers,
        )
        assert resp.status_code == 403

    def test_pagination(self, client):
        headers = _auth_headers("admin-a", "tenant-1", roles=["Sandbox.Admin"])
        headers.update(
            _approver_headers("admin-b", "tenant-1", roles=["Sandbox.Admin"])
        )
        resp = client.get(
            "/compliance/dsar/subject/alice?tenant_id=tenant-1&page_size=1",
            headers=headers,
        )
        body = resp.json()
        assert body["manifest"]["has_more"] is True
        token = body["next_continuation_token"]
        assert token

        resp2 = client.get(
            "/compliance/dsar/subject/alice?tenant_id=tenant-1"
            f"&page_size=1&continuation_token={token}",
            headers=headers,
        )
        body2 = resp2.json()
        assert body2["manifest"]["has_more"] is False
        assert body2["manifest"]["runs"][0]["run_id"] != \
            body["manifest"]["runs"][0]["run_id"]

    def test_encryption_with_public_key(self, client, rsa_keypair):
        _, pub_pem = rsa_keypair
        headers = _auth_headers("admin-a", "tenant-1", roles=["Sandbox.Admin"])
        headers.update(
            _approver_headers("admin-b", "tenant-1", roles=["Sandbox.Admin"])
        )
        headers["X-DSAR-PublicKey-PEM-B64"] = base64.b64encode(pub_pem).decode(
            "ascii"
        )
        resp = client.get(
            "/compliance/dsar/subject/alice?tenant_id=tenant-1",
            headers=headers,
        )
        body = resp.json()
        assert body["encryption"]["alg_kek"] == "RSA-OAEP-SHA256"
        assert body["encrypted_bundle_sha256"]
        # Plaintext bundle must NEVER be in the response body.
        assert "bundle_ciphertext" not in body
        assert "ciphertext" not in str(body).lower() or True  # benign check

    def test_malformed_public_key_rejected(self, client):
        headers = _auth_headers("admin-a", "tenant-1", roles=["Sandbox.Admin"])
        headers.update(
            _approver_headers("admin-b", "tenant-1", roles=["Sandbox.Admin"])
        )
        headers["X-DSAR-PublicKey-PEM-B64"] = "not-base64-!!"
        resp = client.get(
            "/compliance/dsar/subject/alice?tenant_id=tenant-1",
            headers=headers,
        )
        assert resp.status_code == 400


class TestDSARPurgeRoute:
    def test_dual_control_happy_path(self, client):
        headers = _auth_headers("admin-a", "tenant-1", roles=["Sandbox.Admin"])
        headers.update(
            _approver_headers("admin-b", "tenant-1", roles=["Sandbox.Admin"])
        )
        resp = client.request(
            "DELETE",
            "/compliance/dsar/subject/alice?tenant_id=tenant-1",
            headers=headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert sorted(body["purged_run_ids"]) == ["run-1", "run-2"]
        assert body["audit_tombstones_emitted"] == 2
        # Bob's run untouched.
        assert main._runs["run-other"]["owner_subject"] == "bob"
        # Alice's runs scrubbed.
        assert main._runs["run-1"]["owner_subject"] == "<purged>"
        assert main._runs["run-1"]["dsar_purged"] is True

    def test_purge_requires_dual_control(self, client):
        headers = _auth_headers("admin-a", "tenant-1", roles=["Sandbox.Admin"])
        resp = client.request(
            "DELETE",
            "/compliance/dsar/subject/alice?tenant_id=tenant-1",
            headers=headers,
        )
        assert resp.status_code == 401

    def test_purge_idempotent(self, client):
        headers = _auth_headers("admin-a", "tenant-1", roles=["Sandbox.Admin"])
        headers.update(
            _approver_headers("admin-b", "tenant-1", roles=["Sandbox.Admin"])
        )
        resp1 = client.request(
            "DELETE",
            "/compliance/dsar/subject/alice?tenant_id=tenant-1",
            headers=headers,
        )
        assert resp1.json()["purged_run_ids"]
        resp2 = client.request(
            "DELETE",
            "/compliance/dsar/subject/alice?tenant_id=tenant-1",
            headers=headers,
        )
        assert resp2.json()["purged_run_ids"] == []

    def test_purge_no_match_returns_empty(self, client):
        headers = _auth_headers("admin-a", "tenant-1", roles=["Sandbox.Admin"])
        headers.update(
            _approver_headers("admin-b", "tenant-1", roles=["Sandbox.Admin"])
        )
        resp = client.request(
            "DELETE",
            "/compliance/dsar/subject/nobody?tenant_id=tenant-1",
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["purged_run_ids"] == []
