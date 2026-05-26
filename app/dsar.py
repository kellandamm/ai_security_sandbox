"""Phase 5 — Data Subject Access Request (DSAR) export + purge.

Production-credible GDPR Article 15/17 / CCPA §1798.110 implementation.

Contract:
* **Export** is read-only; the assembler walks a snapshot of runs + their
  audit / workspace artifacts and produces a structured manifest.
* If a caller-supplied PEM public key is provided, the payload bundle is
  encrypted with **RSA-OAEP-SHA256 + AES-GCM (256-bit) hybrid envelope**
  and the plaintext bundle is never returned in the HTTP response — the
  orchestrator only ever surfaces the manifest summary, manifest hash, and
  a one-time SAS URL (resolved in main.py) to the encrypted blob.
* **Purge** is a tombstone operation: WORM audit blobs are *not* mutated
  (regulatory requirement). Instead a `DSAR_PURGE` audit event is emitted
  carrying the subject hash + approver identity + run IDs, and the
  ephemeral workspace blobs (which already get cleaned up at run end) are
  best-effort deleted if they still exist.

All public functions are synchronous and pure over their inputs so they
test cleanly without Azure credentials.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = [
    "DSARManifestEntry",
    "DSARPackage",
    "assemble_dsar_package",
    "compute_manifest_hash",
    "encrypt_bundle",
    "purge_subject_records",
    "subject_hash",
    "MAX_PAGE_SIZE",
    "DEFAULT_PAGE_SIZE",
]

MAX_PAGE_SIZE = 500
DEFAULT_PAGE_SIZE = 100


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class DSARManifestEntry:
    """A single run row in the DSAR manifest."""

    run_id: str
    agent_type: str
    status: str
    correlation_id: str
    created_at: Optional[str]
    updated_at: Optional[str]
    workspace_container: Optional[str]
    workspace_blob_count: int
    audit_blob_uri: Optional[str]
    parent_run_id: Optional[str]
    call_depth: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "agent_type": self.agent_type,
            "status": self.status,
            "correlation_id": self.correlation_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "workspace_container": self.workspace_container,
            "workspace_blob_count": self.workspace_blob_count,
            "audit_blob_uri": self.audit_blob_uri,
            "parent_run_id": self.parent_run_id,
            "call_depth": self.call_depth,
        }


@dataclass(frozen=True)
class DSARPackage:
    """Result of an export call.

    ``bundle_ciphertext`` is non-empty only when a public key was supplied.
    The orchestrator should write it to a one-time-SAS-protected blob; it
    must never be embedded in the HTTP response body verbatim.
    """

    manifest: dict[str, Any]
    manifest_sha256: str
    next_continuation_token: Optional[str]
    bundle_ciphertext: bytes = b""
    bundle_encryption_metadata: Optional[dict[str, Any]] = None


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def subject_hash(subject: str, tenant_id: str) -> str:
    """SHA-256(subject|tenant_id) — used to key audit events without
    leaking the raw subject identifier into log indexes."""
    digest = hashlib.sha256(
        f"{subject}|{tenant_id}".encode("utf-8")
    ).hexdigest()
    return digest


def _canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def compute_manifest_hash(manifest: dict[str, Any]) -> str:
    """Stable SHA-256 over a canonical-JSON serialization of *manifest*."""
    return hashlib.sha256(_canonical_json(manifest)).hexdigest()


def _normalize_page_size(page_size: int) -> int:
    if page_size <= 0:
        return DEFAULT_PAGE_SIZE
    return min(page_size, MAX_PAGE_SIZE)


def _matches_subject(
    run: dict[str, Any], subject: str, tenant_id: str
) -> bool:
    return (
        run.get("owner_subject") == subject
        and run.get("owner_tenant_id") == tenant_id
    )


# ─────────────────────────────────────────────────────────────────────────────
# Assemble
# ─────────────────────────────────────────────────────────────────────────────
def assemble_dsar_package(
    *,
    subject: str,
    tenant_id: str,
    runs_snapshot: dict[str, dict[str, Any]],
    list_workspace_blobs: Callable[[str], list[str]] | None = None,
    audit_blob_uri_for: Callable[[str], Optional[str]] | None = None,
    page_size: int = DEFAULT_PAGE_SIZE,
    continuation_token: Optional[str] = None,
    public_key_pem: Optional[bytes] = None,
    generated_at: Optional[datetime] = None,
) -> DSARPackage:
    """Return a deterministic DSAR package for *subject* in *tenant_id*.

    ``runs_snapshot`` is the in-memory run dict (`_runs`); the assembler
    iterates a stable, sorted view so pagination is repeatable.

    ``list_workspace_blobs(run_id)`` and ``audit_blob_uri_for(run_id)``
    are dependency-injected so the assembler can run without Azure
    credentials (production wires them to BlobServiceClient calls).
    Either callable raising is caught and recorded as a zero-count entry.
    """
    if not subject or not tenant_id:
        raise ValueError("subject and tenant_id are required")

    page_size = _normalize_page_size(page_size)
    when = (generated_at or datetime.now(timezone.utc)).isoformat()

    # Stable ordering — sort by created_at then run_id so consecutive
    # paginated calls give consistent slices.
    matched_runs = sorted(
        (
            run
            for run in runs_snapshot.values()
            if _matches_subject(run, subject, tenant_id)
        ),
        key=lambda r: (r.get("created_at") or "", r.get("run_id") or ""),
    )

    start_index = 0
    if continuation_token:
        # The token is the run_id of the last record we returned previously.
        for idx, run in enumerate(matched_runs):
            if run.get("run_id") == continuation_token:
                start_index = idx + 1
                break

    page_runs = matched_runs[start_index : start_index + page_size]
    has_more = (start_index + page_size) < len(matched_runs)
    next_token = (
        page_runs[-1].get("run_id") if has_more and page_runs else None
    )

    entries: list[DSARManifestEntry] = []
    for run in page_runs:
        run_id = run.get("run_id") or ""
        container_name = run.get("workspace_container")
        blob_count = 0
        if list_workspace_blobs is not None and run_id:
            try:
                blob_count = len(list_workspace_blobs(run_id) or [])
            except Exception:  # noqa: BLE001 — best-effort enumeration
                blob_count = 0

        audit_uri = None
        if audit_blob_uri_for is not None and run_id:
            try:
                audit_uri = audit_blob_uri_for(run_id)
            except Exception:  # noqa: BLE001
                audit_uri = None

        entries.append(
            DSARManifestEntry(
                run_id=run_id,
                agent_type=str(run.get("agent_type") or ""),
                status=str(run.get("status") or ""),
                correlation_id=str(run.get("correlation_id") or ""),
                created_at=run.get("created_at"),
                updated_at=run.get("updated_at"),
                workspace_container=container_name,
                workspace_blob_count=blob_count,
                audit_blob_uri=audit_uri,
                parent_run_id=run.get("parent_run_id"),
                call_depth=int(run.get("call_depth") or 0),
            )
        )

    manifest: dict[str, Any] = {
        "subject_hash": subject_hash(subject, tenant_id),
        "tenant_id": tenant_id,
        "generated_at": when,
        "page_size": page_size,
        "continuation_token_in": continuation_token,
        "continuation_token_out": next_token,
        "has_more": has_more,
        "total_matched_in_page": len(entries),
        "runs": [e.to_dict() for e in entries],
        "schema_version": 1,
    }
    digest = compute_manifest_hash(manifest)

    ciphertext = b""
    encryption_metadata: Optional[dict[str, Any]] = None
    if public_key_pem:
        ciphertext, encryption_metadata = encrypt_bundle(
            _canonical_json(manifest),
            public_key_pem=public_key_pem,
        )

    return DSARPackage(
        manifest=manifest,
        manifest_sha256=digest,
        next_continuation_token=next_token,
        bundle_ciphertext=ciphertext,
        bundle_encryption_metadata=encryption_metadata,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Encryption
# ─────────────────────────────────────────────────────────────────────────────
_MIN_RSA_KEY_BITS = 2048


def encrypt_bundle(
    plaintext: bytes, *, public_key_pem: bytes
) -> tuple[bytes, dict[str, Any]]:
    """Hybrid encrypt *plaintext* using RSA-OAEP-SHA256 (CEK wrap) +
    AES-GCM (data). Returns (ciphertext_envelope_bytes, metadata).

    The returned envelope is a canonical-JSON blob with base64 fields, so
    consumers can decrypt with a vanilla `cryptography` install without
    further format negotiation.

    Fail-closed: a too-short key, a wrong key type, or invalid PEM raises
    ``ValueError`` — callers must surface that to the operator rather
    than fall back to plaintext.
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"Invalid public key PEM: {exc}") from exc

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("DSAR bundle encryption requires an RSA public key")
    if public_key.key_size < _MIN_RSA_KEY_BITS:
        raise ValueError(
            f"RSA key size must be >= {_MIN_RSA_KEY_BITS} bits"
        )

    cek = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(cek)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=b"dsar-v1")

    wrapped_cek = public_key.encrypt(
        cek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    import base64

    envelope = {
        "version": "dsar-bundle/1",
        "alg_kek": "RSA-OAEP-SHA256",
        "alg_cek": "AES-256-GCM",
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "wrapped_cek_b64": base64.b64encode(wrapped_cek).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ct).decode("ascii"),
        "aad": "dsar-v1",
    }
    return _canonical_json(envelope), {
        "alg_kek": envelope["alg_kek"],
        "alg_cek": envelope["alg_cek"],
        "rsa_key_bits": public_key.key_size,
        "plaintext_bytes": len(plaintext),
        "ciphertext_bytes": len(envelope["ciphertext_b64"]),
    }


def _decrypt_for_test(
    envelope_bytes: bytes, *, private_key_pem: bytes
) -> bytes:
    """Test-only counterpart to :func:`encrypt_bundle`. Not exported."""
    import base64

    envelope = json.loads(envelope_bytes.decode("utf-8"))
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None
    )
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Expected RSA private key for DSAR decryption")
    wrapped = base64.b64decode(envelope["wrapped_cek_b64"])
    cek = private_key.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    aesgcm = AESGCM(cek)
    return aesgcm.decrypt(
        base64.b64decode(envelope["nonce_b64"]),
        base64.b64decode(envelope["ciphertext_b64"]),
        associated_data=envelope.get("aad", "").encode("utf-8") or None,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Purge
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class PurgeResult:
    purged_run_ids: list[str] = field(default_factory=list)
    workspace_blobs_deleted: int = 0
    workspace_blob_errors: int = 0
    audit_tombstones_emitted: int = 0


def purge_subject_records(
    *,
    subject: str,
    tenant_id: str,
    runs_snapshot: dict[str, dict[str, Any]],
    delete_workspace_blobs: Callable[[str], int] | None = None,
    on_tombstone: Callable[[str, dict[str, Any]], None] | None = None,
    now: Optional[datetime] = None,
) -> PurgeResult:
    """Mark all runs owned by *(subject, tenant_id)* as purged in
    *runs_snapshot* (idempotent — already-purged runs are skipped) and
    invoke the supplied callbacks for each.

    WORM audit blobs are intentionally **not** rewritten — instead the
    caller emits ``DSAR_PURGE`` events that downstream SIEM rules use to
    suppress search results for the subject. ``on_tombstone`` receives
    ``(run_id, metadata)`` per purged run for that purpose.
    """
    if not subject or not tenant_id:
        raise ValueError("subject and tenant_id are required")

    result = PurgeResult()
    when = (now or datetime.now(timezone.utc)).isoformat()
    s_hash = subject_hash(subject, tenant_id)

    for run_id, run in list(runs_snapshot.items()):
        if not _matches_subject(run, subject, tenant_id):
            continue
        if run.get("purged_at"):
            continue

        if delete_workspace_blobs is not None:
            try:
                count = int(delete_workspace_blobs(run_id) or 0)
                result.workspace_blobs_deleted += count
            except Exception:  # noqa: BLE001 — best-effort
                result.workspace_blob_errors += 1

        run["purged_at"] = when
        run["subject_hash"] = s_hash
        run["dsar_purged"] = True
        # Scrub PII fields, retain operational metadata for audit.
        run["owner_subject"] = "<purged>"
        result.purged_run_ids.append(run_id)

        if on_tombstone is not None:
            try:
                on_tombstone(
                    run_id,
                    {
                        "subject_hash": s_hash,
                        "tenant_id": tenant_id,
                        "purged_at": when,
                        "agent_type": run.get("agent_type"),
                        "correlation_id": run.get("correlation_id"),
                    },
                )
                result.audit_tombstones_emitted += 1
            except Exception:  # noqa: BLE001
                # Audit failure must never crash the purge — the tombstone
                # callback's own logging will surface it.
                pass

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Convenience for main.py — read env/config defaults
# ─────────────────────────────────────────────────────────────────────────────
def default_audit_blob_uri(audit_storage_account: str, run_id: str) -> str:
    """Build the canonical audit blob URI under the audit storage account.

    Matches the layout used by :class:`audit.AuditLogger` (``audit-logs``
    container, one append blob per run).
    """
    account = audit_storage_account or os.environ.get(
        "AUDIT_STORAGE_ACCOUNT", ""
    )
    if not account or not run_id:
        return ""
    return (
        f"https://{account}.blob.core.windows.net"
        f"/audit-logs/{run_id}.jsonl"
    )


def iter_run_ids_for_subject(
    runs_snapshot: dict[str, dict[str, Any]],
    *,
    subject: str,
    tenant_id: str,
) -> Iterable[str]:
    for run_id, run in runs_snapshot.items():
        if _matches_subject(run, subject, tenant_id):
            yield run_id
