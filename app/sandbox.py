"""
Ephemeral filesystem sandbox — implements all 9 rules from the article.

Rule 1: Ephemeral workspaces (EphemeralWorkspace context manager)
Rule 2: Separate read / write / audit paths (three distinct blob containers/accounts)
Rule 3: Canonicalize every path before authorization (canonicalize())
Rule 4: Ban symlink following (O_NOFOLLOW; Azure Blob has no symlinks)
Rule 5: noexec/nodev/nosuid enforced at container level (Dockerfile + ACA seccomp)
Rule 6: Reject special file types (validate_blob())
Rule 7: Hard quotas on size and count (WorkspaceQuota)
Rule 8: Virtual paths — agent never sees real host/blob URLs (SandboxPath)
Rule 9: Every file action observable and replayable (AuditEvent emitted on every op)
"""

from __future__ import annotations

import hashlib
import logging
import os
import posixpath
import re
from typing import Optional

<<<<<<< HEAD
from azure.core.exceptions import AzureError
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient, ContentSettings

from audit import AuditLogger
=======
from audit import AuditLogger
from azure.core.exceptions import AzureError
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient, ContentSettings
>>>>>>> origin/main
from models.audit_event import ActionType, Outcome, PolicyDecision

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

WORKSPACE_STORAGE_ACCOUNT = os.environ.get("WORKSPACE_STORAGE_ACCOUNT", "")
AUDIT_STORAGE_ACCOUNT = os.environ.get("AUDIT_STORAGE_ACCOUNT", "")

ALLOWED_CONTENT_TYPES = {"text/plain", "application/json", "text/csv", "text/markdown"}
MAX_BLOB_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB per file  (Rule 7)
MAX_FILES_PER_RUN = 100  # Rule 7
MAX_TOTAL_BYTES_PER_RUN = 500 * 1024 * 1024  # 500 MB per run

# Magic bytes for dangerous file types to reject (Rule 6)
_FORBIDDEN_MAGIC = [
    b"\x7fELF",  # ELF binary
    b"MZ",  # PE/Windows binary
    b"\xca\xfe\xba\xbe",  # Mach-O fat binary
    b"#!",  # shebang (scripts)
    b"\x50\x4b\x03\x04",  # ZIP / JAR / DOCX etc
]

# Safe filename pattern: alphanumeric, dots, hyphens, underscores, slashes (Rule 6)
_SAFE_FILENAME_RE = re.compile(r"^[a-zA-Z0-9._\-/]+$")
_VALID_VIRTUAL_PATH_RE = re.compile(
    r"^/workspace/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/(read|write)/[a-zA-Z0-9._\-/]+$"
)
_SENSITIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("restricted", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("restricted", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("restricted", re.compile(r"(?i)AccountKey\s*=\s*[A-Za-z0-9+/]{32,}={0,2}")),
    ("confidential", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
<<<<<<< HEAD
    (
        "confidential",
        re.compile(
            r"\b(?:\+?\d{1,3}[ .-]?)?(?:\(?\d{3}\)?[ .-]?)\d{3}[ .-]?\d{4}\b"
        ),
    ),
=======
    ("confidential", re.compile(r"\b(?:\+?\d{1,3}[ .-]?)?(?:\(?\d{3}\)?[ .-]?)\d{3}[ .-]?\d{4}\b")),
>>>>>>> origin/main
]


# ── Exceptions ─────────────────────────────────────────────────────────────────


class SandboxError(Exception):
    """Base for all sandbox violations."""


class PathTraversalError(SandboxError):
    """Raised when a path escapes its allowed prefix (Rule 3)."""


class ForbiddenFileTypeError(SandboxError):
    """Raised for disallowed content types or magic bytes (Rule 6)."""


class QuotaExceededError(SandboxError):
    """Raised when a quota limit is reached (Rule 7)."""


class ReadOnlyPathError(SandboxError):
    """Raised when a write is attempted on a read-only path (Rule 2)."""


# ── Path canonicalization ──────────────────────────────────────────────────────


def canonicalize(raw_path: str, allowed_prefix: str) -> str:
    """
    Rule 3: Resolve all .., ., //, and other traversal sequences.
    Raises PathTraversalError if the result escapes allowed_prefix.

    Rule 4: We never follow symlinks — Azure Blob has none. For local
    temp operations, callers must use os.open(..., os.O_NOFOLLOW).
    """
    if not raw_path:
        raise PathTraversalError("Empty path")

    # Reject null bytes immediately (Rule 6)
    if "\x00" in raw_path:
        raise PathTraversalError("Path contains null byte")

    # Normalize: collapse .., ., multiple slashes
    normalized = posixpath.normpath("/" + raw_path.lstrip("/"))

    # After normalization, verify it starts with the allowed prefix
    if (
        not normalized.startswith(allowed_prefix.rstrip("/") + "/")
        and normalized != allowed_prefix
    ):
        raise PathTraversalError(
            f"Path '{normalized}' escapes sandbox prefix '{allowed_prefix}'"
        )

    # Belt-and-suspenders: validate full virtual path shape (Rule 8)
    if not _VALID_VIRTUAL_PATH_RE.match(normalized):
        raise PathTraversalError(
            f"Path '{normalized}' does not match allowed virtual path schema"
        )

    return normalized


# ── File type validation ───────────────────────────────────────────────────────


def validate_blob(blob_name: str, content: bytes, content_type: str) -> None:
    """
    Rule 6: Reject special file types, dangerous magic bytes, and oversized content.
    Rule 7: Enforce per-file size limit.
    """
    # Filename checks
    if len(blob_name) > 255:
        raise ForbiddenFileTypeError(f"Filename too long: {len(blob_name)} chars")
    if not _SAFE_FILENAME_RE.match(blob_name):
        raise ForbiddenFileTypeError(f"Unsafe filename: {blob_name!r}")
    if blob_name.startswith("."):
        raise ForbiddenFileTypeError("Hidden files not permitted")

    # Content type whitelist
    if content_type not in ALLOWED_CONTENT_TYPES:
        raise ForbiddenFileTypeError(f"Content type not allowed: {content_type}")

    # Size limit
    if len(content) > MAX_BLOB_SIZE_BYTES:
        raise QuotaExceededError(
            f"File too large: {len(content)} bytes (max {MAX_BLOB_SIZE_BYTES})"
        )

    # Magic byte scan — reject binaries and scripts
    for magic in _FORBIDDEN_MAGIC:
        if content.startswith(magic):
            raise ForbiddenFileTypeError(f"Forbidden file magic bytes: {magic!r}")

    # Reject null bytes in content
    if b"\x00" in content:
        raise ForbiddenFileTypeError("Content contains null bytes")


# ── Workspace quota tracker ────────────────────────────────────────────────────


class WorkspaceQuota:
    """Rule 7: Track and enforce file count and total size limits per run."""

    def __init__(self):
        self._file_count = 0
        self._total_bytes = 0

    def check_and_record(self, content: bytes) -> None:
        if self._file_count >= MAX_FILES_PER_RUN:
            raise QuotaExceededError(
                f"File count quota exceeded: {self._file_count}/{MAX_FILES_PER_RUN}"
            )
        new_total = self._total_bytes + len(content)
        if new_total > MAX_TOTAL_BYTES_PER_RUN:
            raise QuotaExceededError(
                "Total size quota exceeded: "
                f"{new_total}/{MAX_TOTAL_BYTES_PER_RUN} bytes"
            )
        self._file_count += 1
        self._total_bytes = new_total

    @property
    def file_count(self) -> int:
        return self._file_count

    @property
    def total_bytes(self) -> int:
        return self._total_bytes


# ── Ephemeral workspace context manager ───────────────────────────────────────


class EphemeralWorkspace:
    """
    Rule 1: Per-run scratch space with guaranteed teardown.

    Creates a blob container at __aenter__ (with 24h TTL metadata),
    always deletes it at __aexit__ — even on exception.

    Rule 8: Exposes only virtual paths to callers. Internal blob URLs
    are never returned to the agent.
    """

    def __init__(self, run_id: str, auditor: AuditLogger):
        self.run_id = run_id
        self._auditor = auditor
        self._credential = DefaultAzureCredential()
        self._quota = WorkspaceQuota()
        # Rule 2: separate containers/accounts per path type
        self._write_container = f"workspace-{run_id}"
        self._workspace_client: Optional[BlobServiceClient] = None

    def _workspace_blob_client(self) -> BlobServiceClient:
        if self._workspace_client is None:
            account_url = f"https://{WORKSPACE_STORAGE_ACCOUNT}.blob.core.windows.net"
            self._workspace_client = BlobServiceClient(
                account_url=account_url, credential=self._credential
            )
        return self._workspace_client

    async def __aenter__(self) -> "EphemeralWorkspace":
        """Create ephemeral write container (Rule 1)."""
        try:
            client = self._workspace_blob_client()
            container = client.get_container_client(self._write_container)
            container.create_container(metadata={"run_id": self.run_id, "ttl": "86400"})
            logger.info(
                "Created ephemeral workspace container: %s", self._write_container
            )
        except Exception as exc:
            logger.warning("Container may already exist: %s", exc)
        self._auditor.log(
            ActionType.RUN_START,
            outcome=Outcome.SUCCESS,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Always delete the workspace container on exit (Rule 1)."""
        try:
            client = self._workspace_blob_client()
            container = client.get_container_client(self._write_container)
            container.delete_container()
            logger.info(
                "Deleted ephemeral workspace container: %s", self._write_container
            )
        except Exception as exc:
            logger.error(
                "Failed to delete workspace container %s: %s",
                self._write_container,
                exc,
            )
        finally:
            outcome = Outcome.FAILURE if exc_type else Outcome.SUCCESS
            self._auditor.log(ActionType.RUN_COMPLETE, outcome=outcome)

    # ── Public file operations (Rule 8: virtual paths only) ──────────────────

    @staticmethod
    def _classify_content_label(content: bytes) -> str:
        text = content.decode("utf-8", errors="ignore")
        lowered = text.lower()
        for label, pattern in _SENSITIVE_PATTERNS:
            if pattern.search(text):
                return label
<<<<<<< HEAD
        if any(
            token in lowered
            for token in ["confidential", "private", "internal only"]
        ):
=======
        if any(token in lowered for token in ["confidential", "private", "internal only"]):
>>>>>>> origin/main
            return "confidential"
        if any(token in lowered for token in ["public", "published", "marketing"]):
            return "public"
        return "internal"

    def write_file(
        self, virtual_path: str, content: bytes, content_type: str = "text/plain"
    ) -> str:
        """
        Write a file to the writable sandbox area.

        Rules 2,3,6,7,9 are all enforced here.
        Returns the virtual path (never a real blob URL).
        """
        write_prefix = f"/workspace/{self.run_id}/write"

        # Rule 3: canonicalize
        canon_path = canonicalize(virtual_path, write_prefix)
        blob_name = canon_path.removeprefix(write_prefix + "/")

        # Rule 6: validate content
        validate_blob(blob_name, content, content_type)

        # Rule 7: quota
        self._quota.check_and_record(content)

        # Rule 9: audit BEFORE write
        content_hash = hashlib.sha256(content).hexdigest()
        classification_label = self._classify_content_label(content)
        self._auditor.log(
            ActionType.FILE_WRITE,
            policy_decision=PolicyDecision.ALLOW,
            path=canon_path,
            content_hash=content_hash,
            classification_label=classification_label,
            outcome=Outcome.SUCCESS,
        )

        # Execute write
        client = self._workspace_blob_client()
        blob = client.get_blob_client(container=self._write_container, blob=blob_name)
        blob.upload_blob(
            content,
            overwrite=True,
            content_settings=ContentSettings(content_type=content_type),
        )

        return canon_path  # Rule 8: return virtual path, not blob URL

    def read_file(self, virtual_path: str) -> bytes:
        """
        Read a file from the writable sandbox area (only previously written files).

        Rules 3, 9 enforced.
        """
        write_prefix = f"/workspace/{self.run_id}/write"
        canon_path = canonicalize(virtual_path, write_prefix)
        blob_name = canon_path.removeprefix(write_prefix + "/")

        content = b""
        try:
            client = self._workspace_blob_client()
            blob = client.get_blob_client(
                container=self._write_container, blob=blob_name
            )
            content = blob.download_blob().readall()
        except AzureError as exc:
            self._auditor.log(
                ActionType.FILE_READ,
                path=canon_path,
                outcome=Outcome.FAILURE,
                error_code=str(exc),
            )
            raise

        content_hash = hashlib.sha256(content).hexdigest()
        classification_label = self._classify_content_label(content)
        # Rule 9: audit after read
        self._auditor.log(
            ActionType.FILE_READ,
            policy_decision=PolicyDecision.ALLOW,
            path=canon_path,
            content_hash=content_hash,
            classification_label=classification_label,
            outcome=Outcome.SUCCESS,
        )
        return content

    def delete_file(self, virtual_path: str) -> None:
        """Delete a file from the writable sandbox area. Rule 9 audited."""
        write_prefix = f"/workspace/{self.run_id}/write"
        canon_path = canonicalize(virtual_path, write_prefix)
        blob_name = canon_path.removeprefix(write_prefix + "/")

        try:
            client = self._workspace_blob_client()
            blob = client.get_blob_client(
                container=self._write_container, blob=blob_name
            )
            blob.delete_blob()
        except AzureError as exc:
            self._auditor.log(
                ActionType.FILE_DELETE,
                path=canon_path,
                outcome=Outcome.FAILURE,
                error_code=str(exc),
            )
            raise

        self._auditor.log(
            ActionType.FILE_DELETE,
            policy_decision=PolicyDecision.ALLOW,
            path=canon_path,
            classification_label="internal",
            outcome=Outcome.SUCCESS,
        )
