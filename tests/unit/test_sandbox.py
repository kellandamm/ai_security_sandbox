"""
Unit tests for sandbox.py — filesystem sandboxing rules.

Tests cover:
  - Rule 3: Path canonicalization and traversal rejection
  - Rule 6: File type / content validation
  - Rule 7: Quota enforcement
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../app"))

import pytest
from unittest.mock import MagicMock, patch

from sandbox import (
    canonicalize,
    validate_blob,
    WorkspaceQuota,
    PathTraversalError,
    ForbiddenFileTypeError,
    QuotaExceededError,
)

RUN_ID = "12345678-1234-1234-1234-123456789abc"
WRITE_PREFIX = f"/workspace/{RUN_ID}/write"


# ── Rule 3: Path canonicalization ─────────────────────────────────────────────

class TestCanonicalize:
    def test_valid_path_passes(self):
        path = f"/workspace/{RUN_ID}/write/output.json"
        result = canonicalize(path, WRITE_PREFIX)
        assert result == path

    def test_traversal_dotdot_rejected(self):
        with pytest.raises(PathTraversalError):
            canonicalize(f"/workspace/{RUN_ID}/write/../../../etc/passwd", WRITE_PREFIX)

    def test_traversal_double_dotdot_at_start(self):
        with pytest.raises(PathTraversalError):
            canonicalize("../../etc/shadow", WRITE_PREFIX)

    def test_double_slash_normalized(self):
        # //etc/passwd should still fail prefix check after normalization
        with pytest.raises(PathTraversalError):
            canonicalize(f"/workspace/{RUN_ID}/write//../../etc/passwd", WRITE_PREFIX)

    def test_null_byte_rejected(self):
        with pytest.raises(PathTraversalError):
            canonicalize(f"/workspace/{RUN_ID}/write/file\x00.txt", WRITE_PREFIX)

    def test_empty_path_rejected(self):
        with pytest.raises(PathTraversalError):
            canonicalize("", WRITE_PREFIX)

    def test_path_not_matching_schema_rejected(self):
        with pytest.raises(PathTraversalError):
            canonicalize(f"/workspace/{RUN_ID}/write/file name with spaces.txt", WRITE_PREFIX)

    def test_subdirectory_allowed(self):
        path = f"/workspace/{RUN_ID}/write/subdir/nested/output.txt"
        result = canonicalize(path, WRITE_PREFIX)
        assert result == path

    def test_different_run_id_rejected(self):
        other_run = "00000000-0000-0000-0000-000000000000"
        with pytest.raises(PathTraversalError):
            canonicalize(f"/workspace/{other_run}/write/output.txt", WRITE_PREFIX)


# ── Rule 6: File type validation ──────────────────────────────────────────────

class TestValidateBlob:
    def test_valid_json_file(self):
        validate_blob("result.json", b'{"key": "value"}', "application/json")  # no exception

    def test_valid_text_file(self):
        validate_blob("report.txt", b"Analysis complete.", "text/plain")

    def test_disallowed_content_type_rejected(self):
        with pytest.raises(ForbiddenFileTypeError):
            validate_blob("script.sh", b"#!/bin/bash\necho hi", "application/x-sh")

    def test_elf_magic_rejected(self):
        elf_header = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        with pytest.raises(ForbiddenFileTypeError):
            validate_blob("binary", elf_header, "text/plain")

    def test_pe_magic_rejected(self):
        pe_header = b"MZ" + b"\x00" * 100
        with pytest.raises(ForbiddenFileTypeError):
            validate_blob("malware.exe", pe_header, "text/plain")

    def test_shebang_rejected(self):
        with pytest.raises(ForbiddenFileTypeError):
            validate_blob("script.txt", b"#!/usr/bin/python3\nprint('hi')", "text/plain")

    def test_null_byte_in_content_rejected(self):
        with pytest.raises(ForbiddenFileTypeError):
            validate_blob("file.txt", b"hello\x00world", "text/plain")

    def test_oversized_file_rejected(self):
        big_content = b"x" * (51 * 1024 * 1024)  # 51 MB > 50 MB limit
        with pytest.raises(QuotaExceededError):
            validate_blob("big.txt", big_content, "text/plain")

    def test_hidden_filename_rejected(self):
        with pytest.raises(ForbiddenFileTypeError):
            validate_blob(".hidden", b"secret", "text/plain")

    def test_filename_too_long_rejected(self):
        long_name = "a" * 256
        with pytest.raises(ForbiddenFileTypeError):
            validate_blob(long_name, b"content", "text/plain")

    def test_unsafe_filename_chars_rejected(self):
        with pytest.raises(ForbiddenFileTypeError):
            validate_blob("file; rm -rf /", b"content", "text/plain")


# ── Rule 7: Quota enforcement ─────────────────────────────────────────────────

class TestWorkspaceQuota:
    def test_within_quota_allowed(self):
        quota = WorkspaceQuota()
        quota.check_and_record(b"x" * 1000)
        assert quota.file_count == 1
        assert quota.total_bytes == 1000

    def test_file_count_limit_enforced(self):
        quota = WorkspaceQuota()
        # Fill up to limit
        for _ in range(100):
            quota.check_and_record(b"x")
        # Next write must fail
        with pytest.raises(QuotaExceededError, match="File count quota exceeded"):
            quota.check_and_record(b"x")

    def test_total_size_limit_enforced(self):
        quota = WorkspaceQuota()
        # Write 499 MB
        quota.check_and_record(b"x" * (499 * 1024 * 1024))
        # Next write of 2 MB pushes over 500 MB
        with pytest.raises(QuotaExceededError, match="Total size quota exceeded"):
            quota.check_and_record(b"x" * (2 * 1024 * 1024))

    def test_cumulative_tracking(self):
        quota = WorkspaceQuota()
        quota.check_and_record(b"a" * 100)
        quota.check_and_record(b"b" * 200)
        assert quota.file_count == 2
        assert quota.total_bytes == 300
