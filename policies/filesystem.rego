package agent.filesystem

# ── Filesystem validation rules ────────────────────────────────────────────────
#
# Belt-and-suspenders checks alongside Python canonicalize() in sandbox.py.
# Called as a secondary check — sandbox.py is the primary enforcement.

import future.keywords.if

default valid_path = false
default valid_filename = false

# ── Path validation (Rule 3 + Rule 6) ─────────────────────────────────────────

valid_path if {
    path := input.path
    not contains(path, "..")           # traversal sequence
    not contains(path, "//")           # double slash
    not contains(path, "\x00")         # null byte
    not startswith(path, "/etc")       # system config
    not startswith(path, "/proc")      # proc filesystem
    not startswith(path, "/sys")       # sysfs
    not startswith(path, "/dev")       # device files (Rule 6)
    not startswith(path, "/tmp")       # no direct /tmp access
    not startswith(path, "/root")      # root home
    not startswith(path, "/home")      # user homes
    regex.match(
        `^/workspace/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/(read|write)/[a-zA-Z0-9._\-/]+$`,
        path,
    )
}

# ── Filename validation (Rule 6) ──────────────────────────────────────────────

valid_filename if {
    name := input.filename
    not startswith(name, ".")              # no hidden files
    not contains(name, "\x00")            # no null bytes
    count(name) <= 255                    # length limit
    regex.match(`^[a-zA-Z0-9._\-]+$`, name)  # safe character set only
}

# ── Special file type rejection (Rule 6) ─────────────────────────────────────
# Content-type must be in the approved whitelist.

allowed_content_types := {
    "text/plain",
    "application/json",
    "text/csv",
    "text/markdown",
}

valid_content_type if {
    input.content_type in allowed_content_types
}

# ── Summary decision ─────────────────────────────────────────────────────────

allow_file_operation if {
    valid_path
    valid_filename
    valid_content_type
}
