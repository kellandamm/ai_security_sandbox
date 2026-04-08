package agent.secrets

# ── Credential leak detection ──────────────────────────────────────────────────
#
# Applied to agent output content BEFORE it is written to a file or sent
# over a network call. Prevents the agent from exfiltrating secrets it
# may have encountered in its context (prompt injection defence, Layer 5).
#
# Called from sandbox.py validate_blob() as a belt-and-suspenders check
# alongside the magic-byte and content-type validation.

import future.keywords.if

default contains_credential = false

contains_credential if {
    # Generic key=value patterns (password, secret, token, key, api_key)
    regex.match(
        `(?i)(password|passwd|secret|token|api[_-]?key|auth[_-]?key)\s*[:=]\s*\S{8,}`,
        input.content,
    )
}

contains_credential if {
    # Azure SAS token signature
    regex.match(`sv=\d{4}-\d{2}-\d{2}&`, input.content)
}

contains_credential if {
    # Azure storage account key (base64, 88 chars)
    regex.match(`[A-Za-z0-9+/]{86}==`, input.content)
}

contains_credential if {
    # AWS access key ID
    regex.match(`AKIA[0-9A-Z]{16}`, input.content)
}

contains_credential if {
    # AWS secret access key pattern
    regex.match(`(?i)aws.{0,20}secret.{0,20}[A-Za-z0-9/+]{40}`, input.content)
}

contains_credential if {
    # GitHub personal access token
    regex.match(`gh[pousr]_[A-Za-z0-9]{36,}`, input.content)
}

contains_credential if {
    # Generic bearer token / JWT in content
    regex.match(`Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*`, input.content)
}

contains_credential if {
    # Private key PEM header
    contains(input.content, "-----BEGIN")
    contains(input.content, "PRIVATE KEY-----")
}

# ── Safe output check ─────────────────────────────────────────────────────────

allow_output if {
    not contains_credential
}
