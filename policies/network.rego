package agent.network

# ── Network egress authorization ───────────────────────────────────────────────
#
# Controls which FQDNs agents may reach. Implements the "egress allow-list"
# component of Layer 4 (Network Isolation + DNS Filter).
#
# Azure Firewall enforces this at the infrastructure level; this policy
# provides a second enforcement layer at the application level.

import future.keywords.in

default allow = false

allow {
    # Agent type must have network egress capability at all
    "http_get" in data.allowed_tools[input.agent_type]

    # Destination FQDN must match an entry in the per-agent allowlist
    some allowed_fqdn in data.allowed_egress_fqdns[input.agent_type]
    fqdn_matches(input.destination, allowed_fqdn)

    # Destination must not be a private/RFC1918 address
    not is_private_address(input.destination)

    # Destination must not be a known-bad category
    not is_metadata_endpoint(input.destination)
}

# ── FQDN matching helpers ─────────────────────────────────────────────────────

fqdn_matches(destination, allowed) if {
    destination == allowed
}

fqdn_matches(destination, allowed) if {
    # Allow subdomains: api.github.com matches github.com
    endswith(destination, concat("", [".", allowed]))
}

# ── Private address rejection ─────────────────────────────────────────────────
# Agents must not be able to reach internal services via HTTP egress.

is_private_address(fqdn) if {
    private_prefixes := ["10.", "172.16.", "192.168.", "127.", "169.254.", "::1", "fc00:"]
    some prefix in private_prefixes
    startswith(fqdn, prefix)
}

is_private_address(fqdn) if {
    # Explicit localhost variants
    fqdn in {"localhost", "local", "internal", "cluster.local"}
}

# ── Cloud metadata endpoint rejection ────────────────────────────────────────
# Prevent SSRF to Azure Instance Metadata Service (IMDS) or similar.

is_metadata_endpoint(fqdn) if {
    metadata_hosts := {
        "169.254.169.254",          # Azure/AWS IMDS
        "metadata.azure.internal",
        "metadata.google.internal",
    }
    fqdn in metadata_hosts
}
