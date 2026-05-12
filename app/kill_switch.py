"""
Kill switch client using Azure App Configuration feature flags.

Design principles:
  - Fail-closed: if App Configuration is unreachable, ALL actions are BLOCKED.
  - 10-second TTL cache: fresh enough for near-realtime kills, low enough latency.
  - Hierarchical checks: global flag → agent-type flag → action-type flag.
  - Every check emits an audit event when blocked.

Rule: operators can halt ALL agent execution, a specific agent type, or a specific
capability (file writes, network, OpenAI) with a single flag flip in the portal.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Optional

from azure.appconfiguration import AzureAppConfigurationClient
from azure.identity import DefaultAzureCredential

logger = logging.getLogger(__name__)

APP_CONFIG_ENDPOINT = os.environ.get("APP_CONFIG_ENDPOINT", "")
LABEL = "production"
CACHE_TTL_SECONDS = 10


class KillSwitchError(Exception):
    """Raised when a kill switch is active."""

    def __init__(self, flag_name: str):
        self.flag_name = flag_name
        super().__init__(f"Kill switch active: {flag_name}")


class KillSwitchClient:
    """
    Checks feature flags in Azure App Configuration.

    If App Configuration is unreachable, defaults to BLOCKED (fail-closed).
    This prevents the kill switch from becoming a liability if the service
    has a connectivity issue.
    """

    def __init__(self):
        self._credential = DefaultAzureCredential()
        self._client: Optional[AzureAppConfigurationClient] = None
        self._cache: dict[str, tuple[bool, float]] = {}  # flag → (value, expires_at)

    def _get_client(self) -> AzureAppConfigurationClient:
        if self._client is None:
            if not APP_CONFIG_ENDPOINT:
                raise RuntimeError("APP_CONFIG_ENDPOINT not configured")
            self._client = AzureAppConfigurationClient(
                base_url=APP_CONFIG_ENDPOINT,
                credential=self._credential,
            )
        return self._client

    def _read_flag(self, flag_name: str) -> bool:
        """Read a single feature flag, using cache if fresh."""
        now = time.monotonic()
        if flag_name in self._cache:
            value, expires_at = self._cache[flag_name]
            if now < expires_at:
                return value

        try:
            client = self._get_client()
            setting = client.get_configuration_setting(
                key=f".appconfig.featureflag/{flag_name}",
                label=LABEL,
            )
            import json

            flag_doc = json.loads(setting.value)
            enabled: bool = flag_doc.get("enabled", True)
            self._cache[flag_name] = (enabled, now + CACHE_TTL_SECONDS)
            return enabled
        except Exception as exc:
            logger.critical(
                (
                    "KILL_SWITCH_FAIL_CLOSED: App Configuration unreachable "
                    "for flag '%s': %s. Defaulting to BLOCKED."
                ),
                flag_name,
                exc,
            )
            # Fail closed — cache the blocked state briefly to avoid hammering
            self._cache[flag_name] = (False, now + 5)
            return False

    def check(
        self, agent_type: Optional[str] = None, action_type: Optional[str] = None
    ) -> None:
        """
        Check all applicable kill switches. Raises KillSwitchError if any are active.

        Hierarchy:
          1. agent-execution-enabled (global)
          2. agent-{agent_type}-enabled (per type)
          3. {action_type}-enabled (per capability, e.g. file-write-enabled)
        """
        if not self._read_flag("agent-execution-enabled"):
            raise KillSwitchError("agent-execution-enabled")

        if agent_type:
            safe_type = agent_type.replace("_", "-").lower()
            if not self._read_flag(f"agent-{safe_type}-enabled"):
                raise KillSwitchError(f"agent-{safe_type}-enabled")

        if action_type:
            action_map = {
                "file_write": "file-write-enabled",
                "network_call": "network-egress-enabled",
                "http_get": "network-egress-enabled",
                "openai_call": "openai-calls-enabled",
            }
            flag = action_map.get(action_type)
            if flag and not self._read_flag(flag):
                raise KillSwitchError(flag)

    def is_enabled(
        self, agent_type: Optional[str] = None, action_type: Optional[str] = None
    ) -> bool:
        """Boolean convenience wrapper — returns False if any kill switch is active."""
        try:
            self.check(agent_type=agent_type, action_type=action_type)
            return True
        except KillSwitchError:
            return False
