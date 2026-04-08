"""
Unit tests for kill_switch.py — feature flag enforcement.

Tests cover:
  - Global kill switch blocks all actions
  - Agent-type kill switch blocks specific type
  - Action-type kill switch blocks specific capability
  - Fail-closed: App Configuration unreachable → blocked
  - Cache: flags are cached for TTL seconds
  - is_enabled() convenience wrapper
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../app"))

import json
import time
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from kill_switch import KillSwitchClient, KillSwitchError


def _make_client() -> KillSwitchClient:
    client = KillSwitchClient()
    # Inject a mock App Configuration client
    client._client = MagicMock()
    return client


def _mock_flag(client: KillSwitchClient, flag_name: str, enabled: bool):
    """Configure the mock to return a given flag value."""
    setting = MagicMock()
    setting.value = json.dumps({"id": flag_name, "enabled": enabled, "conditions": {}})

    def get_setting(key, label=None):
        # Strip the .appconfig.featureflag/ prefix the client adds
        if flag_name in key:
            return setting
        raise Exception(f"Flag not found: {key}")

    client._client.get_configuration_setting.side_effect = get_setting


class TestGlobalKillSwitch:
    def test_global_enabled_allows(self):
        client = _make_client()
        _mock_flag(client, "agent-execution-enabled", True)
        client.check()  # no exception

    def test_global_disabled_blocks(self):
        client = _make_client()
        _mock_flag(client, "agent-execution-enabled", False)
        with pytest.raises(KillSwitchError) as exc_info:
            client.check()
        assert exc_info.value.flag_name == "agent-execution-enabled"

    def test_global_disabled_blocks_regardless_of_agent_type(self):
        client = _make_client()
        _mock_flag(client, "agent-execution-enabled", False)
        with pytest.raises(KillSwitchError):
            client.check(agent_type="data-analyst", action_type="file_write")


class TestAgentTypeKillSwitch:
    def test_agent_type_enabled_allows(self):
        client = _make_client()
        flags = {
            "agent-execution-enabled": True,
            "agent-data-analyst-enabled": True,
        }
        setting_map = {
            k: MagicMock(value=json.dumps({"id": k, "enabled": v}))
            for k, v in flags.items()
        }

        def get_setting(key, label=None):
            for flag_name, setting in setting_map.items():
                if flag_name in key:
                    return setting
            raise Exception(f"Not found: {key}")

        client._client.get_configuration_setting.side_effect = get_setting
        client.check(agent_type="data-analyst")  # no exception

    def test_agent_type_disabled_blocks(self):
        client = _make_client()
        flags = {
            "agent-execution-enabled": True,
            "agent-data-analyst-enabled": False,
        }
        setting_map = {
            k: MagicMock(value=json.dumps({"id": k, "enabled": v}))
            for k, v in flags.items()
        }

        def get_setting(key, label=None):
            for flag_name, setting in setting_map.items():
                if flag_name in key:
                    return setting
            raise Exception(f"Not found: {key}")

        client._client.get_configuration_setting.side_effect = get_setting

        with pytest.raises(KillSwitchError) as exc_info:
            client.check(agent_type="data-analyst")
        assert "data-analyst" in exc_info.value.flag_name


class TestActionTypeKillSwitch:
    def _make_multi_flag_client(self, flags: dict) -> KillSwitchClient:
        client = _make_client()
        setting_map = {
            k: MagicMock(value=json.dumps({"id": k, "enabled": v}))
            for k, v in flags.items()
        }

        def get_setting(key, label=None):
            for flag_name, setting in setting_map.items():
                if flag_name in key:
                    return setting
            raise Exception(f"Not found: {key}")

        client._client.get_configuration_setting.side_effect = get_setting
        return client

    def test_file_write_disabled_blocks(self):
        client = self._make_multi_flag_client({
            "agent-execution-enabled": True,
            "file-write-enabled": False,
        })
        with pytest.raises(KillSwitchError) as exc_info:
            client.check(action_type="file_write")
        assert exc_info.value.flag_name == "file-write-enabled"

    def test_openai_calls_disabled_blocks(self):
        client = self._make_multi_flag_client({
            "agent-execution-enabled": True,
            "openai-calls-enabled": False,
        })
        with pytest.raises(KillSwitchError) as exc_info:
            client.check(action_type="openai_call")
        assert exc_info.value.flag_name == "openai-calls-enabled"

    def test_network_egress_disabled_blocks_http_get(self):
        client = self._make_multi_flag_client({
            "agent-execution-enabled": True,
            "network-egress-enabled": False,
        })
        with pytest.raises(KillSwitchError) as exc_info:
            client.check(action_type="http_get")
        assert exc_info.value.flag_name == "network-egress-enabled"

    def test_unknown_action_type_not_blocked(self):
        client = self._make_multi_flag_client({
            "agent-execution-enabled": True,
        })
        client.check(action_type="some_future_action")  # no exception — unknown = not mapped


class TestFailClosed:
    def test_app_config_unreachable_blocks(self):
        client = _make_client()
        client._client.get_configuration_setting.side_effect = Exception("Connection refused")

        with pytest.raises(KillSwitchError):
            client.check()

    def test_app_config_auth_error_blocks(self):
        client = _make_client()
        client._client.get_configuration_setting.side_effect = PermissionError("403 Forbidden")

        with pytest.raises(KillSwitchError):
            client.check()

    def test_is_enabled_returns_false_on_kill(self):
        client = _make_client()
        _mock_flag(client, "agent-execution-enabled", False)
        assert client.is_enabled() is False

    def test_is_enabled_returns_true_when_clear(self):
        client = _make_client()
        _mock_flag(client, "agent-execution-enabled", True)
        assert client.is_enabled() is True


class TestCaching:
    def test_flag_is_cached_within_ttl(self):
        client = _make_client()
        _mock_flag(client, "agent-execution-enabled", True)

        client.check()
        client.check()
        client.check()

        # App Config should only be called once — subsequent reads use cache
        assert client._client.get_configuration_setting.call_count == 1

    def test_cache_expires_after_ttl(self):
        client = _make_client()
        _mock_flag(client, "agent-execution-enabled", True)

        client.check()
        # Artificially expire cache
        for key in list(client._cache.keys()):
            client._cache[key] = (client._cache[key][0], time.monotonic() - 1)

        client.check()
        assert client._client.get_configuration_setting.call_count == 2
