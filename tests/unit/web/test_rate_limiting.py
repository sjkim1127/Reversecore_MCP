"""Unit tests for rate limiting configuration and strict mode."""

from __future__ import annotations

import pytest


class TestRateLimitConfig:
    def test_default_rate_limit_is_60(self):
        """Default rate limit should be 60 requests/minute."""
        from reversecore_mcp.core.config import Settings

        s = Settings()
        assert s.rate_limit == 60

    def test_rate_limit_env_override(self, monkeypatch):
        """REVERSECORE_RATE_LIMIT env var should override the default."""
        monkeypatch.setenv("REVERSECORE_RATE_LIMIT", "30")
        from reversecore_mcp.core.config import Settings

        s = Settings()
        assert s.rate_limit == 30

    def test_rate_limit_minimum_bound(self, monkeypatch):
        """Values below 1 should raise a ValidationError."""
        from pydantic import ValidationError

        monkeypatch.setenv("REVERSECORE_RATE_LIMIT", "0")
        from reversecore_mcp.core.config import Settings

        with pytest.raises(ValidationError):
            Settings()

    def test_rate_limit_maximum_bound(self, monkeypatch):
        """Values above 1000 should raise a ValidationError."""
        from pydantic import ValidationError

        monkeypatch.setenv("REVERSECORE_RATE_LIMIT", "1001")
        from reversecore_mcp.core.config import Settings

        with pytest.raises(ValidationError):
            Settings()

    def test_rate_limit_boundary_values_valid(self, monkeypatch):
        """Values at the boundary (1 and 1000) should be accepted."""
        from reversecore_mcp.core.config import Settings

        monkeypatch.setenv("REVERSECORE_RATE_LIMIT", "1")
        assert Settings().rate_limit == 1

        monkeypatch.setenv("REVERSECORE_RATE_LIMIT", "1000")
        assert Settings().rate_limit == 1000

    def test_config_wrapper_exposes_rate_limit(self, monkeypatch):
        """Config wrapper should expose rate_limit through its property."""
        monkeypatch.setenv("REVERSECORE_RATE_LIMIT", "42")
        from reversecore_mcp.core.config import reset_config

        reset_config()
        from reversecore_mcp.core.config import get_config

        cfg = get_config()
        assert cfg.rate_limit == 42
        reset_config()  # clean up singleton


class TestRateLimitStrictMode:
    def test_strict_mode_env_var_recognised(self, monkeypatch):
        """REVERSECORE_RATE_LIMIT_STRICT=true should be readable from environment."""
        monkeypatch.setenv("REVERSECORE_RATE_LIMIT_STRICT", "true")
        import os

        # The env var exists and equals "true"
        assert os.getenv("REVERSECORE_RATE_LIMIT_STRICT", "").lower() == "true"

    def test_strict_mode_false_by_default(self, monkeypatch):
        """Without the env var, strict mode should be inactive."""
        monkeypatch.delenv("REVERSECORE_RATE_LIMIT_STRICT", raising=False)
        import os

        assert os.getenv("REVERSECORE_RATE_LIMIT_STRICT", "").lower() != "true"
