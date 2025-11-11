"""
Smoke tests for core.logging_config.
"""

import os
import logging

from reversecore_mcp.core.logging_config import get_logger, setup_logging


def test_get_logger_returns_logger():
    logger = get_logger(__name__)
    assert isinstance(logger, logging.Logger)
    logger.info("test log")


def test_setup_logging_smoke(monkeypatch, tmp_path):
    # Redirect log file path to temp directory to avoid permission issues
    log_file = tmp_path / "app.log"
    monkeypatch.setenv("LOG_FILE", str(log_file))
    monkeypatch.setenv("LOG_LEVEL", "INFO")

    # Should not raise
    setup_logging()

    # get logger and write
    logger = get_logger("reversecore_mcp.test")
    logger.info("hello")

    # File may or may not be created depending on handler config; just ensure no exception
    assert True
