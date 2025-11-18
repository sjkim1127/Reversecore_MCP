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
    
    # Reload settings to pick up new environment variables
    from reversecore_mcp.core.config import reload_settings
    reload_settings()

    # Should not raise
    setup_logging()

    # get logger and write
    logger = get_logger("reversecore_mcp.test")
    logger.info("hello")

    # File may or may not be created depending on handler config; just ensure no exception
    assert True


def test_setup_logging_json_format(monkeypatch, tmp_path):
    """Test logging with JSON format."""
    log_file = tmp_path / "app_json.log"
    monkeypatch.setenv("LOG_FILE", str(log_file))
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("LOG_FORMAT", "json")
    
    from reversecore_mcp.core.config import reload_settings
    reload_settings()
    
    setup_logging()
    
    logger = get_logger("test_json")
    logger.info("test message")
    
    # Verify JSON log was created
    assert log_file.exists()


def test_setup_logging_different_log_levels(monkeypatch, tmp_path):
    """Test logging with different log levels."""
    log_file = tmp_path / "app_levels.log"
    
    for level in ["DEBUG", "INFO", "WARNING", "ERROR"]:
        monkeypatch.setenv("LOG_FILE", str(log_file))
        monkeypatch.setenv("LOG_LEVEL", level)
        
        from reversecore_mcp.core.config import reload_settings
        reload_settings()
        
        setup_logging()
        logger = get_logger(f"test_{level}")
        logger.info(f"Testing {level} level")


def test_setup_logging_permission_error(monkeypatch):
    """Test logging when log file cannot be created due to permissions."""
    # Use a path that should be unwritable
    monkeypatch.setenv("LOG_FILE", "/root/impossible/path/app.log")
    monkeypatch.setenv("LOG_LEVEL", "INFO")
    
    from reversecore_mcp.core.config import reload_settings
    reload_settings()
    
    # Should not raise, just log to console
    setup_logging()
    
    logger = get_logger("test_permission")
    logger.info("This should still work")


def test_json_formatter_basic(monkeypatch):
    """Test JSONFormatter basic functionality."""
    import json
    from reversecore_mcp.core.logging_config import JSONFormatter
    
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Test message",
        args=(),
        exc_info=None
    )
    
    result = formatter.format(record)
    data = json.loads(result)
    
    assert data["level"] == "INFO"
    assert data["message"] == "Test message"
    assert "timestamp" in data


def test_json_formatter_with_extra_fields(monkeypatch):
    """Test JSONFormatter with extra fields."""
    import json
    from reversecore_mcp.core.logging_config import JSONFormatter
    
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname="test.py",
        lineno=20,
        msg="Error occurred",
        args=(),
        exc_info=None
    )
    
    # Add extra attributes
    record.tool_name = "test_tool"
    record.file_name = "test.bin"
    record.execution_time_ms = 123
    record.error_code = "E001"
    
    result = formatter.format(record)
    data = json.loads(result)
    
    assert data["tool_name"] == "test_tool"
    assert data["file_name"] == "test.bin"
    assert data["execution_time_ms"] == 123
    assert data["error_code"] == "E001"


def test_json_formatter_with_exception(monkeypatch):
    """Test JSONFormatter with exception info."""
    import json
    from reversecore_mcp.core.logging_config import JSONFormatter
    
    formatter = JSONFormatter()
    
    try:
        raise ValueError("Test exception")
    except ValueError:
        import sys
        exc_info = sys.exc_info()
        
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=30,
            msg="Exception test",
            args=(),
            exc_info=exc_info
        )
        
        result = formatter.format(record)
        data = json.loads(result)
        
        assert "exception" in data
        assert "ValueError" in data["exception"]


def test_get_logger_with_different_names():
    """Test get_logger returns loggers with correct names."""
    logger1 = get_logger("module1")
    logger2 = get_logger("module2")
    
    assert logger1.name == "reversecore_mcp.module1"
    assert logger2.name == "reversecore_mcp.module2"
    assert logger1 != logger2
