"""Unit tests for AuditLogger."""

from unittest.mock import patch, MagicMock

from reversecore_mcp.core.audit import AuditLogger, AuditAction, audit_logger


class TestAuditLogger:
    """Tests for AuditLogger."""

    def test_singleton(self):
        """AuditLogger is a singleton."""
        a1 = AuditLogger()
        a2 = AuditLogger()
        assert a1 is a2

    def test_log_event(self):
        """log_event records an event."""
        logger = AuditLogger()
        logger._logger = MagicMock()
        logger.log_event(
            AuditAction.FILE_UPLOAD,
            "/path/to/file",
            "SUCCESS",
            user="test",
            ip="127.0.0.1",
            details={"key": "value"},
        )
        logger._logger.info.assert_called_once()
        call_arg = logger._logger.info.call_args[0][0]
        assert "FILE_UPLOAD" in call_arg
        assert "/path/to/file" in call_arg
        assert "SUCCESS" in call_arg
        assert "test" in call_arg
        assert "127.0.0.1" in call_arg
        assert "key" in call_arg

    def test_log_event_with_string_action(self):
        """log_event accepts string action."""
        logger = AuditLogger()
        logger._logger = MagicMock()
        logger.log_event("CUSTOM_ACTION", "resource", "FAILURE")
        logger._logger.info.assert_called_once()
        assert "CUSTOM_ACTION" in logger._logger.info.call_args[0][0]

    def test_log_event_default_details(self):
        """log_event uses empty dict when details is None."""
        logger = AuditLogger()
        logger._logger = MagicMock()
        logger.log_event("A", "r", "S", details=None)
        call_arg = logger._logger.info.call_args[0][0]
        assert "{}" in call_arg or "details" in call_arg

    def test_init_fallback_when_file_handler_fails(self):
        """When FileHandler fails, fallback to app log."""
        saved = AuditLogger._instance
        try:
            AuditLogger._instance = None
            with patch("reversecore_mcp.core.audit.get_config") as get_cfg:
                get_cfg.return_value = MagicMock(workspace=MagicMock(parent=MagicMock()))
                get_cfg.return_value.workspace.parent.__truediv__ = lambda self, x: "/tmp/audit.json"
                with patch("logging.FileHandler", side_effect=OSError("Permission denied")):
                    with patch("logging.getLogger") as get_logger:
                        mock_log = MagicMock()
                        get_logger.return_value = mock_log
                        inst = AuditLogger()
                        assert inst._initialized is True
                        mock_log.warning.assert_called_once()
                        assert "Failed to initialize" in str(mock_log.warning.call_args)
        finally:
            AuditLogger._instance = saved
