"""Tests for reversecore_mcp.tools.report.email."""

from unittest.mock import patch

from reversecore_mcp.tools.report.email import EmailConfig, load_quick_contacts_from_env


class TestEmailConfig:
    """Tests for EmailConfig."""

    def test_from_env_not_configured(self):
        with patch.dict("os.environ", {}, clear=False):
            config = EmailConfig.from_env()
            assert config.is_configured is False

    def test_from_env_configured(self):
        env = {
            "REPORT_SMTP_SERVER": "smtp.example.com",
            "REPORT_SMTP_PORT": "465",
            "REPORT_SMTP_USERNAME": "user",
            "REPORT_SMTP_PASSWORD": "pass",
            "REPORT_SMTP_USE_TLS": "false",
            "REPORT_SENDER_NAME": "Test",
        }
        with patch.dict("os.environ", env, clear=False):
            config = EmailConfig.from_env()
            assert config.smtp_server == "smtp.example.com"
            assert config.smtp_port == 465
            assert config.use_tls is False
            assert config.sender_name == "Test"
            assert config.is_configured is True

    def test_is_configured_username_no_password(self):
        config = EmailConfig(smtp_server="smtp.example.com", username="user", password="")
        assert config.is_configured is False


class TestLoadQuickContacts:
    """Tests for load_quick_contacts_from_env."""

    def test_empty(self):
        with patch.dict("os.environ", {}, clear=False):
            result = load_quick_contacts_from_env()
            assert result == {}

    def test_with_contacts(self):
        env = {"REPORT_QUICK_CONTACTS": "Alice:alice@test.com:Analyst,Bob:bob@test.com"}
        with patch.dict("os.environ", env, clear=False):
            result = load_quick_contacts_from_env()
            assert result["Alice"]["email"] == "alice@test.com"
            assert result["Alice"]["role"] == "Analyst"
            assert result["Bob"]["role"] == "Contact"
