"""
Email configuration and utilities for report delivery.
"""

import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class EmailConfig:
    """Email configuration"""

    smtp_server: str = ""
    smtp_port: int = 587
    username: str = ""
    password: str = ""
    use_tls: bool = True
    sender_name: str = "Reversecore_MCP"
    default_recipients: list[str] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> "EmailConfig":
        """Load email configuration from environment variables"""
        smtp_server = os.getenv("REPORT_SMTP_SERVER", "")

        # Return disabled state if SMTP server is not configured
        if not smtp_server:
            logger.info("📧 Email not configured (REPORT_SMTP_SERVER not set)")
            return cls()

        config = cls(
            smtp_server=smtp_server,
            smtp_port=int(os.getenv("REPORT_SMTP_PORT", "587")),
            username=os.getenv("REPORT_SMTP_USERNAME", ""),
            password=os.getenv("REPORT_SMTP_PASSWORD", ""),
            use_tls=os.getenv("REPORT_SMTP_USE_TLS", "true").lower() in ("true", "1", "yes"),
            sender_name=os.getenv("REPORT_SENDER_NAME", "Reversecore_MCP"),
        )

        logger.info(f"📧 Email configured: {smtp_server}:{config.smtp_port}")
        return config

    @property
    def is_configured(self) -> bool:
        """Check if email is configured.

        Requires smtp_server and username. If username is set, password must also be set
        to avoid SMTPAuthenticationError at runtime.
        """
        if not self.smtp_server:
            return False
        if self.username and not self.password:
            return False  # Username without password will fail auth
        return True


def load_quick_contacts_from_env() -> dict[str, dict[str, str]]:
    """Load quick contacts from environment variables

    Format: REPORT_QUICK_CONTACTS=name1:email1:role1,name2:email2:role2
    """
    contacts_str = os.getenv("REPORT_QUICK_CONTACTS", "")
    contacts = {}

    if not contacts_str:
        return contacts

    for entry in contacts_str.split(","):
        parts = entry.strip().split(":")
        if len(parts) >= 2:
            name = parts[0].strip()
            email = parts[1].strip()
            role = parts[2].strip() if len(parts) > 2 else "Contact"
            contacts[name] = {"email": email, "role": role}
            logger.debug(f"Loaded quick contact: {name} -> {email}")

    if contacts:
        logger.info(f"📇 Loaded {len(contacts)} quick contacts from environment")

    return contacts
