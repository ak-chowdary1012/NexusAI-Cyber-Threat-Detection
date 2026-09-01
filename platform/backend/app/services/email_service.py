<<<<<<< HEAD
# Author: Avinash Krishna — Team AVV Elites (SIH26153)
=======
>>>>>>> 77949f2bb89fea05df3ee4faf24abd4771ef1671
"""
platform/backend/app/services/email_service.py
SECURITY.md ref: §1 — email verification and password reset delivery.

Two backends behind one interface:
  - ConsoleEmailBackend: prints the email (including the raw token/link) to
    the server log. This is what runs by default (no SMTP configured), which
    is exactly right for a hackathon demo/local dev — nobody has to wire up
    a real mail server to test the verification flow end to end.
  - SMTPEmailBackend: real delivery via smtplib, selected automatically the
    moment SMTP_HOST is set in the environment (see get_email_service()).

Routers never format an email body inline or touch smtplib directly — they
call send_verification_email()/send_password_reset_email(), so the *content*
of these security-sensitive emails is defined in exactly one place.
"""
from __future__ import annotations

import smtplib
from abc import ABC, abstractmethod
from email.message import EmailMessage

from app.config import Settings, get_settings
from app.utils_logging import get_logger

logger = get_logger(__name__)


class EmailBackend(ABC):
    @abstractmethod
    def send(self, to_address: str, subject: str, body: str) -> None: ...


class ConsoleEmailBackend(EmailBackend):
    """Dev/demo backend — logs instead of sending. Never used when
    environment=production (see get_email_service)."""

    def send(self, to_address: str, subject: str, body: str) -> None:
        logger.info(f"[ConsoleEmailBackend] would send to={to_address!r} subject={subject!r}\n{body}")


class SMTPEmailBackend(EmailBackend):
    def __init__(self, settings: Settings):
        self._settings = settings

    def send(self, to_address: str, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self._settings.email_from_address
        msg["To"] = to_address
        msg.set_content(body)

        with smtplib.SMTP(self._settings.smtp_host, self._settings.smtp_port, timeout=10) as server:
            server.starttls()
            if self._settings.smtp_username and self._settings.smtp_password:
                server.login(self._settings.smtp_username, self._settings.smtp_password)
            server.send_message(msg)


def get_email_service() -> EmailBackend:
    settings = get_settings()
    if settings.smtp_host:
        return SMTPEmailBackend(settings)
    if settings.environment == "production":
        logger.warning("No SMTP_HOST configured in production — falling back to ConsoleEmailBackend; "
                        "verification/reset emails will NOT actually be delivered.")
    return ConsoleEmailBackend()


def send_verification_email(to_address: str, raw_token: str, base_url: str) -> None:
    link = f"{base_url}/verify-email?token={raw_token}"
    body = (
        f"Welcome to NexusAI Forecast.\n\n"
        f"Confirm your email address to activate your account:\n{link}\n\n"
        f"This link expires in {get_settings().email_verification_token_expire_hours} hours. "
        f"If you didn't create this account, you can ignore this email."
    )
    get_email_service().send(to_address, "Verify your NexusAI Forecast account", body)


def send_password_reset_email(to_address: str, raw_token: str, base_url: str) -> None:
    link = f"{base_url}/reset-password?token={raw_token}"
    body = (
        f"A password reset was requested for this account.\n\n"
        f"Reset your password:\n{link}\n\n"
        f"This link expires in {get_settings().password_reset_token_expire_minutes} minutes. "
        f"If you didn't request this, your password has not been changed — you can ignore this email."
    )
    get_email_service().send(to_address, "Reset your NexusAI Forecast password", body)
