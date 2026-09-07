"""Thin wrapper over librouteros. Read-only by design — every method here
issues a print-style query, never a set/add/remove. If you extend this file,
keep that boundary; active/write operations belong in a clearly separate
module once you have a real reason (and a signed authorization) to add them.
"""
from contextlib import contextmanager

from cryptography.fernet import Fernet
from librouteros import connect
from librouteros.exceptions import TrapError

from app.config import settings


def _fernet() -> Fernet:
    if not settings.credential_encryption_key:
        raise RuntimeError(
            "CREDENTIAL_ENCRYPTION_KEY is not set. Generate one (see .env.example) "
            "before storing device credentials."
        )
    return Fernet(settings.credential_encryption_key.encode())


def encrypt_password(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_password(ciphertext: str) -> str:
    return _fernet().decrypt(ciphertext.encode()).decode()


@contextmanager
def device_connection(host: str, port: int, username: str, password: str):
    """Yields a connected librouteros API object. Caller is responsible for
    handling TrapError/connection failures around whatever it does with it."""
    api = connect(username=username, password=password, host=host, port=port)
    try:
        yield api
    finally:
        # librouteros doesn't require an explicit close, but if you swap
        # transport (e.g. ssl) later, close it here.
        pass


def get_system_resource(api) -> dict:
    """/system resource print — gives you the RouterOS version string, among
    other things. This is what version_check.py keys off of."""
    return list(api.path("system", "resource"))[0]


def get_services(api) -> list[dict]:
    """/ip service print — tells you which services (winbox, api, ftp,
    telnet, ssh, www) are enabled and what port/address they're bound to.
    This is read directly, no port-scanning needed if you already have API
    access — see service_check.py."""
    return list(api.path("ip", "service"))


def get_users(api) -> list[dict]:
    """/user print — for the credential_check.py default/blank-password
    check. Note RouterOS's API does not expose plaintext passwords (correctly
    so) — the check here is about presence of default usernames and, where
    testable, blank/default password acceptance, not password recovery."""
    return list(api.path("user"))


def get_firewall_filter_rules(api) -> list[dict]:
    """/ip firewall filter print — for firewall_check.py's any-any and
    missing-input-drop checks."""
    return list(api.path("ip", "firewall", "filter"))
