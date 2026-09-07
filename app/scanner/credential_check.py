"""Checks for default or suspicious usernames on the device.

Important limitation, stated plainly rather than glossed over: RouterOS's
API does not expose plaintext or hashed passwords, and it shouldn't — that's
correct security design on MikroTik's part, not a gap in this tool. So this
check can only flag *presence of default usernames* (the classic "admin"
account still existing) as a lower-confidence finding, not "this password is
weak." A true blank/default-password check would require an authenticated
login *attempt* against the device, which is an active check, not a
read-only one — keep that out of this module if you add it; it belongs
behind the same explicit-authorization gate as any exploitation code.
"""

DEFAULT_USERNAMES = {"admin"}


def check_credentials(users: list[dict]) -> list[dict]:
    findings = []
    usernames = {u.get("name", "").lower() for u in users}

    for default in DEFAULT_USERNAMES:
        if default in usernames:
            findings.append({
                "category": "credential",
                "severity": "medium",
                "title": f"Default username '{default}' still present",
                "detail": (
                    f"The default '{default}' account exists on this device. "
                    f"This alone isn't proof of a weak password — RouterOS's "
                    f"API doesn't expose that — but default accounts are the "
                    f"first thing credential-stuffing and botnet scanners try. "
                    f"Rename or disable it in favor of named, individually "
                    f"attributable accounts."
                ),
                "reference": None,
            })

    if len(users) == 1 and "admin" in usernames:
        findings.append({
            "category": "credential",
            "severity": "low",
            "title": "Only the default admin account exists",
            "detail": "No named per-operator accounts found — everyone with access shares one credential.",
            "reference": None,
        })

    return findings
