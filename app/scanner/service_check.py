"""Checks /ip service print output for services that shouldn't be enabled,
or shouldn't be reachable from anywhere. Read directly from the API — no
port-scanning needed, which also means this works even when you only have
API access from inside the network, not an external vantage point.

If you later want to confirm actual internet-facing exposure (not just "this
service is enabled"), that's a separate, deliberately opt-in check using
python-nmap or a lookup against Shodan/Censys aggregate data — never point
that at a device you don't have authorization for. See the conversation notes
on why this matters.
"""

# Services that should almost never be enabled on a production router.
# Winbox/API being enabled isn't inherently wrong (you need them to manage
# the thing) — the finding is about the *address* they're bound to.
RISKY_IF_UNBOUND = {"winbox", "api", "api-ssl", "ftp", "telnet", "www"}

SEVERITY_BY_SERVICE = {
    "telnet": "high",     # unencrypted admin access
    "ftp": "high",        # unencrypted, and rarely actually needed
    "winbox": "critical", # CVE-2018-14847's attack surface
    "api": "high",
    "api-ssl": "medium",
    "www": "medium",
}


def check_services(services: list[dict]) -> list[dict]:
    findings = []
    for svc in services:
        name = svc.get("name", "")
        # librouteros returns these as real Python bools on current
        # RouterOS/library versions, but handle a string "true"/"false"
        # too in case an older version returns it that way.
        disabled = svc.get("disabled", False)
        if isinstance(disabled, str):
            disabled = disabled == "true"
        # /ip service print on newer RouterOS versions includes active
        # connection/session records alongside static service config —
        # they carry the same 'name' (e.g. a live API session shows up as
        # a second 'api' entry with dynamic=True). Those are sessions, not
        # configured services, and evaluating them here would double-count
        # the same finding once per open connection. Skip them.
        dynamic = svc.get("dynamic", False)
        if isinstance(dynamic, str):
            dynamic = dynamic == "true"
        address = svc.get("address", "")  # empty/0.0.0.0/0 means "reachable from anywhere"

        if disabled or dynamic or name not in RISKY_IF_UNBOUND:
            continue

        if not address or address in ("0.0.0.0/0", "::/0"):
            findings.append({
                "category": "exposed_service",
                "severity": SEVERITY_BY_SERVICE.get(name, "medium"),
                "title": f"{name} service has no address restriction",
                "detail": (
                    f"/ip service '{name}' is enabled with no allowed-address "
                    f"restriction, meaning it's reachable from any source that "
                    f"can route to this device. Restrict to a management VLAN "
                    f"or specific IPs, or disable if unused."
                ),
                "reference": None,
            })
    return findings
