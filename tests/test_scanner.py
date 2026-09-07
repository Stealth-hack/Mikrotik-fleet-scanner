"""These test the check functions directly against fake RouterOS API
responses — no live device or CHR needed to run these. Run with: pytest

Once the checks pass here, THEN point run.py at the real CHR — that order
matters: verify the logic against known inputs before trusting live output.
"""
from app.scanner.credential_check import check_credentials
from app.scanner.firewall_check import check_firewall
from app.scanner.service_check import check_services
from app.scanner.version_check import check_version


def test_version_check_flags_old_vulnerable_version():
    findings = check_version("6.40.1")
    cve_ids = {f["reference"] for f in findings}
    assert "CVE-2018-14847" in cve_ids


def test_version_check_clean_on_patched_version():
    findings = check_version("6.49.8")
    cve_ids = {f["reference"] for f in findings}
    assert "CVE-2023-30799" not in cve_ids


def test_service_check_flags_unrestricted_winbox():
    services = [{"name": "winbox", "disabled": "false", "address": ""}]
    findings = check_services(services)
    assert any(f["title"].startswith("winbox") for f in findings)


def test_service_check_ignores_restricted_service():
    services = [{"name": "winbox", "disabled": "false", "address": "10.0.0.0/24"}]
    findings = check_services(services)
    assert findings == []


def test_credential_check_flags_default_admin():
    users = [{"name": "admin"}]
    findings = check_credentials(users)
    assert any("default username" in f["title"].lower() for f in findings)


def test_firewall_check_flags_missing_drop_rule():
    rules = [{"chain": "input", "action": "accept", "protocol": "tcp", "src-address": "10.0.0.0/24"}]
    findings = check_firewall(rules)
    assert any("no active drop rule" in f["title"].lower() for f in findings)


def test_firewall_check_flags_unrestricted_accept():
    rules = [
        {"chain": "input", "action": "accept", "disabled": "false"},
        {"chain": "input", "action": "drop", "disabled": "false"},
    ]
    findings = check_firewall(rules)
    assert any("unrestricted accept" in f["title"].lower() for f in findings)
