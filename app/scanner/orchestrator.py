"""Runs all four checks against one connected device and returns a flat list
of finding dicts. This is the one function everything else (the CLI runner,
the API endpoint, and eventually the scheduler) calls — keep the actual
check logic in the individual modules, keep this function dumb.
"""
from app.routeros_client import (
    get_firewall_filter_rules,
    get_services,
    get_system_resource,
    get_users,
)
from app.scanner.credential_check import check_credentials
from app.scanner.firewall_check import check_firewall
from app.scanner.service_check import check_services
from app.scanner.version_check import check_version


def run_all_checks(api) -> tuple[str, list[dict]]:
    """Returns (routeros_version, findings)."""
    resource = get_system_resource(api)
    version = resource.get("version", "")

    findings = []
    findings += check_version(version)
    findings += check_services(get_services(api))
    findings += check_credentials(get_users(api))
    findings += check_firewall(get_firewall_filter_rules(api))

    return version, findings
