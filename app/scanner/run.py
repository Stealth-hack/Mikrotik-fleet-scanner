"""CLI: python -m app.scanner.run --host 192.168.56.10 --port 8728 --user admin --password ""

Point this at your CHR first. Once findings look right against a device you
know the state of, wire this into the FastAPI /scans endpoint (app/api/scans.py)
so it can be triggered per-device from the fleet inventory instead of by hand.
"""
import argparse
import sys

from librouteros.exceptions import TrapError

from app.config import settings
from app.routeros_client import device_connection
from app.scanner.orchestrator import run_all_checks

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def main():
    parser = argparse.ArgumentParser(description="Scan one RouterOS device.")
    parser.add_argument("--host", default=settings.chr_host)
    parser.add_argument("--port", type=int, default=settings.chr_port)
    parser.add_argument("--user", default=settings.chr_user)
    parser.add_argument("--password", default=settings.chr_password)
    args = parser.parse_args()

    print(f"Connecting to {args.host}:{args.port} as {args.user}...")
    try:
        with device_connection(args.host, args.port, args.user, args.password) as api:
            version, findings = run_all_checks(api)
    except TrapError as e:
        print(f"RouterOS API error: {e}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Connection failed — is the CHR reachable at {args.host}:{args.port}? ({e})", file=sys.stderr)
        sys.exit(1)

    print(f"\nRouterOS version: {version}")
    print(f"Findings: {len(findings)}\n")

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    for f in findings:
        ref = f" [{f['reference']}]" if f.get("reference") else ""
        print(f"[{f['severity'].upper():8}] {f['title']}{ref}")
        print(f"           {f['detail']}\n")

    if not findings:
        print("No findings — either the device is clean or a check silently failed. Verify against known state.")


if __name__ == "__main__":
    main()
