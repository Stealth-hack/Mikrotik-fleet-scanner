from fastapi import APIRouter, Depends, HTTPException
from librouteros.exceptions import TrapError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Device, Finding, ScanResult
from app.routeros_client import decrypt_password, device_connection
from app.scanner.orchestrator import run_all_checks

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("/{device_id}")
def trigger_scan(device_id: int, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    password = decrypt_password(device.encrypted_password)
    try:
        with device_connection(device.host, device.port, device.username, password) as api:
            version, findings = run_all_checks(api)
    except (TrapError, OSError) as e:
        raise HTTPException(status_code=502, detail=f"Could not scan device: {e}")

    scan_result = ScanResult(device_id=device.id, routeros_version=version)
    db.add(scan_result)
    db.flush()  # get scan_result.id before committing

    for f in findings:
        db.add(Finding(scan_result_id=scan_result.id, **f))

    db.commit()
    return {
        "scan_id": scan_result.id,
        "device": device.name,
        "routeros_version": version,
        "finding_count": len(findings),
    }


@router.get("/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan.id,
        "device_id": scan.device_id,
        "routeros_version": scan.routeros_version,
        "scanned_at": scan.scanned_at,
        "findings": [
            {
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "detail": f.detail,
                "reference": f.reference,
            }
            for f in scan.findings
        ],
    }
