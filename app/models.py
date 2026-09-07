import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


class Device(Base):
    """One MikroTik/RouterOS device in the fleet. This is the table that makes
    this a *fleet* tool instead of a single-device script — everything else
    hangs off this."""

    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)          # operator-facing label, e.g. "Site 12 - Gwarinpa"
    host = Column(String, nullable=False)
    port = Column(Integer, default=8728)
    username = Column(String, nullable=False)
    # Encrypted at rest via cryptography.Fernet — see app/routeros_client.py.
    # Push operators toward a dedicated read-only API user, not full admin.
    encrypted_password = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan_results = relationship("ScanResult", back_populates="device")


class ScanResult(Base):
    """One scan run against one device. Findings hang off this so you can
    diff scan N against scan N-1 later and show drift over time."""

    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    routeros_version = Column(String)
    scanned_at = Column(DateTime, default=datetime.datetime.utcnow)

    device = relationship("Device", back_populates="scan_results")
    findings = relationship("Finding", back_populates="scan_result")


class Finding(Base):
    """One issue found in one scan: a CVE match, an exposed service, a
    default credential, or a firewall gap. severity/category keep this
    generic enough that every checker module writes to the same table."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    scan_result_id = Column(Integer, ForeignKey("scan_results.id"), nullable=False)
    category = Column(String, nullable=False)   # "cve" | "exposed_service" | "credential" | "firewall"
    severity = Column(String, nullable=False)   # "critical" | "high" | "medium" | "low"
    title = Column(String, nullable=False)
    detail = Column(Text)
    reference = Column(String)                  # CVE ID or advisory URL, where applicable

    scan_result = relationship("ScanResult", back_populates="findings")
