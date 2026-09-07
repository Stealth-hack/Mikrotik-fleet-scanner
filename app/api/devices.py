from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Device
from app.routeros_client import encrypt_password

router = APIRouter(prefix="/devices", tags=["devices"])


class DeviceIn(BaseModel):
    name: str
    host: str
    port: int = 8728
    username: str
    password: str  # plaintext in, encrypted before it touches the DB


class DeviceOut(BaseModel):
    id: int
    name: str
    host: str
    port: int
    username: str

    class Config:
        from_attributes = True


@router.post("", response_model=DeviceOut)
def add_device(device: DeviceIn, db: Session = Depends(get_db)):
    db_device = Device(
        name=device.name,
        host=device.host,
        port=device.port,
        username=device.username,
        encrypted_password=encrypt_password(device.password),
    )
    db.add(db_device)
    db.commit()
    db.refresh(db_device)
    return db_device


@router.get("", response_model=list[DeviceOut])
def list_devices(db: Session = Depends(get_db)):
    return db.query(Device).all()


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(device_id: int, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device
