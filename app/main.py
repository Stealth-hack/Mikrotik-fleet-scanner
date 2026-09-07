from fastapi import FastAPI

from app.api import devices, scans

app = FastAPI(
    title="MikroTik Fleet Scanner",
    description="Fleet-level vulnerability/misconfig visibility for MikroTik/RouterOS deployments.",
)

app.include_router(devices.router)
app.include_router(scans.router)


@app.get("/")
def root():
    return {"status": "up", "docs": "/docs"}
