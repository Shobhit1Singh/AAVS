from fastapi import (
    FastAPI,
    UploadFile,
    File,
    BackgroundTasks,
    Form,
    HTTPException
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import tempfile
import os
import uuid
import traceback

from scanner_controller import run_scan


# ==========================================================
# APP
# ==========================================================

app = FastAPI(
    title="API Security Scanner",
    version="2.0.0",
    description="Background API scanner service. Because manually testing endpoints is how people lose weekends."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten in production, obviously
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================================
# MEMORY STORE
# Replace later with Redis / DB if you enjoy scaling.
# ==========================================================

results_store = {}


# ==========================================================
# MODELS
# ==========================================================

class URLScanRequest(BaseModel):
    spec_path: str
    base_url: str


# ==========================================================
# HELPERS
# ==========================================================

def now():
    return datetime.utcnow().isoformat()


def create_scan_record(status="queued"):
    return {
        "status": status,
        "created_at": now(),
        "updated_at": now(),
        "result": [],
        "error": None
    }


def update_scan(scan_id, **kwargs):
    if scan_id not in results_store:
        return

    results_store[scan_id].update(kwargs)
    results_store[scan_id]["updated_at"] = now()


def safe_remove(path):
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except:
        pass


# ==========================================================
# WORKER
# ==========================================================

def run_and_store(scan_id, spec_path, base_url, delete_file=False):
    try:
        update_scan(scan_id, status="running")

        findings = run_scan(
            spec_path,
            base_url=base_url,
            mode="live"
        )

        update_scan(
            scan_id,
            status="completed",
            result=findings
        )

    except Exception as e:
        print(traceback.format_exc())

        update_scan(
            scan_id,
            status="failed",
            error=str(e)
        )

    finally:
        if delete_file:
            safe_remove(spec_path)


# ==========================================================
# HEALTH
# ==========================================================

@app.get("/")
def root():
    return {
        "service": "API Security Scanner",
        "status": "online",
        "time": now()
    }


@app.get("/health")
def health():
    return {
        "ok": True,
        "active_jobs": len(results_store)
    }


# ==========================================================
# START SCAN BY FILE UPLOAD
# ==========================================================

@app.post("/scan/file")
async def scan_with_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    base_url: str = Form(...)
):
    if not base_url.strip():
        raise HTTPException(
            status_code=400,
            detail="base_url is required"
        )

    content = await file.read()

    if not content:
        raise HTTPException(
            status_code=400,
            detail="Empty file uploaded"
        )

    scan_id = str(uuid.uuid4())

    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".json"
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    results_store[scan_id] = create_scan_record()

    background_tasks.add_task(
        run_and_store,
        scan_id,
        tmp_path,
        base_url.strip(),
        True
    )

    return {
        "scan_id": scan_id,
        "status": "queued"
    }


# ==========================================================
# START SCAN BY EXISTING LOCAL SPEC PATH
# Good for CLI workflows.
# ==========================================================

@app.post("/scan/url")
def scan_from_path(
    payload: URLScanRequest,
    background_tasks: BackgroundTasks
):
    if not os.path.exists(payload.spec_path):
        raise HTTPException(
            status_code=404,
            detail="Spec file not found"
        )

    scan_id = str(uuid.uuid4())

    results_store[scan_id] = create_scan_record()

    background_tasks.add_task(
        run_and_store,
        scan_id,
        payload.spec_path,
        payload.base_url.strip(),
        False
    )

    return {
        "scan_id": scan_id,
        "status": "queued"
    }


# ==========================================================
# GET RESULT
# ==========================================================

@app.get("/scan/{scan_id}")
def get_scan_result(scan_id: str):
    if scan_id not in results_store:
        raise HTTPException(
            status_code=404,
            detail="Scan ID not found"
        )

    return results_store[scan_id]


# ==========================================================
# LIST ALL SCANS
# ==========================================================

@app.get("/scans")
def get_all_scans():
    return results_store


# ==========================================================
# ACTIVE ONLY
# ==========================================================

@app.get("/active-scans")
def get_active_scans():
    active = {}

    for scan_id, data in results_store.items():
        if data["status"] in ["queued", "running"]:
            active[scan_id] = data

    return active


# ==========================================================
# DELETE OLD SCAN
# ==========================================================

@app.delete("/scan/{scan_id}")
def delete_scan(scan_id: str):
    if scan_id not in results_store:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    del results_store[scan_id]

    return {
        "deleted": True,
        "scan_id": scan_id
    }