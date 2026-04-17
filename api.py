from fastapi import FastAPI, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import tempfile
import os
import uuid
import traceback

from scanner_controller import run_scan

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

results_store = {}


def run_and_store(scan_id, tmp_path, base_url):
    try:
        result = run_scan(tmp_path, base_url=base_url, mode="live")

        results_store[scan_id] = {
            "status": "completed",
            "result": result
        }

    except Exception as e:
        print(traceback.format_exc())

        results_store[scan_id] = {
            "status": "failed",
            "error": str(e)
        }

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.post("/scan/file")
async def scan_with_file(
    file: UploadFile = File(...),
    base_url: str = None,
    background_tasks: BackgroundTasks = None
):
    content = await file.read()

    if not content:
        return {"error": "Empty file uploaded"}

    scan_id = str(uuid.uuid4())

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    results_store[scan_id] = {"status": "running"}

    background_tasks.add_task(
        run_and_store,
        scan_id,
        tmp_path,
        base_url
    )

    return {
        "scan_id": scan_id,
        "status": "running"
    }


@app.get("/scan/{scan_id}")
def get_scan_result(scan_id: str):
    return results_store.get(
        scan_id,
        {"status": "not_found", "error": "Scan ID not found"}
    )


@app.get("/active-scans")
def get_active_scans():
    return results_store