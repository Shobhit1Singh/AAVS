from fastapi import FastAPI
from pydantic import BaseModel
import subprocess

app = FastAPI()

class ScanRequest(BaseModel):
    url: str
    mode: str


@app.get("/")
def hello():
    return {"backend is working"}

@app.post("/start-scan")
def start_scan(data: ScanRequest):

    subprocess.Popen([
        "python",
        "scanner_controller.py",
        data.url,
        data.mode
    ])

    return {"status": "started"}