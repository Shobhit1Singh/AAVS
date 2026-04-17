from fastapi import FastAPI
from pydantic import BaseModel
from scanner_controller import run_scan

app = FastAPI()

class ScanRequest(BaseModel):
    spec: str
    base_url: str

@app.post("/scan")
def scan(req: ScanRequest):
    result = run_scan(req.spec, req.base_url, mode="live")
    return result