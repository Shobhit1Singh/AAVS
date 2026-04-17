from fastapi import FastAPI
from pydantic import BaseModel
from scanner_controller import run_scan
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # later restrict this if you care about security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    spec: str
    base_url: str
@app.get("/")
def root():
    return {"message": "AAVS running"}
@app.post("/scan")
def scan(req: ScanRequest):
    result = run_scan(req.spec, req.base_url, mode="live")
    return result
@app.get("/scan")
def scan():
    return {"status": "scan started"}