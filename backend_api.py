from fastapi import FastAPI
from pydantic import BaseModel
import subprocess

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
class ScanRequest(BaseModel):
    url: str
    mode: str

@app.post("/start-scan")
def start_scan(data: ScanRequest):

    url = data.url
    mode = data.mode

    # run your scanner script
    subprocess.Popen(["python", "scanner_controller.py", url])

    return {"message": "Scan started", "target": url}