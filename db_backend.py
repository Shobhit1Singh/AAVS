from fastapi import FastAPI
from pydantic import BaseModel
import psycopg2
import uuid

app = FastAPI()

class Scan(BaseModel):
    attack_type: str
    severity: str
    endpoint: str
    payload: str
    solution: str

def get_conn():
    return psycopg2.connect(
        dbname="aavs",
        user="postgres",
        password="your_password",
        host="localhost",
        port="5432"
    )

@app.post("/scan")
def save_scan(scan: Scan):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO scans (scan_id, attack_type, severity, endpoint, payload, solution)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        str(uuid.uuid4()),
        scan.attack_type,
        scan.severity,
        scan.endpoint,
        scan.payload,
        scan.solution
    ))

    conn.commit()
    conn.close()

    return {"message": "Stored in DB"}