from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker
import requests

# =========================
# DATABASE CONFIG
# =========================
DATABASE_URL = "sqlite:///scanner.db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# =========================
# DATABASE MODEL
# =========================
class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    vuln_type = Column(String)
    endpoint = Column(String)
    severity = Column(String)
    payload = Column(String)

# Create tables
Base.metadata.create_all(bind=engine)

# =========================
# PAYLOADS
# =========================
payloads = [
    "' OR 1=1 --",
    "<script>alert(1)</script>",
    "../../etc/passwd"
]

# =========================
# SCANNER LOGIC
# =========================
def scan_api(url):
    findings = []

    for payload in payloads:
        test_url = f"{url}?input={payload}"

        try:
            response = requests.get(test_url, timeout=5)
            text = response.text.lower()

            # SQLi detection
            if "sql syntax" in text or "mysql" in text:
                findings.append({
                    "vuln_type": "SQL Injection",
                    "endpoint": test_url,
                    "severity": "High",
                    "payload": payload
                })

            # XSS reflection
            if payload.lower() in text:
                findings.append({
                    "vuln_type": "Reflected XSS",
                    "endpoint": test_url,
                    "severity": "Medium",
                    "payload": payload
                })

            # Path traversal clue
            if "root:x:" in text:
                findings.append({
                    "vuln_type": "Path Traversal",
                    "endpoint": test_url,
                    "severity": "High",
                    "payload": payload
                })

        except Exception as e:
            print("Request failed:", e)

    return findings

# =========================
# SAVE TO DATABASE
# =========================
def save_findings(findings):
    session = SessionLocal()

    for item in findings:
        row = Finding(
            vuln_type=item["vuln_type"],
            endpoint=item["endpoint"],
            severity=item["severity"],
            payload=item["payload"]
        )
        session.add(row)

    session.commit()
    session.close()

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    target = input("Enter API URL: ").strip()

    results = scan_api(target)

    if results:
        save_findings(results)
        print(f"{len(results)} findings saved to database.")
    else:
        print("No obvious vulnerabilities found.")