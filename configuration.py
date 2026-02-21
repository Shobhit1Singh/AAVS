import os
from dotenv import load_dotenv

load_dotenv()

targets_env = os.getenv("AAVS_TARGETS", "")
TARGETS = [t.strip() for t in targets_env.split(",") if t.strip()]

TIMEOUT = int(os.getenv("AAVS_TIMEOUT", 15))
MAX_CONCURRENCY = int(os.getenv("AAVS_MAX_CONCURRENCY", 10))
WAF_SAFE_CONCURRENCY = int(os.getenv("AAVS_WAF_SAFE_CONCURRENCY", 5))

print("Loaded targets:", TARGETS)