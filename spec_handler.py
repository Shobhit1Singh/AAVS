import requests
import tempfile
import os


def fetch_spec_from_url(base_url):
    paths = ["/swagger.json", "/openapi.json"]

    for path in paths:
        try:
            full_url = base_url.rstrip("/") + path
            res = requests.get(full_url, timeout=5)

            if res.status_code == 200 and "json" in res.headers.get("content-type", ""):
                return res.text
        except:
            continue

    return None


def save_spec_to_temp(spec_content):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    tmp.write(spec_content.encode())
    tmp.close()
    return tmp.name


def cleanup_temp_file(path):
    if path and os.path.exists(path):
        os.remove(path)