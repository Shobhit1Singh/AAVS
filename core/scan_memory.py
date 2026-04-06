import json
import os
import hashlib
import time
from typing import Dict, Any, Optional


class ScanMemory:

    def __init__(self, memory_file: str = "scan_memory.json"):
        self.memory_file = memory_file

        self.memory: Dict[str, Any] = {
            "endpoints": {},
            "payload_history": {},
            "clusters": {},
            "vulnerabilities": {},
            "global": {}  # 🔥 NEW: for tokens, session data, etc.
        }

        self._load()

    # -----------------------------
    # LOAD / SAVE
    # -----------------------------

    def _load(self):
        if os.path.exists(self.memory_file):
            try:
                with open(self.memory_file, "r") as f:
                    data = json.load(f)

                    # 🔥 Merge instead of overwrite (prevents missing keys)
                    for k in self.memory:
                        if k in data:
                            self.memory[k] = data[k]

            except Exception:
                pass

    def _save(self):
        with open(self.memory_file, "w") as f:
            json.dump(self.memory, f, indent=2)

    # -----------------------------
    # GENERIC STORE (CRITICAL FIX)
    # -----------------------------

    def set(self, key: str, value: Any):
        self.memory["global"][key] = value
        self._save()

    def get(self, key: str, default=None):
        return self.memory["global"].get(key, default)

    # -----------------------------
    # ENDPOINT HANDLING
    # -----------------------------

    def _endpoint_key(self, method: str, path: str) -> str:
        return f"{method.upper()}::{path}"

    def register_endpoint(self, method: str, path: str, profile: Dict[str, Any]):
        key = self._endpoint_key(method, path)

        if key not in self.memory["endpoints"]:
            self.memory["endpoints"][key] = {
                "profile": profile,
                "first_seen": time.time(),
                "scan_count": 0,
                "suspicious": False
            }

        self.memory["endpoints"][key]["scan_count"] += 1
        self._save()

    def mark_suspicious(self, method: str, path: str):
        key = self._endpoint_key(method, path)

        if key in self.memory["endpoints"]:
            self.memory["endpoints"][key]["suspicious"] = True
            self._save()

    def is_auth_endpoint(self, method: str, path: str) -> bool:
        path = path.lower()

        return any(x in path for x in [
            "login", "auth", "admin", "user", "account"
        ])

    # -----------------------------
    # PAYLOAD TRACKING
    # -----------------------------

    def _hash_response(self, response_text: str) -> str:
        return hashlib.sha256(response_text.encode()).hexdigest()

    def record_payload_result(
        self,
        method: str,
        path: str,
        payload: str,
        response_text: str,
        cluster_id: Optional[str],
        confidence: float
    ):
        endpoint_key = self._endpoint_key(method, path)
        response_hash = self._hash_response(response_text)

        entry = {
            "payload": payload,
            "response_hash": response_hash,
            "cluster_id": cluster_id,
            "confidence": confidence,
            "timestamp": time.time()
        }

        self.memory["payload_history"].setdefault(endpoint_key, [])
        self.memory["payload_history"][endpoint_key].append(entry)

        if confidence >= 0.7:
            self.memory["vulnerabilities"].setdefault(endpoint_key, [])
            self.memory["vulnerabilities"][endpoint_key].append(entry)

        self._save()

    def get_payload_history(self, method: str, path: str):
        key = self._endpoint_key(method, path)
        return self.memory["payload_history"].get(key, [])

    def has_similar_response(
        self,
        method: str,
        path: str,
        response_text: str
    ) -> bool:
        key = self._endpoint_key(method, path)
        response_hash = self._hash_response(response_text)

        history = self.memory["payload_history"].get(key, [])
        for item in history:
            if item["response_hash"] == response_hash:
                return True

        return False

    # -----------------------------
    # VULNERABILITY TRACKING
    # -----------------------------

    def get_vulnerabilities(self, method: str, path: str):
        key = self._endpoint_key(method, path)
        return self.memory["vulnerabilities"].get(key, [])

    def should_escalate(self, method: str, path: str) -> bool:
        key = self._endpoint_key(method, path)
        endpoint = self.memory["endpoints"].get(key)

        if not endpoint:
            return False

        if endpoint["suspicious"]:
            return True

        vuln_hits = len(self.memory["vulnerabilities"].get(key, []))
        return vuln_hits > 0