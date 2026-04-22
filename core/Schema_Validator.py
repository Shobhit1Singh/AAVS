import re


class SchemaAwareValidator:

    def validate(self, endpoint):
        findings = []

        path = endpoint["path"]
        method = endpoint["method"]
        params = endpoint.get("params", [])
        body = endpoint.get("request_body", {})
        security = endpoint.get("security", [])

        # ===================================
        # 1. AUTH CHECK
        # ===================================
        if security:
            findings.append({
                "type": "Auth Required Endpoint",
                "severity": "INFO"
            })
        else:
            findings.append({
                "type": "No Auth Declared",
                "severity": "MEDIUM"
            })

        # ===================================
        # 2. IDOR SURFACE
        # ===================================
        if re.search(r"{.*id.*}", path.lower()):
            findings.append({
                "type": "Object Reference Endpoint",
                "severity": "HIGH"
            })

        # ===================================
        # 3. STATE CHANGE WITHOUT AUTH
        # ===================================
        if method in ["POST", "PUT", "PATCH", "DELETE"] and not security:
            findings.append({
                "type": "State Changing Endpoint Without Security",
                "severity": "CRITICAL"
            })

        # ===================================
        # 4. BODY FIELD RISKS
        # ===================================
        body_text = str(body).lower()

        risky_fields = [
            "role",
            "price",
            "status",
            "admin",
            "user_id",
            "owner_id",
            "balance",
            "credit"
        ]

        for field in risky_fields:
            if field in body_text:
                findings.append({
                    "type": f"Sensitive Writable Field: {field}",
                    "severity": "HIGH"
                })

        return findings