class AuthStrategyEngine:

    def __init__(self, auth_attacker):
        self.auth_attacker = auth_attacker

    def get_auth_payloads(self):
        payloads = []

        jwt_attacks = self.auth_attacker.generate_jwt_attacks()
        api_key_attacks = self.auth_attacker.generate_api_key_attacks()

        for attack in jwt_attacks:
            for token in attack.get("payloads", []):
                if token:
                    payloads.append({
                        "headers": {"Authorization": f"Bearer {token}"},
                        "__family__": "auth_jwt"
                    })

        for attack in api_key_attacks:
            for key in attack.get("payloads", []):
                payloads.append({
                    "headers": {"X-API-Key": key},
                    "__family__": "auth_apikey"
                })

        return payloads