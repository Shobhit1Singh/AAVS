import requests

class AuthManager:
    def __init__(self, login_url, username, password):
        self.login_url = login_url
        self.username = username
        self.password = password
        self.token = None

    def login(self):
        """
        Perform login and store JWT/session token.
        """
        resp = requests.post(
            self.login_url,
            json={"username": self.username, "password": self.password},
            timeout=10
        )
        if resp.status_code != 200:
            raise Exception(f"Login failed: {resp.status_code}")

        data = resp.json()
        # Adjust depending on crAPI: token may be in 'token' or 'access_token'
        self.token = data.get("token") or data.get("access_token")
        if not self.token:
            raise Exception("Login succeeded but token not found")

    def get_headers(self):
        """
        Return headers with authorization token for executor.
        """
        if not self.token:
            raise Exception("No auth token, call login() first")
        return {"Authorization": f"Bearer {self.token}"}