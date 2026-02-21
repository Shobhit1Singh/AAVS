"""
Endpoint Risk Scoring Engine
Assigns risk scores to endpoints and parameters based on method, auth, and parameter types.
"""

import re

class EndpointRiskScorer:

    def __init__(self):
        # Base scores
        self.method_scores = {
            "GET": 1,
            "POST": 3,
            "PUT": 2,
            "DELETE": 4,
            "PATCH": 3
        }

        self.sensitive_keywords = [
            "admin", "user", "password", "token", "auth", "credit", "card", "id", "session"
        ]

        self.param_type_scores = {
            "string": 1,
            "int": 2,
            "uuid": 3,
            "file": 4,
            "boolean": 0.5
        }

        self.auth_required_score = 2  # extra score if endpoint requires auth

    def score_endpoint(self, endpoint_details: dict) -> dict:
        """
        endpoint_details: {
            "path": str,
            "method": str,
            "parameters": [
                {"name": str, "type": str, "location": str}
            ],
            "auth_required": bool
        }
        returns: endpoint_details with 'risk_score' added
        """
        score = 0

        # Base score by HTTP method
        score += self.method_scores.get(endpoint_details.get("method", "GET").upper(), 1)

        # Extra if auth required
        if endpoint_details.get("auth_required"):
            score += self.auth_required_score

        # Parameter scoring
        param_scores = []
        for param in endpoint_details.get("parameters", []):
            ps = self.param_type_scores.get(param.get("type", "string"), 1)
            # Boost if param name has sensitive keywords
            for kw in self.sensitive_keywords:
                if re.search(rf"\b{kw}\b", param.get("name", ""), re.IGNORECASE):
                    ps += 2
                    break
            param_scores.append(ps)

        score += sum(param_scores)
        endpoint_details["risk_score"] = round(score, 2)

        return endpoint_details

    def rank_endpoints(self, endpoints: list) -> list:
        """
        Rank multiple endpoints by risk_score descending
        """
        scored = [self.score_endpoint(ep) for ep in endpoints]
        scored.sort(key=lambda x: x["risk_score"], reverse=True)
        return scored


if __name__ == "__main__":
    # Example usage
    endpoints = [
        {
            "path": "/login",
            "method": "POST",
            "parameters": [{"name": "email", "type": "string", "location": "body"},
                           {"name": "password", "type": "string", "location": "body"}],
            "auth_required": False
        },
        {
            "path": "/user/{id}/update",
            "method": "PUT",
            "parameters": [{"name": "id", "type": "uuid", "location": "path"},
                           {"name": "admin", "type": "boolean", "location": "body"}],
            "auth_required": True
        }
    ]

    scorer = EndpointRiskScorer()
    ranked = scorer.rank_endpoints(endpoints)
    for ep in ranked:
        print(ep)