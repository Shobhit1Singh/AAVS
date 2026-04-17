import random


class AttackGenerator:
    """
    Generates synthetic attack payloads for security testing.
    Payloads are designed to simulate common vulnerability patterns
    (SQLi, XSS, path traversal, weak auth) without executing harmful commands.
    """

    def __init__(self):

        # Simulated SQL injection payloads
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT null--",
            "' OR 'a'='a",
            "' OR ''='",
            "' OR 1=1#",
            "' OR 1=1/*",
            "'; SELECT * FROM fake_table--"
        ]

        # Simulated XSS payloads
        self.xss_payloads = [
            "<script>alert('test')</script>",
            "<img src=x onerror=alert('test')>",
            "\"><script>alert('test')</script>",
            "<svg/onload=alert('test')>",
            "<body onload=alert('test')>",
            "<iframe src=javascript:alert('test')>",
            "<details open ontoggle=alert('test')>",
            "<math href='javascript:alert(\"test\")'>"
        ]

        # Simulated path traversal payloads
        self.path_payloads = [
            "../../fake/file.txt",
            "../../../fake/file.txt",
            "../../../../fake/file.txt",
            "..\\..\\..\\windows\\fake.ini",
            "/fake/etc/passwd",
            "/fake/proc/self/environ",
            "../../../../../../fake/shadow",
            "..%2f..%2f..%2ffake%2fpasswd"
        ]

        # Simulated authentication bypass attempts
        self.auth_bypass = [
            "",
            "null",
            "admin",
            "administrator",
            "' OR 1=1--",
            "' OR 'admin'='admin",
            "true",
            "1"
        ]

    def _build_payload(self, param, location, payload, method):
        """
        Convert raw payload into executor-compatible structure.
        """

        name = param.get("name")
        loc = param.get("in", location)

        if loc == "query":
            return {"params": {name: payload}}

        if loc == "path":
            return {"path_params": {name: payload}}

        if loc == "header":
            return {"headers": {name: str(payload)}}

        return {"body": {name: payload}}

    def generate_for_endpoint(self, endpoint):
        """
        Generate attack cases for a given endpoint definition.
        """

        params = endpoint.get("parameters", [])
        method = endpoint.get("method", "GET").upper()

        attacks = []

        payload_groups = [
            self.sql_payloads,
            self.xss_payloads,
            self.path_payloads,
            self.auth_bypass
        ]

        for param in params:
            location = param.get("in", "query")
            for group in payload_groups:
                for payload in group:
                    attack = self._build_payload(param, location, payload, method)
                    attack["__family__"] = group[0]  # loosely tag family
                    attacks.append(attack)

        return attacks


class AdaptiveAttackGenerator:
    """
    Extends AttackGenerator with safe mutations to diversify payloads.
    """

    def __init__(self):
        self.base = AttackGenerator()

    def expand(self, endpoint):
        base_cases = self.base.generate_for_endpoint(endpoint)

        mutations = [
            lambda x: x + "'",
            lambda x: x + "\"",
            lambda x: x + "--",
            lambda x: x.upper(),
            lambda x: x.lower(),
            lambda x: x.replace(" ", "%20"),
            lambda x: x + "%00",
            lambda x: x + "%0a",
            lambda x: x[::-1],  # reverse string
            lambda x: f"/*{x}*/",  # wrap in comment
            lambda x: f"<div>{x}</div>",  # wrap in HTML
            lambda x: f"{{\"payload\":\"{x}\"}}",  # JSON wrapper
            lambda x: x.encode("utf-8").hex(),  # hex encoding
            lambda x: "".join(["%" + hex(ord(c))[2:] for c in x])  # URL encoding
        ]

        expanded = []

        for case in base_cases:
            expanded.append(case)
            for key in ["params", "body", "headers", "path_params"]:
                if key in case:
                    for param_name, value in case[key].items():
                        for m in mutations:
                            mutated = dict(case)
                            mutated[key] = dict(case[key])
                            mutated[key][param_name] = m(str(value))
                            expanded.append(mutated)

        random.shuffle(expanded)
        return expanded


def generate_attack_cases(endpoint):
    generator = AdaptiveAttackGenerator()
    return generator.expand(endpoint)
