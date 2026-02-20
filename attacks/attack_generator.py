"""
Attack Generator Module
Generates attack test cases based on API schema
"""

from typing import Dict, List, Any
from faker import Faker
from attacks.payload import AttackPayloads
import logging
from colorama import Fore, Style

logger = logging.getLogger(__name__)
fake = Faker()


class AttackGenerator:

    def __init__(self):
        self.payloads = AttackPayloads()

    def _normalize_parameters(self, endpoint_details: Dict[str, Any]) -> Dict[str, List[Dict]]:
        params = endpoint_details.get("parameters", {})

        normalized = {
            "query": [],
            "path": [],
            "header": []
        }

        if isinstance(params, dict):
            for key in normalized:
                normalized[key] = params.get(key, [])

        elif isinstance(params, list):
            for p in params:
                loc = p.get("in")
                if loc in normalized:
                    normalized[loc].append(p)

        return normalized

    def generate_attacks_for_endpoint(self, endpoint_details: Dict[str, Any]) -> List[Dict[str, Any]]:
        attacks = []

        params = self._normalize_parameters(endpoint_details)

        for param in params["query"]:
            attacks.extend(self._generate_parameter_attacks(param, "query"))

        for param in params["path"]:
            attacks.extend(self._generate_parameter_attacks(param, "path"))

        for param in params["header"]:
            attacks.extend(self._generate_parameter_attacks(param, "header"))

        if endpoint_details.get("request_body"):
            attacks.extend(self._generate_body_attacks(endpoint_details["request_body"]))

        logger.info(f"Generated {len(attacks)} attack test cases")
        return attacks

    def _generate_parameter_attacks(self, param: Dict[str, Any], location: str) -> List[Dict[str, Any]]:
        attacks = []
        param_name = param.get("name", "unknown")
        param_type = param.get("type", "string")

        if param_type == "string":
            attacks.extend(self._string_attacks(param_name, param, location))
        elif param_type == "integer":
            attacks.extend(self._integer_attacks(param_name, param, location))
        elif param_type == "boolean":
            attacks.extend(self._boolean_attacks(param_name, location))
        elif param_type == "array":
            attacks.extend(self._array_attacks(param_name, location))

        attacks.extend(self._type_confusion_attacks(param_name, param_type, location))

        return attacks

    def _string_attacks(self, name: str, param: Dict, loc: str) -> List[Dict]:
        attacks = []

        for payload in self.payloads.SQL_INJECTION[:5]:
            attacks.append(self._build("SQL Injection", "CRITICAL", name, loc, payload))

        for payload in self.payloads.XSS_PAYLOADS[:3]:
            attacks.append(self._build("XSS", "HIGH", name, loc, payload))

        for payload in self.payloads.COMMAND_INJECTION[:3]:
            attacks.append(self._build("Command Injection", "CRITICAL", name, loc, payload))

        for payload in self.payloads.PATH_TRAVERSAL[:3]:
            attacks.append(self._build("Path Traversal", "HIGH", name, loc, payload))

        if param.get("max_length"):
            max_len = param["max_length"]
            attacks.append(self._build("Buffer Overflow", "MEDIUM", name, loc, "A" * (max_len * 2)))

        return attacks

    def _integer_attacks(self, name: str, param: Dict, loc: str) -> List[Dict]:
        attacks = []
        for payload in self.payloads.INTEGER_ATTACKS:
            attacks.append(self._build("Integer Overflow", "MEDIUM", name, loc, payload))
        return attacks

    def _boolean_attacks(self, name: str, loc: str) -> List[Dict]:
        attacks = []
        for payload in ["yes", "no", "1", "0", None]:
            attacks.append(self._build("Type Confusion", "LOW", name, loc, payload))
        return attacks

    def _array_attacks(self, name: str, loc: str) -> List[Dict]:
        return [
            self._build("Empty Array", "LOW", name, loc, []),
            self._build("Resource Exhaustion", "HIGH", name, loc, list(range(100000)))
        ]

    def _type_confusion_attacks(self, name: str, typ: str, loc: str) -> List[Dict]:
        wrong = {
            "string": [123, True, None],
            "integer": ["abc", None],
            "boolean": ["yes", 1],
        }

        return [
            self._build("Type Confusion", "MEDIUM", name, loc, v)
            for v in wrong.get(typ, [])
        ]

    def _generate_body_attacks(self, request_body: Dict) -> List[Dict]:
        attacks = []

        schema = request_body.get("content", {}).get("application/json", {}).get("schema", {})
        props = schema.get("properties", {})

        for name, details in props.items():
            typ = details.get("type", "string")
            if typ == "string":
                attacks.extend(self._string_attacks(name, details, "body"))
            elif typ == "integer":
                attacks.extend(self._integer_attacks(name, details, "body"))

        return attacks

    def _build(self, attack_type, severity, name, loc, payload):
        return {
            "attack_type": attack_type,
            "severity": severity,
            "param_name": name,
            "param_location": loc,
            "payload": payload,
            "expected_safe_behavior": "Input should be validated"
        }

    def print_attack_summary(self, attacks: List[Dict]):
        print(f"\n{Fore.CYAN}{'='*70}")
        print("GENERATED ATTACK TEST CASES")
        print(f"{'='*70}{Style.RESET_ALL}\n")

        counts = {}
        for a in attacks:
            counts[a["attack_type"]] = counts.get(a["attack_type"], 0) + 1

        print(f"{Fore.YELLOW}Total Attacks:{Style.RESET_ALL} {len(attacks)}\n")

        for t, c in sorted(counts.items(), key=lambda x: -x[1]):
            print(f"{t:30} : {c}")

        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")