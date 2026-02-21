from typing import Dict, List, Any
from faker import Faker
from attacks.payload import AttackPayloads
import logging

logger = logging.getLogger(__name__)
fake = Faker()


class AttackGenerator:

    def __init__(self):
        self.payloads = AttackPayloads()

    def _normalize_parameters(self, endpoint_details: Dict[str, Any]) -> Dict[str, List[Dict]]:
        params = endpoint_details.get("parameters", {})
        normalized = {"query": [], "path": [], "header": []}

        if isinstance(params, dict):
            for k in normalized:
                normalized[k] = params.get(k, [])
        elif isinstance(params, list):
            for p in params:
                loc = p.get("in")
                if loc in normalized:
                    normalized[loc].append(p)

        return normalized

    def generate_attacks_for_endpoint(self, endpoint_details: Dict[str, Any]) -> List[Dict[str, Any]]:
        attacks = []
        params = self._normalize_parameters(endpoint_details)

        for loc in ("query", "path", "header"):
            for param in params[loc]:
                attacks += self._generate_parameter_attacks(param, loc)

        if endpoint_details.get("request_body"):
            attacks += self._generate_body_attacks(endpoint_details["request_body"])

        unique = {self._hash_attack(a): a for a in attacks}
        result = list(unique.values())

        logger.info(f"Generated {len(result)} attack test cases")
        return result

    def _generate_parameter_attacks(self, param: Dict[str, Any], location: str) -> List[Dict[str, Any]]:
        name = param.get("name", "unknown")
        typ = param.get("type", "string")

        if typ == "string":
            attacks = self._string_attacks(name, param, location)
        elif typ == "integer":
            attacks = self._integer_attacks(name, location)
        elif typ == "boolean":
            attacks = self._boolean_attacks(name, location)
        elif typ == "array":
            attacks = self._array_attacks(name, location)
        else:
            attacks = []

        attacks += self._type_confusion_attacks(name, typ, location)
        return attacks

    def _string_attacks(self, name, param, loc):
        attacks = []
        attacks += [self._build("SQL Injection", "CRITICAL", name, loc, p) for p in self.payloads.SQL_INJECTION[:3]]
        attacks += [self._build("XSS", "HIGH", name, loc, p) for p in self.payloads.XSS_PAYLOADS[:2]]
        attacks += [self._build("Command Injection", "CRITICAL", name, loc, p) for p in self.payloads.COMMAND_INJECTION[:2]]
        attacks += [self._build("Path Traversal", "HIGH", name, loc, p) for p in self.payloads.PATH_TRAVERSAL[:2]]

        max_len = param.get("max_length")
        if max_len:
            attacks.append(self._build("Buffer Overflow", "MEDIUM", name, loc, "A" * min(max_len * 2, 5000)))

        return attacks

    def _integer_attacks(self, name, loc):
        return [self._build("Integer Overflow", "MEDIUM", name, loc, p) for p in self.payloads.INTEGER_ATTACKS[:5]]

    def _boolean_attacks(self, name, loc):
        vals = ["yes", "no", "1", "0", None]
        return [self._build("Type Confusion", "LOW", name, loc, v) for v in vals]

    def _array_attacks(self, name, loc):
        return [
            self._build("Empty Array", "LOW", name, loc, []),
            self._build("Resource Exhaustion", "HIGH", name, loc, list(range(1000)))
        ]

    def _type_confusion_attacks(self, name, typ, loc):
        wrong = {
            "string": [123, True, None],
            "integer": ["abc", None],
            "boolean": ["yes", 1]
        }
        return [self._build("Type Confusion", "MEDIUM", name, loc, v) for v in wrong.get(typ, [])]

    def _generate_body_attacks(self, request_body: Dict) -> List[Dict]:
        attacks = []
        schema = request_body.get("content", {}).get("application/json", {}).get("schema", {})
        props = schema.get("properties", {})

        for name, details in props.items():
            typ = details.get("type", "string")
            if typ == "string":
                attacks += self._string_attacks(name, details, "body")
            elif typ == "integer":
                attacks += self._integer_attacks(name, "body")

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

    def _hash_attack(self, a):
        return f"{a['attack_type']}_{a['param_name']}_{a['param_location']}_{str(a['payload'])}"