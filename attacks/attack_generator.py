from typing import Dict, List, Any
from faker import Faker
from attacks.payload import AttackPayloads
import random
import logging
import re

logger = logging.getLogger(__name__)
fake = Faker()


class AttackGenerator:

    def __init__(self):
        self.payloads = AttackPayloads()

    # -----------------------------
    # Public Entry
    # -----------------------------

    def generate_attacks_for_endpoint(self, endpoint_details: Dict[str, Any]) -> List[Dict[str, Any]]:

        attacks = []
        params = self._normalize_parameters(endpoint_details)

        context = {
            "method": endpoint_details.get("method", "").lower(),
            "path": endpoint_details.get("path", "").lower()
        }

        # Parameter attacks (query, path, header)
        for loc in ("query", "path", "header"):
            for param in params[loc]:
                attacks += self._generate_parameter_attacks(param, loc, context)

        # Body attacks
        request_body = endpoint_details.get("request_body")
        if request_body:
            # If Postman raw body (string), wrap in dict
            if isinstance(request_body, str):
                request_body = {"raw": request_body}
            attacks += self._generate_body_attacks(request_body, context)

        # Deduplicate
        unique = {self._hash_attack(a): a for a in attacks}
        result = list(unique.values())

        logger.info(f"Generated {len(result)} adaptive attack cases")
        return result

    # -----------------------------
    # Parameter Handling
    # -----------------------------

    def _normalize_parameters(self, endpoint_details: Dict[str, Any]) -> Dict[str, List[Dict]]:
        params = endpoint_details.get("parameters", {})
        normalized = {"query": [], "path": [], "header": []}

        # Convert dict to list
        if isinstance(params, dict):
            for k in normalized:
                normalized[k] = []
                for name, value in params.get(k, {}).items():
                    normalized[k].append({"name": name, "example": value, "type": "string"})
        elif isinstance(params, list):
            for p in params:
                loc = p.get("in")
                if loc in normalized:
                    normalized[loc].append(p)

        # For Postman query strings
        query = endpoint_details.get("query", {})
        if query:
            for k, v in query.items():
                normalized["query"].append({"name": k, "example": v[0] if isinstance(v, list) else v, "type": "string"})

        return normalized

    # -----------------------------
    # Parameter Attack Generation
    # -----------------------------

    def _generate_parameter_attacks(self, param: Dict[str, Any], location: str, context: Dict) -> List[Dict]:

        name = param.get("name", "unknown")
        typ = param.get("type", "string")

        attacks = []

        if typ == "string":
            attacks += self._adaptive_string_attacks(name, param, location, context)

        elif typ == "integer":
            attacks += self._adaptive_integer_attacks(name, param, location)

        elif typ == "boolean":
            attacks += self._boolean_confusion_attacks(name, location)

        elif typ == "array":
            attacks += self._array_stress_attacks(name, location)

        attacks += self._type_confusion_attacks(name, typ, location)

        return attacks

    # -----------------------------
    # Adaptive String Attacks
    # -----------------------------

    def _adaptive_string_attacks(self, name, param, loc, context):

        attacks = []
        lower_name = name.lower()

        base_sets = []

        if re.search(r"id|user|account", lower_name):
            base_sets += self.payloads.INTEGER_ATTACKS[:5]

        if re.search(r"url|redirect|callback", lower_name):
            base_sets += ["https://evil.com", "//evil.com"]

        if re.search(r"file|path", lower_name):
            base_sets += self.payloads.PATH_TRAVERSAL[:3]

        if re.search(r"search|query|filter", lower_name):
            base_sets += self.payloads.SQL_INJECTION[:4]

        if not base_sets:
            base_sets += self.payloads.SQL_INJECTION[:2]
            base_sets += self.payloads.XSS_PAYLOADS[:2]

        mutated = self._mutate_payloads(base_sets)

        for payload in mutated:
            attacks.append(self._build("Adaptive Injection", "HIGH", name, loc, payload))

        max_len = param.get("max_length")
        if max_len:
            overflow = "A" * min(max_len * 3, 10000)
            attacks.append(self._build("Length Overflow", "MEDIUM", name, loc, overflow))

        return attacks

    # -----------------------------
    # Integer Attacks
    # -----------------------------

    def _adaptive_integer_attacks(self, name, param, loc):

        attacks = []
        minimum = param.get("minimum", 0)
        maximum = param.get("maximum", 100000)

        boundaries = [
            minimum - 1,
            maximum + 1,
            2**31 - 1,
            -2**31,
            999999999999
        ]

        for value in boundaries:
            attacks.append(self._build("Boundary Violation", "MEDIUM", name, loc, value))

        return attacks

    # -----------------------------
    # Boolean Attacks
    # -----------------------------

    def _boolean_confusion_attacks(self, name, loc):
        variants = ["true", "false", "1", "0", "yes", None, 999]
        return [self._build("Boolean Confusion", "LOW", name, loc, v) for v in variants]

    # -----------------------------
    # Array Attacks
    # -----------------------------

    def _array_stress_attacks(self, name, loc):
        return [
            self._build("Empty Array", "LOW", name, loc, []),
            self._build("Array Amplification", "HIGH", name, loc, list(range(5000)))
        ]

    # -----------------------------
    # Type Confusion
    # -----------------------------

    def _type_confusion_attacks(self, name, typ, loc):
        wrong = {
            "string": [123, True, None],
            "integer": ["abc", None],
            "boolean": ["true", 1, "no"]
        }
        return [self._build("Type Confusion", "MEDIUM", name, loc, v) for v in wrong.get(typ, [])]

    # -----------------------------
    # Body Attacks (Unified for Postman/OpenAPI)
    # -----------------------------

    def _generate_body_attacks(self, request_body: Dict, context: Dict) -> List[Dict]:

        attacks = []

        # If raw Postman string
        if "raw" in request_body:
            body = request_body["raw"]
            attacks.append(self._build("Raw Body Injection", "HIGH", "body", "body", body))
            # Simple mutation
            mutated = body + "' OR 1=1 --"
            attacks.append(self._build("Raw Body Mutation", "HIGH", "body", "body", mutated))
            return attacks

        # OpenAPI schema-based body
        schema = request_body.get("content", {}).get("application/json", {}).get("schema", {})
        baseline_body = self._generate_valid_body(schema)

        if baseline_body:
            attacks.append(self._build("Baseline Body", "INFO", "body", "body", baseline_body))
            for key in baseline_body:
                mutated = baseline_body.copy()
                mutated[key] = self._mutate_single_value(mutated[key])
                attacks.append(self._build("Field Mutation", "HIGH", key, "body", mutated))

        return attacks

    # -----------------------------
    # Body Generators
    # -----------------------------

    def _generate_valid_body(self, schema):

        if not schema:
            return {}

        props = schema.get("properties", {})
        body = {}

        for name, details in props.items():
            typ = details.get("type", "string")

            if typ == "string":
                body[name] = fake.word()
            elif typ == "integer":
                body[name] = random.randint(1, 100)
            elif typ == "boolean":
                body[name] = True
            elif typ == "array":
                body[name] = []
            elif typ == "object":
                body[name] = self._generate_valid_body(details)

        return body

    # -----------------------------
    # Mutation Engine
    # -----------------------------

    def _mutate_payloads(self, payloads):
        mutated = []
        for p in payloads:
            mutated.append(p)
            mutated.append(str(p) + "'")
            mutated.append(str(p) + "--")
            mutated.append(str(p) * 2)
        return mutated

    def _mutate_single_value(self, value):
        if isinstance(value, str):
            return value + "' OR 1=1 --"
        if isinstance(value, int):
            return value * 99999
        if isinstance(value, bool):
            return not value
        return None

    # -----------------------------
    # Builder + Hash
    # -----------------------------

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