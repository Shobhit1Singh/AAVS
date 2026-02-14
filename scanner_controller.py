from parser.api_parser import APIParser
from attacks.attack_generator import AttackGenerator
from attacks.executor import TestExecutor

def run_scan(swagger_path):

    parser = APIParser(swagger_path)
    endpoints = parser.get_all_endpoints()
    attacker = AttackGenerator()
    executor = TestExecutor(parser.base_url)

    results = []

    for ep in endpoints:
        url = ep["path"]
        method = ep["method"]
        params = ep.get("params", [])
        details = parser.get_endpoint_details(ep["path"], ep["method"])
        payloads = attacker.generate_attacks_for_endpoint(details)


        for payload in payloads:
            response = executor.execute_attack(
             attack=payload,
            endpoint_path=ep["path"],
            method=ep["method"]
            )

            finding = analyze_response(url, payload, response)
            if finding:
                results.append(finding)

    return results


def analyze_response(url, payload, response):

    text = response.get("response_body","").lower()

    if "sql" in text or "syntax error" in text:
        return {
            "url": url,
            "payload": payload,
            "issue": "Possible SQL Injection"
        }

    if response.get("status_code") == 500:
        return {
            "url": url,
            "payload": payload,
            "issue": "Server Crash Detected"
        }

    return None


if __name__ == "__main__":
    findings = run_scan("openapi3.yml")

    for f in findings:
        print(f)
