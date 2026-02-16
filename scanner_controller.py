from parser.api_parser import APIParser
from attacks.attack_generator import AttackGenerator
from attacks.executor import TestExecutor
from analyser.response_analyser import ResponseAnalyzer
def run_scan(swagger_path):

    parser = APIParser(swagger_path)
    endpoints = parser.get_all_endpoints()
    attacker = AttackGenerator()
    executor = TestExecutor(parser.base_url)

    analyzer = ResponseAnalyzer()

    all_results = []

    for ep in endpoints:
        details = parser.get_endpoint_details(ep["path"], ep["method"])
        payloads = attacker.generate_attacks_for_endpoint(details)

        for payload in payloads:
            response = executor.execute_attack(
                attack=payload,
                endpoint_path=ep["path"],
                method=ep["method"]
            )

            result_data = {
                "url": ep["path"],
                "payload": payload,
                "response": response
            }

            all_results.append(result_data)

    findings = analyzer.analyze_all_results(all_results)
    return findings
    # return results


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
    findings = run_scan("C:/AAVS/vampi.yaml")

    for f in findings:
        print(f)
