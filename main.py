from parser.api_parser import APIParser
from attacks.attack_generator import AttackGenerator
from attacks.auth_attacks import AuthAttackGenerator
from attacks.executor import TestExecutor
from attacks.ml_optimiser import MLPayloadOptimizer
from core.session_manager import SessionManager
from core.rate_limiter import RateLimiter
from colorama import Fore, Style
import json
import os
import time
import sys

sys.path.insert(0, 'C:\\AAVS')

API_SPEC = 'examples/simple_api.yaml'
BASE_URL = 'http://127.0.0.1:5000/api/v1'


def banner(title):
    print(f"\n{Fore.CYAN}{'='*70}")
    print(title)
    print(f"{'='*70}{Style.RESET_ALL}\n")


def get_parser():
    return APIParser(API_SPEC)


def demo_basic_parsing():
    banner("DEMO 1: Basic API Parsing")
    parser = get_parser()
    parser.print_summary()


def demo_endpoint_details():
    banner("DEMO 2: Endpoint Details")
    parser = get_parser()
    details = parser.get_endpoint_details('/users', 'POST')

    print(f"{Fore.GREEN}Endpoint:{Style.RESET_ALL} POST /users")
    print(f"{Fore.GREEN}Summary:{Style.RESET_ALL} {details['summary']}\n")

    if details['request_body']:
        print(f"{Fore.YELLOW}Request Body:{Style.RESET_ALL}")
        schema = details['request_body']['content'].get('application/json', {}).get('schema', {})
        properties = parser.extract_schema_properties(schema)

        for name, info in properties.items():
            required = "REQUIRED" if info['required'] else "OPTIONAL"
            print(f"  • {name} ({info['type']}) - {required}")


def demo_security_schemes():
    banner("DEMO 3: Security Schemes")
    parser = get_parser()
    security = parser.get_security_schemes()

    for name, scheme in security.items():
        print(f"• {name} | Type: {scheme.get('type')}")


def demo_attack_generation():
    banner("DEMO 4: Attack Pattern Generation")

    parser = get_parser()
    endpoint = parser.get_endpoint_details('/users', 'POST')

    generator = AttackGenerator()
    attacks = generator.generate_attacks_for_endpoint(endpoint)

    generator.print_attack_summary(attacks)

    with open('output/generated_attacks.json', 'w') as f:
        json.dump(attacks, f, indent=2)

    print(f"{Fore.GREEN}✓ Exported {len(attacks)} attacks{Style.RESET_ALL}")


def run_complete_scan():
    banner("API SECURITY FUZZER - COMPLETE SCAN")

    parser = get_parser()
    generator = AttackGenerator()

    endpoint = parser.get_endpoint_details('/users', 'POST')
    attacks = generator.generate_attacks_for_endpoint(endpoint)

    executor = TestExecutor(BASE_URL, timeout=5)

    results = executor.execute_all_attacks(
        attacks[:20],
        endpoint_path='/users',
        method='POST',
        delay=0.1
    )

    print(f"{Fore.GREEN}✓ Executed {len(results)} attacks{Style.RESET_ALL}")


def run_advanced_scan():
    banner("INTELLIGENT SCAN")

    parser = get_parser()
    generator = AttackGenerator()
    auth_generator = AuthAttackGenerator()
    optimizer = MLPayloadOptimizer()
    rate_limiter = RateLimiter(max_requests_per_second=5)
    executor = TestExecutor(BASE_URL, timeout=5)

    endpoint = parser.get_endpoint_details('/users', 'POST')
    attacks = generator.generate_attacks_for_endpoint(endpoint)[:20]

    results = []

    for attack in attacks:
        rate_limiter.wait_if_needed()
        result = executor.execute_attack(attack, '/users', 'POST')
        results.append(result)

        optimizer.add_training_data(
            str(attack.get('payload', '')),
            result.get('vulnerability_detected', False)
        )

        if result.get('status_code') == 429:
            rate_limiter.handle_rate_limit_response(
                result.get('response_headers', {})
            )

    print(f"{Fore.GREEN}✓ Intelligent scan executed on {len(results)} attacks{Style.RESET_ALL}")

    if optimizer.train():
        optimizer.save_model()


if __name__ == "__main__":
    os.makedirs('output', exist_ok=True)

    demo_basic_parsing()
    demo_endpoint_details()
    demo_security_schemes()
    demo_attack_generation()

    run_complete_scan()
    run_advanced_scan()
