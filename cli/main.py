#!/usr/bin/env python3
"""
API Security Fuzzer - Command Line Interface
Professional security testing tool for REST APIs
"""

import click
import yaml
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import box
import logging

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from fuzzer.parser.api_parser import APIParser
from fuzzer.attacks.attack_generator import AttackGenerator
from fuzzer.attacks.auth_attacks import AuthAttackGenerator
from fuzzer.attacks.executor import TestExecutor
from fuzzer.attacks.ml_optimizer import MLPayloadOptimizer
from fuzzer.analyzer.response_analyzer import ResponseAnalyzer
from fuzzer.analyzer.reporter import ReportGenerator
from fuzzer.core.session_manager import SessionManager
from fuzzer.core.rate_limiter import RateLimiter

console = Console()

# ASCII Art Banner
BANNER = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║     █████╗ ██████╗ ██╗    ███████╗██╗   ██╗███████╗███████╗     ║
║    ██╔══██╗██╔══██╗██║    ██╔════╝██║   ██║╚══███╔╝╚══███╔╝     ║
║    ███████║██████╔╝██║    █████╗  ██║   ██║  ███╔╝   ███╔╝      ║
║    ██╔══██║██╔═══╝ ██║    ██╔══╝  ██║   ██║ ███╔╝   ███╔╝       ║
║    ██║  ██║██║     ██║    ██║     ╚██████╔╝███████╗███████╗     ║
║    ╚═╝  ╚═╝╚═╝     ╚═╝    ╚═╝      ╚═════╝ ╚══════╝╚══════╝     ║
║                                                                   ║
║              API Security Fuzzer & Vulnerability Scanner         ║
║                         Version 1.0.0                            ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
"""


def print_banner():
    """Print fancy banner"""
    console.print(BANNER, style="bold cyan")


def load_config(config_path: str) -> dict:
    """Load configuration from YAML file"""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        console.print(f"[red]✗ Config file not found: {config_path}[/red]")
        sys.exit(1)
    except yaml.YAMLError as e:
        console.print(f"[red]✗ Invalid YAML config: {e}[/red]")
        sys.exit(1)


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """
    API Security Fuzzer - Automated API vulnerability scanner
    
    Find security vulnerabilities in REST APIs through intelligent fuzzing.
    """
    pass


@cli.command()
@click.option('--spec', '-s', required=True, help='OpenAPI/Swagger specification file')
@click.option('--base-url', '-u', required=True, help='Base URL of the API')
@click.option('--output', '-o', default='output/reports', help='Output directory for reports')
@click.option('--config', '-c', help='Configuration file (YAML)')
@click.option('--endpoints', '-e', multiple=True, help='Specific endpoints to test (e.g., "GET /users")')
@click.option('--auth-token', help='Bearer token for authentication')
@click.option('--api-key', help='API key for authentication')
@click.option('--rate-limit', default=10, help='Max requests per second (default: 10)')
@click.option('--timeout', default=10, help='Request timeout in seconds (default: 10)')
@click.option('--ml/--no-ml', default=True, help='Use ML optimization (default: enabled)')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(spec, base_url, output, config, endpoints, auth_token, api_key, rate_limit, timeout, ml, verbose):
    """
    Run a complete security scan on an API
    
    Example:
        apifuzz scan -s api.yaml -u https://api.example.com
    """
    print_banner()
    
    # Setup logging
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    # Load config if provided
    cfg = {}
    if config:
        cfg = load_config(config)
        console.print(f"[green]✓ Loaded config: {config}[/green]")
    
    # Merge CLI args with config
    base_url = cfg.get('target', {}).get('base_url', base_url)
    auth_token = cfg.get('auth', {}).get('bearer_token', auth_token)
    api_key = cfg.get('auth', {}).get('api_key', api_key)
    
    console.print(Panel.fit(
        f"[bold]Target:[/bold] {base_url}\n"
        f"[bold]Spec:[/bold] {spec}\n"
        f"[bold]Output:[/bold] {output}",
        title="[bold cyan]Scan Configuration[/bold cyan]",
        border_style="cyan"
    ))
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        # Step 1: Parse API
        task1 = progress.add_task("[cyan]Parsing API specification...", total=None)
        try:
            parser = APIParser(spec)
            api_info = parser.get_api_info()
            all_endpoints = parser.get_all_endpoints()
            progress.update(task1, completed=True)
            console.print(f"[green]✓ Parsed {len(all_endpoints)} endpoints[/green]")
        except Exception as e:
            console.print(f"[red]✗ Failed to parse spec: {e}[/red]")
            sys.exit(1)
        
        # Step 2: Setup authentication
        task2 = progress.add_task("[cyan]Configuring authentication...", total=None)
        session_mgr = SessionManager(base_url)
        
        if auth_token:
            session_mgr.authenticate_bearer(auth_token)
        elif api_key:
            session_mgr.authenticate_api_key(api_key)
        
        progress.update(task2, completed=True)
        console.print("[green]✓ Authentication configured[/green]")
        
        # Step 3: Setup rate limiter
        task3 = progress.add_task("[cyan]Initializing rate limiter...", total=None)
        rate_limiter = RateLimiter(max_requests_per_second=rate_limit)
        progress.update(task3, completed=True)
        console.print(f"[green]✓ Rate limit: {rate_limit} req/s[/green]")
        
        # Step 4: Generate attacks
        task4 = progress.add_task("[cyan]Generating attack patterns...", total=None)
        generator = AttackGenerator()
        auth_generator = AuthAttackGenerator()
        
        all_attacks = []
        
        # Filter endpoints if specified
        endpoints_to_test = all_endpoints
        if endpoints:
            endpoints_to_test = [
                ep for ep in all_endpoints 
                if f"{ep['method']} {ep['path']}" in endpoints
            ]
        
        for endpoint in endpoints_to_test:
            details = parser.get_endpoint_details(endpoint['path'], endpoint['method'])
            attacks = generator.generate_attacks_for_endpoint(details)
            all_attacks.extend(attacks)
        
        progress.update(task4, completed=True)
        console.print(f"[green]✓ Generated {len(all_attacks)} attack test cases[/green]")
        
        # Step 5: ML optimization
        if ml:
            task5 = progress.add_task("[cyan]Optimizing with ML...", total=None)
            optimizer = MLPayloadOptimizer()
            optimizer.load_model()
            progress.update(task5, completed=True)
            console.print("[green]✓ ML optimizer ready[/green]")
        
        # Step 6: Execute attacks
        console.print("\n[bold yellow]Starting attack execution...[/bold yellow]\n")
        
        executor = TestExecutor(base_url, timeout=timeout)
        results = []
        
        attack_progress = progress.add_task(
            "[cyan]Executing attacks...", 
            total=len(all_attacks)
        )
        
        for i, attack in enumerate(all_attacks):
            rate_limiter.wait_if_needed()
            
            # Get endpoint details
            endpoint = endpoints_to_test[i % len(endpoints_to_test)]
            
            result = executor.execute_attack(
                attack, 
                endpoint['path'], 
                endpoint['method']
            )
            results.append(result)
            
            # Update ML if enabled
            if ml:
                optimizer.add_training_data(
                    str(attack.get('payload', '')),
                    result.get('vulnerability_detected', False)
                )
            
            # Handle rate limits
            if result.get('status_code') == 429:
                rate_limiter.handle_rate_limit_response(
                    result.get('response_headers', {})
                )
            
            progress.update(attack_progress, advance=1)
        
        progress.update(attack_progress, completed=True)
        
        # Step 7: Analyze results
        task7 = progress.add_task("[cyan]Analyzing responses...", total=None)
        analyzer = ResponseAnalyzer()
        analyzer.analyze_all_results(results)
        progress.update(task7, completed=True)
        
        # Step 8: Generate reports
        task8 = progress.add_task("[cyan]Generating reports...", total=None)
        reporter = ReportGenerator(output)
        
        vulnerabilities = analyzer.get_vulnerabilities()
        stats = analyzer.get_statistics()
        
        json_report = reporter.generate_json_report(vulnerabilities, stats, api_info)
        text_report = reporter.generate_text_report(vulnerabilities, stats, api_info)
        html_report = reporter.generate_html_report(vulnerabilities, stats, api_info)
        
        progress.update(task8, completed=True)
        
        # Train and save ML model
        if ml and len(results) > 10:
            optimizer.train()
            optimizer.save_model()
    
    # Print summary
    console.print("\n")
    console.print(Panel.fit(
        f"[bold]Attacks Executed:[/bold] {len(results)}\n"
        f"[bold]Vulnerabilities Found:[/bold] {len(vulnerabilities)}\n"
        f"[bold]Reports Generated:[/bold] 3 (JSON, TXT, HTML)",
        title="[bold green]✓ Scan Complete[/bold green]",
        border_style="green"
    ))
    
    # Vulnerability summary table
    if vulnerabilities:
        console.print("\n[bold red]⚠ VULNERABILITIES DETECTED[/bold red]\n")
        
        table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        table.add_column("Severity", style="bold")
        table.add_column("Type", style="cyan")
        table.add_column("Endpoint", style="yellow")
        table.add_column("Parameter", style="green")
        
        for vuln in vulnerabilities[:10]:  # Show first 10
            severity_style = {
                'CRITICAL': 'bold red',
                'HIGH': 'bold yellow',
                'MEDIUM': 'bold blue',
                'LOW': 'bold green',
            }.get(vuln['severity'], 'white')
            
            table.add_row(
                f"[{severity_style}]{vuln['severity']}[/{severity_style}]",
                vuln['attack_type'],
                f"{vuln['method']} {vuln['url'][:40]}",
                vuln['param_name']
            )
        
        console.print(table)
        
        if len(vulnerabilities) > 10:
            console.print(f"\n[yellow]... and {len(vulnerabilities) - 10} more[/yellow]")
    else:
        console.print("\n[bold green]✓ No vulnerabilities detected[/bold green]")
    
    console.print(f"\n[bold cyan]Reports saved to:[/bold cyan] {output}\n")


@cli.command()
@click.argument('spec_file')
def parse(spec_file):
    """
    Parse and display API specification details
    
    Example:
        apifuzz parse api.yaml
    """
    print_banner()
    
    try:
        parser = APIParser(spec_file)
        parser.print_summary()
        
        # Show endpoints in table
        endpoints = parser.get_all_endpoints()
        
        table = Table(show_header=True, header_style="bold cyan", box=box.ROUNDED)
        table.add_column("Method", style="bold")
        table.add_column("Path", style="cyan")
        table.add_column("Summary", style="white")
        
        for ep in endpoints:
            method_style = {
                'GET': 'green',
                'POST': 'blue',
                'PUT': 'yellow',
                'DELETE': 'red',
                'PATCH': 'magenta',
            }.get(ep['method'], 'white')
            
            table.add_row(
                f"[{method_style}]{ep['method']}[/{method_style}]",
                ep['path'],
                ep['summary'][:50]
            )
        
        console.print("\n")
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]✗ Failed to parse spec: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--type', '-t', 
              type=click.Choice(['jwt', 'oauth', 'apikey', 'all']),
              default='all',
              help='Type of authentication attacks')
def list_attacks(type):
    """
    List available attack patterns
    
    Example:
        apifuzz list-attacks --type jwt
    """
    print_banner()
    
    auth_gen = AuthAttackGenerator()
    
    if type in ['jwt', 'all']:
        console.print("\n[bold cyan]JWT Attack Patterns:[/bold cyan]\n")
        jwt_attacks = auth_gen.generate_jwt_attacks()
        
        table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE)
        table.add_column("Attack Type", style="cyan")
        table.add_column("Severity", style="bold")
        table.add_column("Description")
        
        for attack in jwt_attacks:
            severity_style = {
                'CRITICAL': 'bold red',
                'HIGH': 'bold yellow',
                'MEDIUM': 'bold blue',
                'LOW': 'bold green',
            }.get(attack['severity'], 'white')
            
            table.add_row(
                attack['attack_type'],
                f"[{severity_style}]{attack['severity']}[/{severity_style}]",
                attack['description']
            )
        
        console.print(table)
    
    if type in ['oauth', 'all']:
        console.print("\n[bold cyan]OAuth Attack Patterns:[/bold cyan]\n")
        oauth_attacks = auth_gen.generate_oauth_attacks()
        
        for attack in oauth_attacks:
            console.print(f"[cyan]• {attack['attack_type']}[/cyan] - {attack['description']}")
    
    if type in ['apikey', 'all']:
        console.print("\n[bold cyan]API Key Attack Patterns:[/bold cyan]\n")
        apikey_attacks = auth_gen.generate_api_key_attacks()
        
        for attack in apikey_attacks:
            console.print(f"[cyan]• {attack['attack_type']}[/cyan] - {attack['description']}")


@cli.command()
def init():
    """
    Initialize a new project with example configs
    
    Example:
        apifuzz init
    """
    print_banner()
    
    console.print("\n[bold cyan]Initializing API Fuzzer project...[/bold cyan]\n")
    
    # Create directories
    dirs = ['configs', 'output/reports', 'output/ml_models']
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        console.print(f"[green]✓ Created directory: {dir_path}[/green]")
    
    # Create example config
    example_config = """# API Fuzzer Configuration
# Save this file and run: apifuzz scan -c config.yaml

target:
  base_url: https://api.example.com/v1
  spec_file: path/to/openapi.yaml

auth:
  # Choose one authentication method
  bearer_token: your_jwt_token_here
  # api_key: your_api_key_here
  # basic:
  #   username: admin
  #   password: password123

scan:
  rate_limit: 10  # requests per second
  timeout: 10     # seconds
  use_ml: true    # Enable ML optimization
  
  # Specific endpoints to test (optional)
  # endpoints:
  #   - "GET /users"
  #   - "POST /users"

attacks:
  # Enable/disable attack categories
  sql_injection: true
  xss: true
  command_injection: true
  auth_bypass: true
  
output:
  directory: output/reports
  formats:
    - json
    - html
    - txt
"""
    
    config_path = Path('configs/example_target.yaml')
    with open(config_path, 'w') as f:
        f.write(example_config)
    
    console.print(f"[green]✓ Created example config: {config_path}[/green]")
    
    console.print("\n[bold green]✓ Project initialized successfully![/bold green]")
    console.print("\n[yellow]Next steps:[/yellow]")
    console.print("  1. Edit configs/example_target.yaml with your API details")
    console.print("  2. Run: apifuzz scan -c configs/example_target.yaml")


@cli.command()
@click.argument('report_file')
def view(report_file):
    """
    View a generated report
    
    Example:
        apifuzz view output/reports/report.json
    """
    try:
        import json
        
        with open(report_file, 'r') as f:
            report = json.load(f)
        
        console.print(Panel.fit(
            f"[bold]API:[/bold] {report['scan_info']['api_name']}\n"
            f"[bold]Scan Date:[/bold] {report['scan_info']['timestamp']}\n"
            f"[bold]Vulnerabilities:[/bold] {report['summary']['total_vulnerabilities']}",
            title="[bold cyan]Scan Report[/bold cyan]",
            border_style="cyan"
        ))
        
        # Show vulnerabilities
        if report['vulnerabilities']:
            table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
            table.add_column("Severity", style="bold")
            table.add_column("Type", style="cyan")
            table.add_column("Endpoint")
            
            for vuln in report['vulnerabilities'][:10]:
                table.add_row(
                    vuln['severity'],
                    vuln['attack_type'],
                    f"{vuln['method']} {vuln['url']}"
                )
            
            console.print("\n")
            console.print(table)
        
    except FileNotFoundError:
        console.print(f"[red]✗ Report not found: {report_file}[/red]")
    except json.JSONDecodeError:
        console.print(f"[red]✗ Invalid JSON report[/red]")


if __name__ == '__main__':
    cli()