# Usage Guide

## Installation

### Option 1: Development Mode
```bash
git clone https://github.com/yourusername/api-security-fuzzer.git
cd api-security-fuzzer
pip install -r requirements.txt
pip install -e .
```

### Option 2: Direct Installation
```bash
pip install api-security-fuzzer
```

## Commands

### `apifuzz scan`

Run a complete security scan.

**Options:**
- `-s, --spec FILE` - OpenAPI specification file (required)
- `-u, --base-url URL` - API base URL (required)
- `-c, --config FILE` - Configuration file
- `-o, --output DIR` - Output directory
- `-e, --endpoints ENDPOINT` - Specific endpoints to test
- `--auth-token TOKEN` - Bearer token
- `--api-key KEY` - API key
- `--rate-limit N` - Max requests per second
- `--timeout N` - Request timeout
- `--ml/--no-ml` - Enable/disable ML
- `-v, --verbose` - Verbose output

**Examples:**
```bash
# Basic scan
apifuzz scan -s api.yaml -u https://api.example.com

# With JWT authentication
apifuzz scan -s api.yaml -u https://api.example.com \
  --auth-token eyJhbGciOiJIUzI1NiIs...

# Test specific endpoints
apifuzz scan -s api.yaml -u https://api.example.com \
  -e "GET /users" \
  -e "POST /users"

# Using config file
apifuzz scan -c configs/production.yaml

# Slow and stealthy
apifuzz scan -s api.yaml -u https://api.example.com \
  --rate-limit 1 \
  --timeout 30
```

### `apifuzz parse`

Parse and display API specification.
```bash
apifuzz parse api.yaml
```

### `apifuzz list-attacks`

List available attack patterns.
```bash
# All attacks
apifuzz list-attacks

# JWT attacks only
apifuzz list-attacks --type jwt

# OAuth attacks
apifuzz list-attacks --type oauth
```

### `apifuzz init`

Initialize a new project.
```bash
apifuzz init
```

Creates:
- `configs/` directory with example config
- `output/reports/` directory
- `output/ml_models/` directory

### `apifuzz view`

View a generated report.
```bash
apifuzz view output/reports/report.json
```

## Configuration Files

### Structure
```yaml
target:
  base_url: string
  spec_file: string

auth:
  bearer_token: string
  api_key: string
  basic:
    username: string
    password: string

scan:
  rate_limit: int
  timeout: int
  use_ml: bool
  endpoints: list

attacks:
  categories: dict
  custom_payloads: list

output:
  directory: string
  formats: list
```

### Examples

See `configs/example_target.yaml` for a complete example.

## Authentication

### Bearer Token (JWT)
```bash
apifuzz scan -s api.yaml -u https://api.example.com \
  --auth-token eyJhbGciOiJIUzI1NiIs...
```

Or in config:
```yaml
auth:
  bearer_token: eyJhbGciOiJIUzI1NiIs...
```

### API Key
```bash
apifuzz scan -s api.yaml -u https://api.example.com \
  --api-key your_api_key_here
```

Or in config:
```yaml
auth:
  api_key: your_api_key_here
  api_key_header: X-API-Key  # optional
```

### Basic Auth

In config only:
```yaml
auth:
  basic:
    username: admin
    password: password123
```

## Output Reports

Three formats are generated:

1. **JSON** - Machine-readable
```bash
   output/reports/vulnerability_report_20260212_143022.json
```

2. **HTML** - Interactive web report
```bash
   output/reports/vulnerability_report_20260212_143022.html
```

3. **TXT** - Plain text
```bash
   output/reports/vulnerability_report_20260212_143022.txt
```

## Machine Learning

### Training

ML automatically trains on scan results:
- Tracks successful attack payloads
- Learns patterns that find vulnerabilities
- Saves model for future use

### Using Trained Models
```bash
# Model automatically loads if available
apifuzz scan -s api.yaml -u https://api.example.com

# Disable ML
apifuzz scan -s api.yaml -u https://api.example.com --no-ml
```

Models stored in: `output/ml_models/`

## Tips & Best Practices

### 1. Start Slow
```bash
apifuzz scan -s api.yaml -u https://api.example.com \
  --rate-limit 1
```

### 2. Test Locally First
```bash
python examples/vulnerable_api.py  # Terminal 1
apifuzz scan -s examples/simple_api.yaml -u http://127.0.0.1:5000/api/v1  # Terminal 2
```

### 3. Use Config Files
Create reusable configs for different environments:
- `configs/dev.yaml`
- `configs/staging.yaml`
- `configs/production.yaml`

### 4. Focus on Critical Endpoints
```bash
apifuzz scan -s api.yaml -u https://api.example.com \
  -e "POST /auth/login" \
  -e "POST /payments" \
  -e "GET /admin/*"
```

### 5. Review Reports Carefully
Not all findings are exploitable. Review each:
- Context matters
- False positives happen
- Verify manually when critical

## Troubleshooting

### Connection Errors
```
✗ Connection error: ...
```
**Solution**: Check base URL and network connectivity

### Rate Limiting
```
⚠️ Rate limit hit
```
**Solution**: Reduce rate limit with `--rate-limit 1`

### Authentication Failures
```
✗ 401 Unauthorized
```
**Solution**: Verify token/API key is valid and not expired

### Parsing Errors
```
✗ Failed to parse spec
```
**Solution**: Validate OpenAPI spec with online validator

## Next Steps

- Read [Configuration Guide](configuration.md)
- Check [Advanced Usage](advanced.md)
- Review [Contributing Guidelines](../CONTRIBUTING.md)