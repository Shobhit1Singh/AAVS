# 🔒 API Security Fuzzer

Professional automated security testing tool for REST APIs. Find vulnerabilities through intelligent fuzzing, JWT attacks, SQL injection, and more.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-blue)

## ✨ Features

- 🎯 **Intelligent Fuzzing** - Automated attack generation based on API specs
- 🔐 **Authentication Testing** - JWT, OAuth, API keys, and session attacks
- 🧠 **Machine Learning** - Learns which payloads are most effective
- ⚡ **Rate Limiting** - Smart adaptive delays to avoid detection
- 📊 **Beautiful Reports** - JSON, HTML, and text reports with detailed findings
- 🎨 **Rich CLI** - Professional command-line interface with progress tracking
- 📝 **YAML Configs** - Easy configuration for different targets

### Attack Types

- SQL Injection
- NoSQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- JWT Vulnerabilities
- OAuth Flaws
- Authentication Bypass
- Input Validation Failures
- And 10+ more...

## 🚀 Quick Start

### Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/api-security-fuzzer.git
cd api-security-fuzzer

# Install dependencies
pip install -r requirements.txt

# Or install as a package
pip install -e .
```

### Basic Usage
```bash
# Initialize project
apifuzz init

# Scan an API
apifuzz scan -s api.yaml -u https://api.example.com

# With authentication
apifuzz scan -s api.yaml -u https://api.example.com --auth-token YOUR_JWT

# Use configuration file
apifuzz scan -c configs/target.yaml

# Parse API spec only
apifuzz parse api.yaml

# List available attacks
apifuzz list-attacks --type jwt
```

## 📚 Documentation

### Configuration File Example
```yaml
target:
  base_url: https://api.example.com/v1
  spec_file: openapi.yaml

auth:
  bearer_token: eyJhbGciOiJIUzI1NiIs...

scan:
  rate_limit: 10
  timeout: 10
  use_ml: true

attacks:
  categories:
    sql_injection: true
    xss: true
    jwt_attacks: true

output:
  directory: output/reports
  formats: [json, html, txt]
```

### Running a Scan
```bash
# Full scan with all options
apifuzz scan \
  --spec examples/api.yaml \
  --base-url https://api.example.com/v1 \
  --auth-token eyJhbGc... \
  --rate-limit 5 \
  --output reports/ \
  --verbose
```

### Example Output
```
╔═══════════════════════════════════════════════════════════════════╗
║                     API Security Fuzzer                          ║
║                        Version 1.0.0                             ║
╚═══════════════════════════════════════════════════════════════════╝

✓ Parsed 15 endpoints
✓ Generated 247 attack test cases
✓ ML optimizer ready

Executing attacks... ████████████████████████████ 100% 247/247

⚠ VULNERABILITIES DETECTED

┌──────────┬─────────────────────┬──────────────────┬────────────┐
│ Severity │ Type                │ Endpoint         │ Parameter  │
├──────────┼─────────────────────┼──────────────────┼────────────┤
│ CRITICAL │ SQL Injection       │ POST /users      │ username   │
│ HIGH     │ JWT None Algorithm  │ GET /profile     │ token      │
│ MEDIUM   │ XSS                 │ POST /comments   │ text       │
└──────────┴─────────────────────┴──────────────────┴────────────┘

Reports saved to: output/reports/
```

## 🧪 Testing with Vulnerable API

We include a deliberately vulnerable test API:
```bash
# Terminal 1: Start vulnerable API
python examples/vulnerable_api.py

# Terminal 2: Run scanner
apifuzz scan -s examples/simple_api.yaml -u http://127.0.0.1:5000/api/v1
```

**⚠️ WARNING:** Never deploy the test API to production!

## 🏗️ Project Structure
```
api-security-fuzzer/
├── fuzzer/              # Core fuzzing engine
│   ├── parser/          # OpenAPI parser
│   ├── attacks/         # Attack generators
│   ├── analyzer/        # Response analysis
│   └── core/            # Session, rate limiting
├── cli/                 # Command-line interface
├── configs/             # Example configurations
├── examples/            # Sample APIs and specs
├── docs/                # Documentation
└── output/              # Reports and ML models
```

## 📊 Machine Learning

The ML module learns from your scans:

1. **Training**: Tracks which payloads find vulnerabilities
2. **Optimization**: Prioritizes effective attacks in future scans
3. **Persistence**: Saves models for reuse
```bash
# ML is enabled by default
apifuzz scan -s api.yaml -u https://api.example.com

# Disable ML
apifuzz scan -s api.yaml -u https://api.example.com --no-ml
```

Models are saved in `output/ml_models/`.

## 🔧 Advanced Usage

### Custom Attack Payloads

Edit `configs/custom_attacks.yaml`:
```yaml
attacks:
  custom_payloads:
    - "'; DROP TABLE users--"
    - "admin' OR '1'='1"
    - "<script>alert('custom')</script>"
```

### Testing Specific Endpoints
```bash
apifuzz scan -s api.yaml -u https://api.example.com \
  -e "GET /users" \
  -e "POST /users"
```

### Rate Limiting
```bash
# Slow and stealthy (1 req/s)
apifuzz scan -s api.yaml -u https://api.example.com --rate-limit 1

# Fast (20 req/s)
apifuzz scan -s api.yaml -u https://api.example.com --rate-limit 20
```

## 📈 Report Formats

### JSON Report
Machine-readable, perfect for CI/CD integration.

### HTML Report
Beautiful, interactive report with charts and color coding.

### Text Report
Plain text for terminal viewing or logging.

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## ⚖️ Legal Disclaimer

**USE RESPONSIBLY**

This tool is for:
- ✅ Testing your own APIs
- ✅ Authorized penetration testing
- ✅ Security research with permission
- ✅ Educational purposes

This tool is NOT for:
- ❌ Unauthorized access to systems
- ❌ Attacking APIs you don't own
- ❌ Violating terms of service
- ❌ Illegal activities

**You are responsible for your actions.** Always get written permission before testing third-party systems.

## 📄 License

MIT License - see [LICENSE](LICENSE) file

## 🙏 Acknowledgments

Built with:
- OpenAPI/Swagger specs
- OWASP Top 10 API Security Risks
- scikit-learn for ML
- Rich for beautiful CLI

## 📧 Contact

- **Author**: Your Name
- **Email**: your.email@example.com
- **GitHub**: https://github.com/yourusername/api-security-fuzzer

---

**⭐ Star this repo if you find it useful!**