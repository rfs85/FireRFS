# FireRFS - Firebase Security Assessment Tool

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

FireRFS is a comprehensive security assessment tool for Firebase applications, designed to identify vulnerabilities, misconfigurations, and potential security risks in your Firebase deployment.

## 🌟 Features

- **API Key Analysis**: Validate and assess Firebase API key restrictions
- **Service Accessibility**: Check access levels for Firebase services
- **Security Rules Analysis**: Evaluate Firestore and Storage security rules
- **Vulnerability Scanning**: Identify common security vulnerabilities
- **Interactive Mode**: Guided security assessment process
- **Comprehensive Reports**: Detailed HTML reports with findings and recommendations
- **Auto-Exploitation**: Optional automated exploitation of discovered vulnerabilities
- **Custom Configuration**: Support for custom security assessment profiles

## 📁 Repository Structure

```
firebase_rfs/
├── docs/                    # Documentation files
├── examples/               # Example configurations and usage
├── tests/                  # Test suite
├── firebase_rfs/          # Main package
│   ├── core/             # Core functionality
│   │   ├── scanner.py   # Security scanning logic
│   │   └── analyzer.py  # Analysis components
│   ├── utils/           # Utility functions
│   │   ├── reporting.py # Report generation
│   │   └── helpers.py   # Helper functions
│   ├── templates/       # HTML report templates
│   ├── __init__.py     # Package initialization
│   └── cli.py          # Command-line interface
├── requirements.txt       # Production dependencies
├── requirements-win.txt   # Windows-specific dependencies
├── requirements-dev.txt   # Development dependencies
├── setup.py              # Package setup file
└── README.md             # This file
```

## 🚀 Quick Start

### Installation

```bash
# For Linux/Mac
pip install -r requirements.txt

# For Windows
pip install -r requirements-win.txt

# Install in development mode
pip install -e .
```

### Basic Usage

```bash
# Quick security scan
python -m firebase_rfs.cli -k YOUR_API_KEY --scan-mode quick

# Comprehensive assessment
python -m firebase_rfs.cli -k YOUR_API_KEY -p YOUR_PROJECT_ID --scan-mode comprehensive

# Interactive mode
python -m firebase_rfs.cli --interactive
```

## 🔧 Configuration

FireRFS supports custom configuration through YAML files:

```yaml
scan_settings:
  timeout: 30
  max_depth: 5
  services:
    - firestore
    - storage
    - database
```

Use custom configuration:
```bash
python -m firebase_rfs.cli --config custom_config.yaml
```

## 📊 Reports

FireRFS generates detailed HTML reports containing:
- Executive Summary
- Vulnerability Findings
- Security Recommendations
- Technical Details
- Remediation Steps

Reports are saved in the `firerfs_results_[timestamp]` directory.

## 🛡️ Security Features

- API Key Validation
- Service Access Control Analysis
- Security Rules Assessment
- Data Exposure Detection
- Authentication Configuration Review
- Network Security Analysis
- Custom Security Policies

## 🧪 Development

### Setting up Development Environment

```bash
# Clone the repository
git clone https://github.com/yourusername/firebase_rfs.git
cd firebase_rfs

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -r requirements-dev.txt
```

### Running Tests

```bash
pytest tests/
```

### Code Style

We use Black for code formatting and Flake8 for linting:
```bash
black .
flake8 .
```

## 📝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## 🔒 Security

- Report security vulnerabilities to [security@yourdomain.com]
- Follow responsible disclosure practices
- Check our [Security Policy](SECURITY.md)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Firebase Team for documentation
- Security researchers and contributors
- Open source security tools community

## 📬 Contact

- Website: [your-website.com]
- Twitter: [@your_handle]
- Email: [contact@yourdomain.com]

---
Made with ❤️ by the FireRFS Team