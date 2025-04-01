# FireRFS - Firebase Reconnaissance & Security Testing Tool

[![FireRFS Banner](https://img.shields.io/badge/FireRFS-Firebase%20Security%20Testing-red)](https://github.com/rfs85/FireRFS)
![Version](https://img.shields.io/badge/Version-1.1.0-blue)
![Python](https://img.shields.io/badge/Python-3.7%2B-yellow)
![License](https://img.shields.io/badge/License-MIT-green)

FireRFS is a comprehensive tool for Firebase security assessment and data exfiltration. It allows security researchers and penetration testers to identify vulnerabilities in Firebase applications and assess the security posture of Firebase projects.

## Features

- **API Key Analysis**: Test Firebase API key restrictions (referrer, IP, app)
- **Service Discovery**: Identify accessible Firebase services (Realtime Database, Firestore, Storage, Auth, Functions, Hosting)
- **Security Rule Analysis**: Evaluate security rules for potential vulnerabilities
- **Vulnerability Detection**: Identify common Firebase security issues:
  - Public database access without authentication
  - Misconfigured storage buckets
  - Excessive permissions in security rules
  - JWT token vulnerabilities
  - Insecure Cloud Functions
  - Authentication bypass vulnerabilities
  - API key exposure in client-side code
- **Credential Extraction**: Find and extract API keys, tokens, secrets, and other credentials
- **Data Extraction**: Dump accessible data from Firebase services (optional)
- **Comprehensive Reporting**: Generate well-formatted terminal, HTML, and text reports

## Installation

```bash
# Clone the repository
git clone https://github.com/rfs85/FireRFS.git
cd FireRFS

# Install required dependencies
pip install -r requirements.txt
```

## Usage

Basic usage:

```bash
python firebase-rfs.py -k YOUR_FIREBASE_API_KEY
```

With project ID (if known):

```bash
python firebase-rfs.py -k YOUR_FIREBASE_API_KEY -p YOUR_PROJECT_ID
```

### Command Line Options

```
Options:
  -h, --help            Show this help message and exit
  -k KEY, --key KEY     Firebase API key (required)
  -p PROJECT_ID, --project-id PROJECT_ID
                        Firebase project ID (will be enumerated if not provided)
  -s SERVICES, --services SERVICES
                        Services to test (comma-separated list: database,firestore,auth,storage,functions,hosting)
  -o OUTPUT, --output OUTPUT
                        Output directory
  -d, --data            Dump all accessible data
  --html                Generate HTML report (default)
  --no-html             Do not generate HTML report
  --text                Generate text report
  --detailed            Detailed output
  --archive             Create ZIP archive of results
  --auto-exploit        Attempt to automatically exploit vulnerabilities (USE WITH CAUTION)
  --exploit-critical-only
                        Only exploit critical vulnerabilities with auto-exploit option
  --steps               Save results for each step to separate files (default)
  --no-steps            Don't save intermediate step results

Testing Modes:
  --recon-only          Only perform reconnaissance, no vulnerability testing
  --vuln-only           Only perform vulnerability testing, skip reconnaissance
  --quick               Perform quick testing (less comprehensive)
  --thorough            Perform thorough testing (more comprehensive, slower)
```

## Assessment Modes

FireRFS offers multiple assessment modes to suit different testing scenarios:

- **Standard Assessment**: The default mode. Balanced between thoroughness and speed.
- **Quick Assessment**: Fast testing of the most critical issues. Good for initial reconnaissance.
- **Thorough Assessment**: Comprehensive testing of all possible vulnerabilities. Takes longer but provides more detailed results.
- **Reconnaissance Only**: Only gathers information about the Firebase project without testing for vulnerabilities.
- **Vulnerability Testing Only**: Only tests for vulnerabilities, assuming reconnaissance has already been performed.

## Example Usage Scenarios

### Basic Security Assessment
```bash
python firebase-rfs.py -k YOUR_API_KEY
```

### Quick Initial Assessment
```bash
python firebase-rfs.py -k YOUR_API_KEY --quick
```

### Complete Security Audit with Data Extraction
```bash
python firebase-rfs.py -k YOUR_API_KEY -p YOUR_PROJECT_ID --thorough --data --text --archive
```

### Testing Specific Services
```bash
python firebase-rfs.py -k YOUR_API_KEY --services database,storage,auth
```

## Output

FireRFS generates organized output with different levels of detail:

- **Terminal Output**: Real-time, colorized assessment progress and findings
- **HTML Report**: Comprehensive report with all findings, organized by severity
- **Text Report**: Plain text version of the full assessment report
- **JSON Files**: Detailed results for each step of the assessment
- **Data Dumps**: Extracted data from accessible Firebase services (if enabled)

All output is saved to a timestamped directory for easy reference.

## Security Notes

- This tool is designed for authorized security testing only.
- Always obtain proper permission before testing Firebase applications.
- The auto-exploitation features should be used with extreme caution and only on systems you own or have explicit permission to test.
- Be responsible with any data extracted from Firebase services.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request to [our GitHub repository](https://github.com/rfs85/FireRFS).

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and professional security assessment purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before conducting security testing.