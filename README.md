# FireRFS - Firebase Reconnaissance & Security Testing Framework

## Project Structure and File Descriptions

### 1. Main Application Files

#### `firebase-rfs.py`
The primary entry point for the FireRFS security assessment tool.
- **Purpose**: Command-line interface for running security assessments
- **Key Features**:
  - Flexible scanning modes
  - Comprehensive Firebase project analysis
  - Multiple assessment options

**Usage Example:**
```bash
python firebase-rfs.py -k YOUR_FIREBASE_API_KEY -p YOUR_PROJECT_ID
```

#### `advanced-cli-script.py` (FireRFSCLI)
An advanced, interactive command-line interface for security assessments.
- **Purpose**: Provide a user-friendly, interactive security testing experience
- **Key Features**:
  - Interactive mode
  - Detailed scanning options
  - Rich console output
  - Comprehensive result reporting

**Usage Example:**
```bash
python advanced-cli-script.py --interactive
# or
python advanced-cli-script.py -k YOUR_API_KEY --deep-scan
```

### 2. Core Module Files

#### `firebase_rfs.py`
The core implementation of the FireRFS security assessment tool.
- **Purpose**: Implement core reconnaissance and security testing functionality
- **Key Components**:
  - Service accessibility checking
  - Database rule analysis
  - Authentication testing
  - Vulnerability detection

#### `integration.py`
Provides integration and advanced assessment capabilities.
- **Purpose**: Coordinate different components of the security assessment
- **Key Features**:
  - Step-by-step assessment process
  - Result integration
  - Archive creation
  - Auto-exploitation module

### 3. Support Files

#### `requirements.txt`
Defines all Python package dependencies for the project.
- Lists essential libraries for:
  - Security testing
  - Network analysis
  - Data processing
  - Reporting

**To Install Dependencies:**
```bash
pip install -r requirements.txt
```

#### `README.md`
Project documentation and usage guide.
- Provides:
  - Project overview
  - Installation instructions
  - Usage examples
  - Feature descriptions

### 4. Configuration and Utility Files

#### `.env` (Not included in repository)
- **Purpose**: Store sensitive configuration information
- **Recommended Contents**:
  - API keys
  - Project-specific settings
  - Credentials (git-ignored)

## Project Workflow

1. **Reconnaissance**
   - Identify accessible Firebase services
   - Enumerate project details
   - Discover potential vulnerabilities

2. **Security Assessment**
   - Analyze database rules
   - Check authentication mechanisms
   - Scan for exposed secrets
   - Validate network infrastructure

3. **Reporting**
   - Generate comprehensive reports
   - Provide actionable insights
   - Highlight security risks

## Key Features

- 🔍 Comprehensive Firebase project scanning
- 🛡️ Advanced vulnerability detection
- 📊 Detailed reporting
- 🌐 Network infrastructure analysis
- 🔐 Secret and API key discovery

## Security Warning ⚠️

- Use only on systems you own or have explicit permission to test
- Treat discovered information confidentially
- Comply with all legal and ethical guidelines

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Submit a pull request

## License

MIT License - See LICENSE file for details.

## Disclaimer

This tool is for authorized security testing and research purposes only. Misuse may violate local, state, or federal laws.