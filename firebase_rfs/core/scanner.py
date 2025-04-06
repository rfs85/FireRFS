#!/usr/bin/env python3

"""
FireRFS - Firebase Reconnaissance & Security Testing Tool
Main class implementation
"""

import os
import sys
import time
import json
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
import logging
import requests
from typing import Dict, List, Any, Optional
from pathlib import Path

from firebase_rfs.utils.helpers import validate_api_key, validate_project_id
from firebase_rfs.utils.reporting import ReportGenerator

# Define constants
VERSION = "1.1.0"
SEVERITY_ORDER_MAP = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4
}

logger = logging.getLogger(__name__)

class FirebaseScanner:
    """Main scanner class for Firebase security assessment."""
    
    def __init__(
        self,
        api_key: str,
        project_id: Optional[str] = None,
        timeout: int = 30
    ):
        """
        Initialize the Firebase scanner.
        
        Args:
            api_key: Firebase API key
            project_id: Optional Firebase project ID
            timeout: Request timeout in seconds
        """
        if not validate_api_key(api_key):
            raise ValueError("Invalid Firebase API key format")
        
        if project_id and not validate_project_id(project_id):
            raise ValueError("Invalid Firebase project ID format")
        
        self.api_key = api_key
        self.project_id = project_id
        self.timeout = timeout
        self.base_url = "https://firebaseio.com"
        self.report_generator = ReportGenerator()
    
    def check_api_key_restrictions(self) -> Dict[str, Any]:
        """
        Check API key restrictions and allowed domains.
        
        Returns:
            Dict containing API key restriction details
        """
        logger.info("Checking API key restrictions...")
        
        try:
            # Test API key against different Firebase services
            services = {
                "database": f"{self.base_url}/.json?auth={self.api_key}",
                "storage": f"https://firebasestorage.googleapis.com/v0/b/{self.project_id}.appspot.com/o?auth={self.api_key}" if self.project_id else None,
                "firestore": f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents?key={self.api_key}" if self.project_id else None
            }
            
            results = {
                "status": "success",
                "restrictions": {
                    "android": False,
                    "ios": False,
                    "browser": [],
                    "server": False
                },
                "findings": []
            }
            
            # Test each service
            for service_name, url in services.items():
                if url:
                    try:
                        response = requests.get(url, timeout=self.timeout)
                        if response.status_code == 200:
                            results["restrictions"]["server"] = True
                            results["findings"].append({
                                "severity": "medium",
                                "title": f"Unrestricted {service_name.title()} Access",
                                "description": f"The API key has unrestricted access to Firebase {service_name}.",
                                "recommendation": f"Add appropriate restrictions for {service_name} access in the Firebase Console."
                            })
                    except requests.exceptions.RequestException as e:
                        logger.warning(f"Error testing {service_name}: {str(e)}")
            
            return results
            
        except Exception as e:
            logger.error(f"Error checking API key restrictions: {str(e)}")
            return {
                "status": "error",
                "message": str(e)
            }
    
    def check_service_accessibility(self) -> Dict[str, Any]:
        """
        Check accessibility of various Firebase services.
        
        Returns:
            Dict containing service accessibility status
        """
        logger.info("Checking service accessibility...")
        
        services = {
            "firestore": "https://firestore.googleapis.com/v1/",
            "storage": "https://storage.googleapis.com/",
            "database": "https://firebaseio.com/",
            "functions": "https://cloudfunctions.googleapis.com/v1/",
            "hosting": "https://firebasehosting.googleapis.com/v1beta1/"
        }
        
        results = {}
        
        for service_name, base_url in services.items():
            try:
                url = f"{base_url}?key={self.api_key}"
                response = requests.get(url, timeout=self.timeout)
                
                results[service_name] = {
                    "accessible": response.status_code != 403,
                    "status_code": response.status_code,
                    "requires_auth": response.status_code == 401
                }
                
                if results[service_name]["accessible"]:
                    logger.warning(f"{service_name} appears to be accessible")
            except requests.exceptions.RequestException as e:
                logger.error(f"Error checking {service_name}: {str(e)}")
                results[service_name] = {
                    "accessible": False,
                    "error": str(e)
                }
        
        return results
    
    def analyze_security_rules(self, rules: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze Firebase security rules for vulnerabilities.
        
        Args:
            rules: Optional dictionary containing security rules to analyze
                  If not provided, attempts to fetch rules if project_id is available
        
        Returns:
            Dict containing security rule analysis results
        """
        logger.info("Analyzing security rules...")
        
        findings = []
        
        if not rules and self.project_id:
            # Attempt to fetch rules if not provided
            try:
                url = f"https://firebasestorage.googleapis.com/v0/b/{self.project_id}.appspot.com/o/.settings/rules.json?alt=media&key={self.api_key}"
                response = requests.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    rules = response.json()
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching security rules: {str(e)}")
        
        if rules:
            # Check for common security issues
            if ".read" in str(rules) and "true" in str(rules[".read"]):
                findings.append({
                    "severity": "high",
                    "title": "Public Read Access",
                    "description": "Database allows public read access without authentication",
                    "recommendation": "Implement proper authentication checks in security rules"
                })
            
            if ".write" in str(rules) and "true" in str(rules[".write"]):
                findings.append({
                    "severity": "critical",
                    "title": "Public Write Access",
                    "description": "Database allows public write access without authentication",
                    "recommendation": "Implement proper authentication and validation in security rules"
                })
        
        return {
            "findings": findings,
            "rules_analyzed": bool(rules)
        }
    
    def scan_vulnerabilities(self, mode: str = "quick") -> Dict[str, Any]:
        """
        Scan for common Firebase vulnerabilities.
        
        Args:
            mode: Scan mode ('quick' or 'comprehensive')
        
        Returns:
            Dict containing vulnerability scan results
        """
        logger.info(f"Starting {mode} vulnerability scan...")
        
        vulnerabilities = []
        
        # Basic vulnerability checks
        if not self.project_id:
            vulnerabilities.append({
                "severity": "info",
                "title": "Limited Scan Scope",
                "description": "No project ID provided, limiting scan capabilities",
                "recommendation": "Provide project ID for comprehensive scanning"
            })
        
        # Check for common misconfigurations
        service_results = self.check_service_accessibility()
        for service, status in service_results.items():
            if status.get("accessible", False):
                vulnerabilities.append({
                    "severity": "medium",
                    "title": f"Exposed {service.title()} Service",
                    "description": f"{service.title()} service is publicly accessible",
                    "recommendation": f"Review and restrict {service} access controls"
                })
        
        # Additional checks for comprehensive mode
        if mode == "comprehensive" and self.project_id:
            # Add more detailed vulnerability checks here
            pass
        
        return {
            "vulnerabilities": vulnerabilities,
            "scan_mode": mode,
            "timestamp": datetime.now().isoformat()
        }
    
    def generate_report(self, results: Dict[str, Any], output_dir: str) -> str:
        """
        Generate a security assessment report.
        
        Args:
            results: Dictionary containing assessment results
            output_dir: Directory to save the report
        
        Returns:
            str: Path to the generated report file
        """
        return self.report_generator.generate_html_report(results, output_dir)

class FireRFS:
    """Firebase reconnaissance and security testing tool main class"""
    
    def __init__(self, api_key, project_id=None, services=None, html_report=True, detailed=False, data_dump=False, output_dir=None):
        """Initialize the FireRFS tool
        
        Args:
            api_key (str): Firebase API key
            project_id (str, optional): Firebase project ID
            services (list, optional): List of services to test
            html_report (bool, optional): Generate HTML report
            detailed (bool, optional): Detailed output
            data_dump (bool, optional): Dump all accessible data
            output_dir (str, optional): Output directory
        """
        self.api_key = api_key
        self.project_id = project_id
        self.html_report = html_report
        self.detailed = detailed
        self.data_dump = data_dump
        self.output_dir = output_dir or f"firerfs_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.console = Console()
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        # Initialize services to check
        self.services_to_check = {
            "database": True,
            "firestore": True,
            "auth": True,
            "storage": True,
            "functions": True,
            "hosting": True
        }
        
        if services:
            # Reset all services to False
            for service in self.services_to_check:
                self.services_to_check[service] = False
            
            # Enable only the specified services
            for service in services:
                if service in self.services_to_check:
                    self.services_to_check[service] = True
        
        # Initialize results structure
        self.results = {
            "metadata": {
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "api_key": self.api_key,
                "project_id": self.project_id
            },
            "vulnerabilities": [],
            "services": {},
            "restrictions": {},
            "account_info": {
                "project_details": {},
                "databases": [],
                "functions": [],
                "storage_buckets": [],
                "hosting_sites": [],
                "members": []
            },
            "security_rules": {},
            "exposed_data": [],
            "extracted_data": {
                "database": {},
                "firestore": {},
                "storage": {},
                "other": {}
            }
        }
    
    def run(self):
        """Run the full assessment"""
        return self.run_assessment_with_steps()
    
    def run_quick_assessment(self):
        """Run a quick assessment with minimal tests"""
        self.console.print("[bold]Running quick assessment (limited tests)[/bold]")
        
        # Only check essential services in quick mode
        self.services_to_check = {
            "database": True,
            "firestore": True,
            "auth": True,
            "storage": True,
            "functions": False,
            "hosting": False
        }
        
        # Disable data dump in quick mode
        self.data_dump = False
        
        # Run limited steps
        self.console.print("\n[bold blue]Step 1/4:[/bold blue] Testing API Key Restrictions...")
        self.test_api_key_restrictions()
        
        self.console.print("\n[bold blue]Step 2/4:[/bold blue] Checking Service Accessibility...")
        self.check_service_accessibility()
        
        self.console.print("\n[bold blue]Step 3/4:[/bold blue] Analyzing Security Rules...")
        self.analyze_security_rules()
        
        self.console.print("\n[bold blue]Step 4/4:[/bold blue] Identifying Basic Vulnerabilities...")
        self._check_public_db_access()
        self._check_storage_permissions()
        
        # Generate reports
        self.print_terminal_report()
        
        if self.html_report:
            output_file = f"{self.output_dir}/firerfs_quick_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            self.generate_html_report(output_file)
        
        return self.results
    
    def generate_html_report(self, output_file, extracted_keys=None):
        """Generate an HTML report with extracted keys if available"""
        self.console.print("[dim]Generating HTML report...[/dim]")
        # Placeholder implementation
        try:
            with open(output_file, 'w') as f:
                f.write("<!DOCTYPE html><html><head><title>FireRFS Report</title></head><body>")
                f.write("<h1>Firebase Security Assessment Report</h1>")
                f.write(f"<p>This is a placeholder HTML report for API key: {self.api_key}</p>")
                f.write("</body></html>")
            
            self.console.print(f"[green]HTML report saved to {output_file}[/green]")
            return True
        except Exception as e:
            self.console.print(f"[bold red]Error generating HTML report: {str(e)}[/bold red]")
            return False
    
    def generate_text_report(self, output_file):
        """Generate a text report of the security assessment
        
        Args:
            output_file (str): Path to save the text report
        
        Returns:
            bool: True if report generation was successful
        """
        try:
            with open(output_file, 'w') as f:
                # Write basic report information
                f.write("FireRFS - Firebase Security Assessment Report\n")
                f.write("=" * 50 + "\n\n")
                
                # Metadata
                f.write("Metadata:\n")
                f.write(f"Scan Time: {self.results['metadata'].get('scan_time', 'Unknown')}\n")
                f.write(f"Project ID: {self.project_id or 'Not Specified'}\n\n")
                
                # Vulnerabilities
                f.write("Vulnerabilities:\n")
                vulnerabilities = self.results.get('vulnerabilities', [])
                if vulnerabilities:
                    for vuln in vulnerabilities:
                        f.write(f"- {vuln.get('severity', 'UNKNOWN')}: {vuln.get('description', 'Unspecified vulnerability')}\n")
                else:
                    f.write("No vulnerabilities detected.\n")
                
                # Services
                f.write("\nService Accessibility:\n")
                services = self.results.get('services', {})
                for service, details in services.items():
                    status = "Accessible" if details.get('accessible', False) else "Not Accessible"
                    f.write(f"- {service.capitalize()}: {status}\n")
                
                # Restrictions
                f.write("\nAPI Key Restrictions:\n")
                restrictions = self.results.get('restrictions', {})
                for restriction, value in restrictions.items():
                    if not restriction.endswith('_details'):
                        f.write(f"- {restriction.replace('_', ' ').title()}: {value}\n")
            
            self.console.print(f"[green]Text report saved to {output_file}[/green]")
            return True
        except Exception as e:
            self.console.print(f"[bold red]Error generating text report: {str(e)}[/bold red]")
            return False
    
    def run_assessment_with_steps(self):
        """Run the assessment with step-by-step file creation"""
        import time
        from datetime import datetime
        
        self.console.print("[bold]Starting Firebase Security Assessment[/bold]")
        start_time = time.time()
        
        # Initialize results structure
        self.results = {
            "metadata": {
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "api_key": self.api_key,
                "project_id": self.project_id
            },
            "vulnerabilities": [],
            "services": {},
            "restrictions": {},
            "account_info": {
                "project_details": {},
                "databases": [],
                "functions": [],
                "storage_buckets": [],
                "hosting_sites": [],
                "members": []
            },
            "security_rules": {},
            "exposed_data": [],
            "extracted_data": {
                "database": {},
                "firestore": {},
                "storage": {},
                "other": {}
            }
        }
        
        # Step 1: Test API Key Restrictions
        self.console.print("\n[bold blue]Step 1/7:[/bold blue] Testing API Key Restrictions...")
        self.test_api_key_restrictions()
        
        # Step 2: Check Service Accessibility
        self.console.print("\n[bold blue]Step 2/7:[/bold blue] Checking Service Accessibility...")
        self.check_service_accessibility()
        
        # Step 3: Enumerate Account Details
        self.console.print("\n[bold blue]Step 3/7:[/bold blue] Enumerating Account Details...")
        self.enumerate_account_details()
        
        # Step 4: Analyze Security Rules
        self.console.print("\n[bold blue]Step 4/7:[/bold blue] Analyzing Security Rules...")
        self.analyze_security_rules()
        
        # Step 5: Extract Data
        self.console.print("\n[bold blue]Step 5/7:[/bold blue] Extracting Data...")
        if self.data_dump:
            self.dump_data()
        else:
            self.console.print("[yellow]Data extraction disabled[/yellow]")
        
        # Step 6: Extract Keys and Tokens
        self.console.print("\n[bold blue]Step 6/7:[/bold blue] Extracting Keys and Tokens...")
        keys = self.extract_keys_and_tokens()
        
        # Step 7: Identify Advanced Vulnerabilities
        self.console.print("\n[bold blue]Step 7/7:[/bold blue] Identifying Advanced Vulnerabilities...")
        self.identify_advanced_vulnerabilities()
        
        # Save Final Results
        end_time = time.time()
        self.results["metadata"]["duration"] = f"{end_time - start_time:.2f} seconds"
        
        # Print terminal report
        self.print_terminal_report()
        
        # Generate HTML report
        if self.html_report:
            output_file = f"{self.output_dir}/firerfs_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            self.generate_html_report(output_file, keys)
        
        return self.results
    
    def test_api_key_restrictions(self):
        """Placeholder for testing API key restrictions"""
        self.results["restrictions"] = {
            "referrer": False,
            "referrer_details": "No referrer restrictions detected",
            "ip": False,
            "ip_details": "No IP restrictions detected"
        }
    
    def check_service_accessibility(self):
        """Placeholder for checking service accessibility"""
        self.results["services"] = {
            "database": {"accessible": True},
            "firestore": {"accessible": True},
            "auth": {"accessible": True},
            "storage": {"accessible": True},
            "functions": {"accessible": False},
            "hosting": {"accessible": True}
        }
    
    def enumerate_account_details(self):
        """Placeholder for enumerating account details"""
        self.results["account_info"] = {
            "project_details": {
                "name": f"Project {self.project_id or 'Unknown'}",
                "id": self.project_id
            }
        }
    
    def analyze_security_rules(self):
        """Placeholder for analyzing security rules"""
        self.results["security_rules"] = {
            "database": {"public_access": True},
            "firestore": {"public_read": True}
        }
    
    def dump_data(self):
        """Placeholder for data dumping"""
        self.results["extracted_data"] = {
            "database": {"accessible": True},
            "firestore": {"accessible": True}
        }
    
    def extract_keys_and_tokens(self):
        """Placeholder for extracting keys and tokens"""
        return {
            "api_keys": [self.api_key],
            "tokens": [],
            "passwords": [],
            "secrets": [],
            "other_credentials": []
        }
    
    def identify_advanced_vulnerabilities(self):
        """Placeholder for identifying advanced vulnerabilities"""
        self.results["vulnerabilities"] = [
            {
                "severity": "HIGH",
                "description": "Potential API key exposure",
                "service": "Authentication"
            }
        ]
    
    def print_terminal_report(self):
        """Placeholder for printing terminal report"""
        self.console.print("[bold green]Security Assessment Complete[/bold green]")
    
    def _check_public_db_access(self):
        """Placeholder for checking public database access"""
        pass
    
    def _check_storage_permissions(self):
        """Placeholder for checking storage permissions"""
        pass

# Add main block if needed
if __name__ == "__main__":
    # Example usage
    firerfs = FireRFS("sample_api_key")
    results = firerfs.run()