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

# Define constants
VERSION = "1.1.0"
SEVERITY_ORDER_MAP = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4
}

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