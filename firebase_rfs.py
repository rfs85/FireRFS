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
    
    # Include the methods from terminal-output-enhancement.py
    def print_terminal_report(self):
        """Print a well-organized terminal report of the security assessment"""
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.tree import Tree
        from rich.text import Text
        from datetime import datetime
        
        console = Console()
        
        # Print header
        console.print("\n")
        console.print("[bold red]FireRFS[/bold red] - Firebase Reconnaissance & Security Testing Tool", justify="center")
        console.print(f"[dim]v{VERSION}[/dim]", justify="center")
        console.print("\n")
        
        # Print assessment metadata
        metadata_table = Table(show_header=False, box=None)
        metadata_table.add_column("Property", style="dim")
        metadata_table.add_column("Value")
        
        metadata_table.add_row("API Key", self.api_key)
        metadata_table.add_row("Project ID", self.project_id)
        metadata_table.add_row("Scan Time", self.results["metadata"]["scan_time"])
        
        # Determine security rating
        severity_counts = {}
        for vuln in self.results["vulnerabilities"]:
            severity = vuln["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if severity_counts.get("CRITICAL", 0) > 0:
            rating = "CRITICAL RISK"
            rating_style = "bold red"
        elif severity_counts.get("HIGH", 0) > 0:
            rating = "HIGH RISK"
            rating_style = "bold orange3"
        elif severity_counts.get("MEDIUM", 0) > 0:
            rating = "MEDIUM RISK"
            rating_style = "bold yellow"
        elif severity_counts.get("LOW", 0) > 0:
            rating = "LOW RISK"
            rating_style = "bold green"
        else:
            rating = "SECURE"
            rating_style = "bold green"
        
        metadata_table.add_row("Security Rating", f"[{rating_style}]{rating}[/{rating_style}]")
        
        assessment_panel = Panel(
            metadata_table,
            title="[bold]Assessment Summary[/bold]",
            border_style="blue"
        )
        console.print(assessment_panel)
        
        # Print vulnerabilities
        if self.results["vulnerabilities"]:
            vuln_table = Table(title="[bold]Vulnerabilities[/bold]")
            vuln_table.add_column("Severity", style="bold")
            vuln_table.add_column("Service")
            vuln_table.add_column("Description", width=50)
            vuln_table.add_column("Recommendation", width=50)
            
            # Sort vulnerabilities by severity
            sorted_vulns = sorted(
                self.results["vulnerabilities"],
                key=lambda x: SEVERITY_ORDER_MAP.get(x["severity"], 999)
            )
            
            for vuln in sorted_vulns:
                severity = vuln["severity"]
                severity_style = {
                    "CRITICAL": "red",
                    "HIGH": "orange3",
                    "MEDIUM": "yellow",
                    "LOW": "green",
                    "INFO": "blue"
                }.get(severity, "white")
                
                vuln_table.add_row(
                    f"[{severity_style}]{severity}[/{severity_style}]",
                    vuln["service"],
                    vuln["description"],
                    vuln["recommendation"]
                )
            
            console.print(vuln_table)
        else:
            console.print(Panel("[green]No vulnerabilities found[/green]", title="[bold]Vulnerabilities[/bold]"))
        
        # Print service accessibility
        service_table = Table(title="[bold]Service Accessibility[/bold]")
        service_table.add_column("Service")
        service_table.add_column("Status")
        service_table.add_column("Description", width=60)
        
        for service_name, service_data in self.results["services"].items():
            status = "Accessible" if service_data.get("accessible", False) else "Not Accessible"
            status_style = "red" if service_data.get("accessible", False) and service_data.get("critical", False) else "green"
            
            service_table.add_row(
                service_name,
                f"[{status_style}]{status}[/{status_style}]",
                service_data.get("description", "")
            )
        
        console.print(service_table)
        
        # Print API key restrictions
        restrictions_table = Table(title="[bold]API Key Restrictions[/bold]")
        restrictions_table.add_column("Restriction Type")
        restrictions_table.add_column("Status")
        restrictions_table.add_column("Details", width=60)
        
        restriction_map = {
            "referrer": "Referrer Restrictions",
            "ip": "IP Restrictions",
            "android_apps": "Android App Restrictions",
            "ios_apps": "iOS App Restrictions"
        }
        
        for restriction_key, restriction_name in restriction_map.items():
            value = self.results["restrictions"].get(restriction_key, "UNKNOWN")
            details_key = f"{restriction_key}_details"
            details = self.results["restrictions"].get(details_key, "")
            
            if value == True:
                status = "Enabled"
                status_style = "green"
            elif value == False:
                status = "Disabled"
                status_style = "red"
            elif value == "MAYBE":
                status = "Possibly Enabled"
                status_style = "yellow"
            else:
                status = "Unknown"
                status_style = "blue"
            
            restrictions_table.add_row(
                restriction_name,
                f"[{status_style}]{status}[/{status_style}]",
                details[:60] if details else ""
            )
        
        console.print(restrictions_table)
    
    # Include other methods from step-by-step-files.py
    def save_step_results(self, step_name, data, file_format="json"):
        """Save step results to a file
        
        Args:
            step_name (str): Name of the step
            data (dict): Data to save
            file_format (str): File format (json or txt)
        
        Returns:
            str: Path to the saved file
        """
        from datetime import datetime
        import os
        import json
        
        # Format filename
        sanitized_step = step_name.lower().replace(" ", "_")
        filename = f"{self.output_dir}/{sanitized_step}"
        
        # Save file
        if file_format == "json":
            filename += ".json"
            with open(filename, 'w') as f:
                json.dump(data, f, indent=4)
        else:
            filename += ".txt"
            with open(filename, 'w') as f:
                f.write(str(data))
        
        self.console.print(f"[dim]Saved step results to {filename}[/dim]")
        return filename
    
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
        self.save_step_results("1_API_Key_Restrictions", self.results["restrictions"])
        
        # Step 2: Check Service Accessibility
        self.console.print("\n[bold blue]Step 2/7:[/bold blue] Checking Service Accessibility...")
        self.check_service_accessibility()
        self.save_step_results("2_Service_Accessibility", self.results["services"])
        
        # Step 3: Enumerate Account Details
        self.console.print("\n[bold blue]Step 3/7:[/bold blue] Enumerating Account Details...")
        self.enumerate_account_details()
        self.save_step_results("3_Account_Enumeration", self.results["account_info"])
        
        # Step 4: Analyze Security Rules
        self.console.print("\n[bold blue]Step 4/7:[/bold blue] Analyzing Security Rules...")
        self.analyze_security_rules()
        self.save_step_results("4_Security_Rules", self.results["security_rules"])
        
        # Step 5: Extract Data (if enabled)
        self.console.print("\n[bold blue]Step 5/7:[/bold blue] Extracting Data...")
        if self.data_dump:
            self.dump_data()
            self.save_step_results("5_Extracted_Data", self.results["extracted_data"])
        else:
            self.console.print("[yellow]Data extraction disabled[/yellow]")
        
        # Step 6: Extract API Keys and tokens
        self.console.print("\n[bold blue]Step 6/7:[/bold blue] Extracting Keys and Tokens...")
        keys = self.extract_keys_and_tokens()
        self.save_step_results("6_Extracted_Keys", keys)
        
        # Step 7: Identify Advanced Vulnerabilities
        self.console.print("\n[bold blue]Step 7/7:[/bold blue] Identifying Advanced Vulnerabilities...")
        self.identify_advanced_vulnerabilities()
        self.save_step_results("7_Advanced_Vulnerabilities", 
                              {"vulnerabilities": self.results["vulnerabilities"],
                               "exposed_data": self.results["exposed_data"]})
        
        # Save Final Results
        end_time = time.time()
        self.results["metadata"]["duration"] = f"{end_time - start_time:.2f} seconds"
        self.save_step_results("final_results", self.results)
        
        # Print terminal report
        self.print_terminal_report()
        
        # Generate HTML report
        if self.html_report:
            output_file = f"{self.output_dir}/firerfs_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            self.generate_html_report(output_file, keys)
        
        return self.results
    
    # Placeholder for various assessment methods
    def test_api_key_restrictions(self):
        """Test API key restrictions"""
        self.console.print("[dim]Testing API key restrictions...[/dim]")
        # Placeholder implementation
        self.results["restrictions"] = {
            "referrer": False,
            "referrer_details": "No referrer restrictions detected",
            "ip": False,
            "ip_details": "No IP restrictions detected",
            "android_apps": False,
            "android_apps_details": "No Android app restrictions detected",
            "ios_apps": False,
            "ios_apps_details": "No iOS app restrictions detected"
        }
        # Add vulnerability for unrestricted API key
        self.results["vulnerabilities"].append({
            "severity": "HIGH",
            "service": "API Key",
            "description": "Firebase API key has no restrictions",
            "recommendation": "Add referrer, IP, or app restrictions to your API key to prevent unauthorized use"
        })
    
    def check_service_accessibility(self):
        """Check service accessibility"""
        self.console.print("[dim]Checking service accessibility...[/dim]")
        # Placeholder implementation
        self.results["services"] = {
            "database": {
                "accessible": True,
                "description": "Realtime Database is accessible with this API key",
                "details": "Database is accessible and contains data",
                "critical": True
            },
            "firestore": {
                "accessible": True,
                "description": "Firestore is accessible with this API key",
                "details": "Firestore is accessible and contains collections",
                "critical": True
            },
            "auth": {
                "accessible": True,
                "description": "Authentication is accessible with this API key",
                "details": "Authentication service is accessible",
                "critical": False
            },
            "storage": {
                "accessible": True,
                "description": "Storage is accessible with this API key",
                "details": "Storage buckets are accessible and contain files",
                "critical": True
            },
            "functions": {
                "accessible": False,
                "description": "Cloud Functions require additional authentication",
                "details": "Cloud Functions are not directly accessible with this API key",
                "critical": False
            },
            "hosting": {
                "accessible": True,
                "description": "Hosting is accessible",
                "details": "Hosting site is publicly accessible",
                "critical": False
            }
        }
    
    def enumerate_account_details(self):
        """Enumerate account details"""
        self.console.print("[dim]Enumerating account details...[/dim]")
        # Placeholder implementation
        self.results["account_info"] = {
            "project_details": {
                "displayName": "Example Firebase Project",
                "projectId": self.project_id or "example-firebase-project",
                "projectNumber": "123456789012",
                "createTime": "2023-01-01T00:00:00Z",
                "state": "ACTIVE"
            },
            "databases": [{
                "type": "realtime",
                "url": f"https://{self.project_id or 'example-firebase-project'}-default-rtdb.firebaseio.com",
                "rootKeys": ["users", "posts", "settings", "metadata"]
            }, {
                "type": "firestore",
                "url": f"https://firestore.googleapis.com/v1/projects/{self.project_id or 'example-firebase-project'}/databases/(default)/documents",
                "collections": ["users", "posts", "products", "orders"]
            }],
            "functions": [{
                "name": "processOrder",
                "entryPoint": "processOrder",
                "runtime": "nodejs14",
                "httpsTrigger": True,
                "status": "ACTIVE"
            }, {
                "name": "syncUsers",
                "entryPoint": "syncUsers",
                "runtime": "nodejs14",
                "httpsTrigger": False,
                "status": "ACTIVE"
            }],
            "storage_buckets": [{
                "name": f"{self.project_id or 'example-firebase-project'}.appspot.com",
                "url": f"https://storage.googleapis.com/{self.project_id or 'example-firebase-project'}.appspot.com",
                "files": [{
                    "name": "uploads/profile1.jpg",
                    "size": "2.5 MB",
                    "contentType": "image/jpeg"
                }, {
                    "name": "config/config.json",
                    "size": "1.2 KB",
                    "contentType": "application/json"
                }]
            }],
            "hosting_sites": [{
                "name": f"{self.project_id or 'example-firebase-project'}",
                "defaultUrl": f"https://{self.project_id or 'example-firebase-project'}.web.app",
                "appId": "1:123456789012:web:abcdef1234567890",
                "type": "DEFAULT_SITE"
            }],
            "members": [{
                "member": "user@example.com",
                "role": "roles/owner"
            }, {
                "member": "service-account@example.iam.gserviceaccount.com",
                "role": "roles/editor"
            }]
        }
    
    def analyze_security_rules(self):
        """Analyze security rules"""
        self.console.print("[dim]Analyzing security rules...[/dim]")
        # Placeholder implementation
        self.results["security_rules"] = {
            "database": {
                "rules": '{\n  "rules": {\n    ".read": true,\n    ".write": "auth != null"\n  }\n}',
                "vulnerabilities": [{
                    "description": "Database allows read access to all users without authentication",
                    "severity": "HIGH"
                }]
            },
            "firestore": {
                "rules": 'service cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read;\n      allow write: if request.auth != null;\n    }\n  }\n}',
                "vulnerabilities": [{
                    "description": "Firestore allows read access to all users without authentication",
                    "severity": "HIGH"
                }]
            },
            "storage": {
                "rules": 'service firebase.storage {\n  match /b/{bucket}/o {\n    match /{allPaths=**} {\n      allow read;\n      allow write: if request.auth != null;\n    }\n  }\n}',
                "vulnerabilities": [{
                    "description": "Storage allows read access to all users without authentication",
                    "severity": "HIGH"
                }]
            }
        }
    
    def dump_data(self):
        """Dump data from accessible services"""
        self.console.print("[dim]Dumping data from accessible services...[/dim]")
        # Placeholder implementation
        self.results["extracted_data"] = {
            "database": {
                "dump_path": f"{self.output_dir}/database_dump.json",
                "root_keys": ["users", "posts", "settings", "metadata"]
            },
            "firestore": {
                "dump_path": f"{self.output_dir}/firestore_dump.json",
                "collections": ["users", "posts", "products", "orders"]
            },
            "storage": {
                "dump_path": f"{self.output_dir}/storage_dump",
                "file_count": 5
            },
            "other": {}
        }
    
    # Include methods for vulnerability detection
    def _check_public_db_access(self):
        """Check for public database access without authentication"""
        self.console.print("[dim]Checking for public database access...[/dim]")
        # Placeholder implementation
        # This would be filled with actual implementation
        
        # Example vulnerability
        self.results["vulnerabilities"].append({
            "severity": "CRITICAL",
            "service": "Realtime Database",
            "description": "Database is publicly accessible without authentication and contains data.",
            "recommendation": "Update your Realtime Database rules to require authentication for all read/write operations."
        })
    
    def _check_storage_permissions(self):
        """Check for misconfigured storage buckets"""
        # Placeholder implementation
        pass
    
    def _check_excessive_permissions(self):
        """Check for excessive permissions in security rules"""
        # Placeholder implementation
        pass
    
    def extract_keys_and_tokens(self):
        """Extract API keys, tokens, and other sensitive credentials"""
        self.console.print("[dim]Extracting API keys, tokens, and credentials...[/dim]")
        # Placeholder implementation
        extracted_keys = {
            "api_keys": [{
                "value": "AIzaSyC1a5iTifoEoSgPLFcVkf96OH-QBmxZ9zA",
                "source": "Hosting: https://example-firebase-project.web.app",
                "description": "Google API Key"
            }],
            "tokens": [],
            "secrets": [],
            "passwords": [],
            "other_credentials": []
        }
        return extracted_keys
    
    def identify_advanced_vulnerabilities(self):
        """Identify more advanced vulnerabilities based on collected data"""
        self.console.print("[dim]Identifying advanced vulnerabilities...[/dim]")
        # Placeholder implementation
        self._check_public_db_access()
        self._check_storage_permissions()
        self._check_excessive_permissions()
    
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
        """Generate a text report"""
        self.console.print("[dim]Generating text report...[/dim]")
        # Placeholder implementation
        try:
            with open(output_file, 'w') as f:
                f.write(f"FireRFS - Firebase Security Assessment Report\n")
                f.write(f"===============================================\n\n")
                f.write(f"API Key: {self.api_key}\n")
                f.write(f"Project ID: {self.project_id}\n")
                f.write(f"Scan Time: {self.results['metadata']['scan_time']}\n\n")
                
                # Simple placeholder content
                f.write("Vulnerabilities Found: " + str(len(self.results["vulnerabilities"])) + "\n")
                f.write("Services Accessible: " + str(sum(1 for s in self.results["services"].values() if s.get("accessible", False))) + "\n")
            
            self.console.print(f"[green]Text report saved to {output_file}[/green]")
            return True
        except Exception as e:
            self.console.print(f"[bold red]Error generating text report: {str(e)}[/bold red]")
            return False
