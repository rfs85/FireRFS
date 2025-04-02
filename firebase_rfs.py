#!/usr/bin/env python3

"""
FireRFS - Firebase Reconnaissance & Security Testing Tool
Advanced Firebase Security Assessment Framework
"""

import os
import sys
import json
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# Rich library for enhanced console output
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.syntax import Syntax
from rich.table import Table

# Firebase and security packages
import firebase_admin
from firebase_admin import credentials, db, firestore, storage
from cryptography.fernet import Fernet
from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation
from dns import resolver
import whois
import nmap

# Version and logging configuration
VERSION = "1.2.0"
console = Console()
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class ScanConfig:
    """Configuration for security scan."""
    depth: str
    services: List[str]
    timeout: int = 300
    max_threads: int = 10
    report_format: str = "html"

@dataclass
class VulnerabilityReport:
    """Structured vulnerability report."""
    severity: str
    description: str
    affected_component: str
    recommendation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None

class FireRFS:
    """
    Advanced FireRFS scanning framework with enhanced capabilities
    """
    
    def __init__(
        self,
        api_key: str,
        project_id: Optional[str] = None,
        config_path: Optional[str] = None,
        credentials_path: Optional[str] = None
    ) -> None:
        """
        Initialize the FireRFS scanner with configuration
        
        Args:
            api_key: Firebase API key
            project_id: Optional Firebase project ID
            config_path: Optional path to configuration file
            credentials_path: Optional path to Firebase credentials
        """
        self.console = Console()
        self.api_key = api_key
        self.project_id = project_id
        self.config = self._load_config(config_path)
        self.version = VERSION
        self.vulnerabilities: List[VulnerabilityReport] = []
        
        # Initialize Firebase Admin SDK if credentials provided
        if credentials_path and os.path.exists(credentials_path):
            cred = credentials.Certificate(credentials_path)
            firebase_admin.initialize_app(cred)
    
    def _load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Load configuration from file or use default settings
        
        Args:
            config_path: Optional path to JSON/YAML configuration file
        
        Returns:
            Configuration dictionary
        """
        default_config = {
            "default_services": [
                "database", "firestore", "auth", 
                "storage", "functions", "hosting"
            ],
            "scan_modes": {
                "quick": {
                    "depth": "low",
                    "services": ["database", "auth"]
                },
                "comprehensive": {
                    "depth": "high",
                    "services": ["database", "firestore", "auth", "storage", "functions", "hosting"]
                }
            },
            "vulnerability_thresholds": {
                "critical": 3,
                "high": 5,
                "medium": 7
            }
        }
        
        if config_path and os.path.exists(config_path):
            try:
                config_file = Path(config_path)
                if config_file.suffix in ['.yaml', '.yml']:
                    import yaml
                    with open(config_path) as f:
                        user_config = yaml.safe_load(f)
                else:
                    with open(config_path) as f:
                        user_config = json.load(f)
                default_config.update(user_config)
            except Exception as e:
                logger.error(f"Error loading configuration: {e}")
                self.console.print(f"[bold red]Error loading configuration: {e}[/bold red]")
        
        return default_config
    
    def validate_api_key(self, api_key: str) -> bool:
        """
        Perform comprehensive validation of Firebase API key
        
        Args:
            api_key: Firebase API key to validate
        
        Returns:
            Whether the key passes validation
        """
        if not api_key:
            return False
        
        # Firebase API key typical characteristics
        checks = [
            len(api_key) > 35,          # Minimum length
            len(api_key) < 45,          # Maximum length
            api_key.startswith('AIza'),  # Typical Firebase API key prefix
            all(c.isalnum() or c in ['-', '_'] for c in api_key)  # Valid characters
        ]
        
        return all(checks)
    
    async def scan_network_security(self) -> List[VulnerabilityReport]:
        """
        Perform comprehensive network security assessment
        
        Returns:
            List of discovered vulnerabilities
        """
        vulnerabilities = []
        
        # DNS security checks
        try:
            dns_results = resolver.resolve(f"{self.project_id}.firebaseapp.com", 'A')
            for ip in dns_results:
                # Perform additional security checks on IP
                nm = nmap.PortScanner()
                nm.scan(ip.to_text(), arguments='-sS -sV --script vuln')
                
                # Analyze results
                for host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        for port in ports:
                            service = nm[host][proto][port]
                            if service.get('state') == 'open':
                                vulnerabilities.append(
                                    VulnerabilityReport(
                                        severity="HIGH",
                                        description=f"Open port {port} running {service.get('name')}",
                                        affected_component="Network",
                                        recommendation=f"Consider closing port {port} if not required"
                                    )
                                )
        except Exception as e:
            logger.error(f"Error in DNS security scan: {e}")
        
        # SSL/TLS security checks
        try:
            server_location = ServerNetworkLocation(
                hostname=f"{self.project_id}.firebaseapp.com",
                port=443
            )
            scanner = Scanner()
            scan_request = ServerScanRequest(
                server_location=server_location,
                scan_commands=scanner.get_available_commands()
            )
            scan_result = scanner.run_scan_request(scan_request)
            
            # Analyze SSL/TLS results
            for result in scan_result.scan_commands_results:
                if result.scan_command_error:
                    vulnerabilities.append(
                        VulnerabilityReport(
                            severity="MEDIUM",
                            description=f"SSL/TLS issue: {result.scan_command_error}",
                            affected_component="SSL/TLS",
                            recommendation="Review and update SSL/TLS configuration"
                        )
                    )
        except Exception as e:
            logger.error(f"Error in SSL/TLS security scan: {e}")
        
        return vulnerabilities
    
    def scan_database_security(self) -> List[VulnerabilityReport]:
        """
        Perform comprehensive database security assessment
        
        Returns:
            List of discovered vulnerabilities
        """
        vulnerabilities = []
        
        # Realtime Database checks
        try:
            ref = db.reference('/')
            rules = ref.get_rules()
            
            # Analyze database rules
            if '.read' in rules and rules['.read'] is True:
                vulnerabilities.append(
                    VulnerabilityReport(
                        severity="CRITICAL",
                        description="Database allows unrestricted read access",
                        affected_component="Realtime Database",
                        recommendation="Implement proper read access rules",
                        cwe_id="CWE-284",
                        cvss_score=9.1
                    )
                )
            
            if '.write' in rules and rules['.write'] is True:
                vulnerabilities.append(
                    VulnerabilityReport(
                        severity="CRITICAL",
                        description="Database allows unrestricted write access",
                        affected_component="Realtime Database",
                        recommendation="Implement proper write access rules",
                        cwe_id="CWE-284",
                        cvss_score=9.1
                    )
                )
        except Exception as e:
            logger.error(f"Error in database security scan: {e}")
        
        # Firestore checks
        try:
            db = firestore.client()
            collections = db.collections()
            
            for collection in collections:
                # Check collection-level security
                if collection.get().exists:
                    vulnerabilities.append(
                        VulnerabilityReport(
                            severity="MEDIUM",
                            description=f"Collection '{collection.id}' is publicly readable",
                            affected_component="Firestore",
                            recommendation="Review collection-level security rules"
                        )
                    )
        except Exception as e:
            logger.error(f"Error in Firestore security scan: {e}")
        
        return vulnerabilities
    
    def generate_report(self, format: str = "html") -> Union[str, Dict[str, Any]]:
        """
        Generate a detailed security assessment report
        
        Args:
            format: Output format (html, json, or console)
        
        Returns:
            Formatted report content
        """
        if format == "json":
            return {
                "scan_date": datetime.now().isoformat(),
                "project_id": self.project_id,
                "vulnerabilities": [
                    {
                        "severity": v.severity,
                        "description": v.description,
                        "component": v.affected_component,
                        "recommendation": v.recommendation,
                        "cwe_id": v.cwe_id,
                        "cvss_score": v.cvss_score
                    }
                    for v in self.vulnerabilities
                ]
            }
        elif format == "html":
            # Generate rich HTML report
            report = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>FireRFS Security Report</title>
                <style>
                    body { font-family: Arial, sans-serif; }
                    .vulnerability { margin: 20px; padding: 10px; border: 1px solid #ccc; }
                    .critical { border-left: 5px solid #ff0000; }
                    .high { border-left: 5px solid #ff9900; }
                    .medium { border-left: 5px solid #ffcc00; }
                    .low { border-left: 5px solid #00cc00; }
                </style>
            </head>
            <body>
            """
            
            # Add vulnerabilities
            for vuln in self.vulnerabilities:
                report += f"""
                <div class="vulnerability {vuln.severity.lower()}">
                    <h3>{vuln.severity} - {vuln.affected_component}</h3>
                    <p><strong>Description:</strong> {vuln.description}</p>
                    <p><strong>Recommendation:</strong> {vuln.recommendation}</p>
                    {f'<p><strong>CWE:</strong> {vuln.cwe_id}</p>' if vuln.cwe_id else ''}
                    {f'<p><strong>CVSS Score:</strong> {vuln.cvss_score}</p>' if vuln.cvss_score else ''}
                </div>
                """
            
            report += "</body></html>"
            return report
        else:
            # Console output
            table = Table(title="Security Assessment Results")
            table.add_column("Severity", style="bold")
            table.add_column("Component")
            table.add_column("Description")
            table.add_column("Recommendation")
            
            for vuln in self.vulnerabilities:
                table.add_row(
                    vuln.severity,
                    vuln.affected_component,
                    vuln.description,
                    vuln.recommendation
                )
            
            return self.console.print(table)

if __name__ == "__main__":
    # This section is handled by cli.py
    pass 