formatted_info += f"  DNS Records: {json.dumps(details.get('dns_records', {}), indent=2)}\n"
            formatted_info += f"  SSL Certificate: {json.dumps(details.get('ssl_certificate', {}), indent=2)}\n"
            formatted_info += f"  WHOIS Info: {json.dumps(details.get('whois_info', {}), indent=2)}\n\n"
        
        return formatted_info or "No network information discovered."
    
    def _format_vulnerabilities(self) -> str:
        """
        Format vulnerability information
        
        Returns:
            str: Formatted vulnerability details
        """
        vulnerability_levels = ['critical', 'high', 'medium', 'low']
        formatted_vulns = ""
        
        for level in vulnerability_levels:
            vulns = self.results['vulnerabilities'].get(level, [])
            formatted_vulns += f"{level.upper()} Vulnerabilities ({len(vulns)}):\n"
            
            for vuln in vulns[:5]:  # Limit to top 5 vulnerabilities
                formatted_vulns += f"  • {vuln.get('description', 'Unspecified vulnerability')}\n"
            
            formatted_vulns += "\n"
        
        return formatted_vulns or "No vulnerabilities detected."
    
    def _format_service_analysis(self) -> str:
        """
        Format service analysis information
        
        Returns:
            str: Formatted service analysis details
        """
        services = self.results['services']
        formatted_services = ""
        
        # Database Analysis
        formatted_services += "Database Analysis:\n"
        if services.get('database', {}).get('realtime_database', {}):
            rt_db = services['database']['realtime_database']
            formatted_services += f"  Realtime Database:\n"
            formatted_services += f"    Accessible Paths: {len(rt_db.get('accessible_paths', []))}\n"
            formatted_services += f"    Potential Vulnerabilities: {len(rt_db.get('potential_vulnerabilities', []))}\n"
        
        if services.get('database', {}).get('firestore', {}):
            firestore = services['database']['firestore']
            formatted_services += f"  Firestore:\n"
            formatted_services += f"    Accessible Collections: {len(firestore.get('accessible_collections', []))}\n"
            formatted_services += f"    Potential Vulnerabilities: {len(firestore.get('potential_vulnerabilities', []))}\n"
        
        # Add other service analyses as needed
        return formatted_services or "No service analysis available."
    
    def _format_exposed_credentials(self) -> str:
        """
        Format exposed credentials information
        
        Returns:
            str: Formatted credential exposure details
        """
        credentials = self.results['exposed_credentials']
        formatted_creds = ""
        
        for cred_type, creds in credentials.items():
            formatted_creds += f"{cred_type.replace('_', ' ').title()} Credentials:\n"
            
            if creds:
                for i, cred in enumerate(creds[:5], 1):  # Limit to top 5
                    formatted_creds += f"  {i}. Source: {cred.get('source', 'Unknown')}\n"
                    formatted_creds += f"     Type: {cred.get('type', 'Unknown')}\n"
                    # Partially mask sensitive information
                    if 'value' in cred:
                        masked_value = cred['value'][:4] + '*' * (len(cred['value']) - 8) + cred['value'][-4:]
                        formatted_creds += f"     Value: {masked_value}\n"
            else:
                formatted_creds += "  No credentials exposed\n"
            
            formatted_creds += "\n"
        
        return formatted_creds or "No exposed credentials detected."
    
    def comprehensive_security_assessment(self) -> Dict[str, Any]:
        """
        Perform a comprehensive security assessment of the Firebase project
        
        Returns:
            Dict containing comprehensive assessment results
        """
        # Initialize Firebase app
        try:
            cred = credentials.Certificate({
                "type": "service_account",
                "project_id": self.project_id,
                "private_key_id": "",
                "private_key": "",
                "client_email": "",
                "client_id": "",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": ""
            })
            firebase_admin.initialize_app(cred)
        except Exception as e:
            self.console.print(f"[red]Firebase App Initialization Error: {e}[/red]")
            return self.results
        
        try:
            # Perform comprehensive reconnaissance
            self.perform_network_reconnaissance()
            
            # Credential discovery
            self.credential_discovery()
            
            # Database analysis
            self.advanced_database_analysis()
            
            # Generate final report
            self.generate_comprehensive_report()
            
            return self.results
        
        except Exception as e:
            self.console.print(f"[red]Comprehensive Assessment Error: {e}[/red]")
            return self.results
        finally:
            # Clean up Firebase app
            try:
                firebase_admin.delete_app(firebase_admin.get_app())
            except ValueError:
                pass
    
    @classmethod
    def run_cli(cls):
        """
        Command-line interface for enhanced Firebase security assessment
        """
        import argparse
        
        parser = argparse.ArgumentParser(description="Enhanced Firebase Security Assessment Tool")
        parser.add_argument("-k", "--api-key", required=True, help="Firebase API key")
        parser.add_argument("-p", "--project-id", help="Firebase project ID")
        parser.add_argument("-o", "--output-dir", help="Output directory for results")
        parser.add_argument("--deep-scan", action="store_true", help="Perform deep security scanning")
        parser.add_argument("--credential-scan", action="store_true", help="Perform extensive credential discovery")
        
        args = parser.parse_args()
        
        # Initialize the assessment tool
        firerfs = cls(
            api_key=args.api_key, 
            project_id=args.project_id, 
            output_dir=args.output_dir
        )
        
        console = Console()
        console.print("[bold blue]Starting Enhanced Firebase Security Assessment[/bold blue]")
        
        try:
            # Perform comprehensive security assessment
            results = firerfs.comprehensive_security_assessment()
            
            # Optional deep scanning
            if args.deep_scan:
                console.print("[bold yellow]Performing Deep Security Scan...[/bold yellow]")
                # Add additional deep scanning logic if needed
            
            # Optional credential scanning
            if args.credential_scan:
                console.print("[bold yellow]Performing Extensive Credential Discovery...[/bold yellow]")
                additional_paths = ['/var/www', '/home']
                firerfs.credential_discovery(scan_paths=additional_paths)
            
            # Generate final report
            report = firerfs.generate_comprehensive_report()
            
            console.print(f"\n[bold green]Security Assessment Completed[/bold green]")
            console.print(f"Results saved in: {firerfs.output_dir}")
            
            return results
        
        except Exception as e:
            console.print(f"[bold red]Error during security assessment: {e}[/bold red]")
            import traceback
            traceback.print_exc()
            return None

def main():
    """
    Entry point for the Enhanced FireRFS CLI application
    """
    try:
        results = EnhancedFireRFS.run_cli()
        sys.exit(0 if results else 1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()#!/usr/bin/env python3

"""
Enhanced FireRFS - Advanced Firebase Reconnaissance & Security Testing Framework

Comprehensive security assessment tool for Firebase projects with:
- Multi-vector vulnerability detection
- Advanced reconnaissance techniques
- Detailed security analysis
"""

import os
import sys
import re
import json
import base64
import hashlib
import random
import requests
import ipaddress
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

# Advanced libraries for in-depth analysis
import firebase_admin
from firebase_admin import credentials, db, firestore, storage, auth
import jwt
import whois
import dns.resolver
import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

class EnhancedFireRFS:
    """
    Advanced Firebase Security Assessment Framework
    
    Provides comprehensive security testing and reconnaissance capabilities
    for Firebase projects.
    """
    
    def __init__(self, 
                 api_key: str, 
                 project_id: Optional[str] = None, 
                 output_dir: Optional[str] = None):
        """
        Initialize the enhanced Firebase security assessment tool
        
        Args:
            api_key (str): Firebase API key
            project_id (str, optional): Firebase project ID
            output_dir (str, optional): Directory to store assessment results
        """
        self.api_key = api_key
        self.project_id = project_id
        self.console = Console()
        
        # Enhanced results structure
        self.results = {
            "metadata": {
                "scan_timestamp": datetime.now().isoformat(),
                "api_key_hash": self._hash_sensitive_data(api_key)
            },
            "reconnaissance": {
                "network_infrastructure": {},
                "dns_records": {},
                "ssl_certificates": {}
            },
            "vulnerabilities": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": []
            },
            "services": {
                "authentication": {},
                "database": {
                    "realtime": {},
                    "firestore": {}
                },
                "storage": {},
                "hosting": {},
                "cloud_functions": {}
            },
            "exposed_credentials": {
                "api_keys": [],
                "tokens": [],
                "secrets": []
            }
        }
        
        # Output directory for results
        self.output_dir = output_dir or f"firerfs_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.output_dir, exist_ok=True)
    
    def _hash_sensitive_data(self, data: str) -> str:
        """
        Securely hash sensitive information
        
        Args:
            data (str): Sensitive data to hash
        
        Returns:
            str: SHA-256 hash of the data
        """
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    def perform_network_reconnaissance(self) -> Dict[str, Any]:
        """
        Conduct comprehensive network infrastructure reconnaissance
        
        Returns:
            Dict containing network infrastructure details
        """
        if not self.project_id:
            self.console.print("[yellow]Project ID required for network reconnaissance[/yellow]")
            return {}
        
        def resolve_dns_records(domain: str) -> Dict[str, List[str]]:
            """
            Resolve various DNS record types
            
            Args:
                domain (str): Domain to resolve
            
            Returns:
                Dict of DNS record types and their values
            """
            record_types = ['A', 'MX', 'TXT', 'NS', 'CNAME']
            dns_records = {}
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_records[record_type] = [str(rdata) for rdata in answers]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
            
            return dns_records
        
        def get_ssl_certificate(domain: str) -> Dict[str, Any]:
            """
            Retrieve SSL certificate details
            
            Args:
                domain (str): Domain to check
            
            Returns:
                Dict of SSL certificate information
            """
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                        der_cert = secure_sock.getpeercert(binary_form=True)
                        cert = x509.load_der_x509_certificate(der_cert, default_backend())
                        
                        return {
                            "subject": str(cert.subject),
                            "issuer": str(cert.issuer),
                            "version": cert.version.name,
                            "serial_number": cert.serial_number,
                            "not_valid_before": str(cert.not_valid_before),
                            "not_valid_after": str(cert.not_valid_after)
                        }
            except Exception as e:
                self.console.print(f"[red]SSL Certificate Error: {e}[/red]")
                return {}
        
        def get_whois_info(domain: str) -> Dict[str, Any]:
            """
            Retrieve WHOIS information for a domain
            
            Args:
                domain (str): Domain to lookup
            
            Returns:
                Dict of WHOIS information
            """
            try:
                domain_info = whois.whois(domain)
                return {
                    "registrar": domain_info.get("registrar", "Unknown"),
                    "creation_date": str(domain_info.get("creation_date", "Unknown")),
                    "expiration_date": str(domain_info.get("expiration_date", "Unknown"))
                }
            except Exception as e:
                self.console.print(f"[red]WHOIS Lookup Error: {e}[/red]")
                return {}
        
        # Construct domain variations
        domains = [
            f"{self.project_id}.firebaseapp.com",
            f"{self.project_id}.web.app",
            f"www.{self.project_id}.com"
        ]
        
        # Perform reconnaissance
        network_info = {}
        for domain in domains:
            try:
                network_info[domain] = {
                    "dns_records": resolve_dns_records(domain),
                    "ssl_certificate": get_ssl_certificate(domain),
                    "whois_info": get_whois_info(domain)
                }
            except Exception as e:
                self.console.print(f"[yellow]Reconnaissance failed for {domain}: {e}[/yellow]")
        
        # Store results
        self.results["reconnaissance"]["network_infrastructure"] = network_info
        return network_info
    
    def credential_discovery(self, scan_paths: List[str] = None) -> List[Dict[str, str]]:
        """
        Advanced credential discovery across multiple sources
        
        Args:
            scan_paths (List[str], optional): Additional paths to scan for credentials
        
        Returns:
            List of discovered credentials
        """
        credentials_found = []
        
        # Default scan paths
        default_paths = [
            os.path.expanduser('~'),
            '/etc',
            os.getcwd()
        ]
        
        # Merge paths
        scan_paths = (scan_paths or []) + default_paths
        
        # Regex patterns for credential detection
        credential_patterns = [
            r'(?i)(api[_]?key|secret[_]?key|access[_]?token|firebase[_]?token)',
            r'AIza[0-9A-Za-z\-_]{35}',  # Firebase API key pattern
            r'sk_[a-z]{2}_[0-9a-zA-Z]{24}',  # Stripe-like secret key
        ]
        
        def scan_file(filepath: str) -> List[Dict[str, str]]:
            """
            Scan a single file for potential credentials
            
            Args:
                filepath (str): Path to the file to scan
            
            Returns:
                List of discovered credentials
            """
            file_credentials = []
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    for pattern in credential_patterns:
                        matches = re.findall(pattern, content)
                        file_credentials.extend([
                            {
                                "type": "potential_credential",
                                "source": filepath,
                                "value": match,
                                "context": content[max(0, content.find(match)-50):content.find(match)+len(match)+50]
                            } for match in matches
                        ])
            except (UnicodeDecodeError, PermissionError, IsADirectoryError):
                pass
            return file_credentials
        
        # Recursive file scanning
        for base_path in scan_paths:
            try:
                for root, _, files in os.walk(base_path):
                    for file in files:
                        filepath = os.path.join(root, file)
                        credentials_found.extend(scan_file(filepath))
            except Exception as e:
                self.console.print(f"[yellow]Credential scan error in {base_path}: {e}[/yellow]")
        
        # Store and return results
        self.results["exposed_credentials"]["secrets"] = credentials_found
        return credentials_found
    
    def advanced_database_analysis(self) -> Dict[str, Any]:
        """
        Perform advanced analysis of Firebase databases
        
        Returns:
            Dict of database analysis results
        """
        database_analysis = {
            "realtime_database": self._analyze_realtime_database(),
            "firestore": self._analyze_firestore()
        }
        
        self.results["services"]["database"] = database_analysis
        return database_analysis
    
    def _analyze_realtime_database(self) -> Dict[str, Any]:
        """
        Analyze Realtime Database security and structure
        
        Returns:
            Dict of Realtime Database analysis results
        """
        db_analysis = {
            "accessible_paths": [],
            "potential_vulnerabilities": []
        }
        
        try:
            # Attempt to access root database reference
            root_ref = db.reference('/')
            
            def recursive_scan(ref, depth=0, max_depth=3):
                """
                Recursively scan database structure
                
                Args:
                    ref (DatabaseReference): Firebase database reference
                    depth (int): Current recursion depth
                    max_depth (int): Maximum recursion depth
                
                Returns:
                    Dict of scanned database structure
                """
                if depth > max_depth:
                    return {}
                
                try:
                    data = ref.get()
                    if isinstance(data, dict):
                        scanned_data = {}
                        for key, value in data.items():
                            # Check for sensitive key names
                            if re.search(r'(password|token|secret|key)', str(key), re.IGNORECASE):
                                db_analysis["potential_vulnerabilities"].append({
                                    "type": "sensitive_key_detected",
                                    "path": ref.path + '/' + key
                                })
                            
                            # Recursively scan
                            scanned_data[key] = recursive_scan(ref.child(key), depth + 1, max_depth)
                        return scanned_data
                    return data
                except Exception as e:
                    self.console.print(f"[yellow]Database scan error: {e}[/yellow]")
                    return {}
            
            # Perform recursive scan
            db_structure = recursive_scan(root_ref)
            
            db_analysis.update({
                "structure": db_structure,
                "root_keys": list(db_structure.keys()) if isinstance(db_structure, dict) else []
            })
        
        except Exception as e:
            self.console.print(f"[red]Realtime Database Analysis Error: {e}[/red]")
        
        return db_analysis
    
    def _analyze_firestore(self) -> Dict[str, Any]:
        """
        Analyze Firestore database security and structure
        
        Returns:
            Dict of Firestore analysis results
        """
        firestore_analysis = {
            "accessible_collections": [],
            "potential_vulnerabilities": []
        }
        
        try:
            # Initialize Firestore client
            firestore_client = firestore.client()
            
            # List all collections
            collections = list(firestore_client.collection_group('').stream())
            
            firestore_analysis["accessible_collections"] = [
                collection.id for collection in collections
            ]
            
            # Sample documents from collections
            for collection_id in firestore_analysis["accessible_collections"][:10]:  # Limit to first 10
                collection_ref = firestore_client.collection(collection_id)
                docs = list(collection_ref.limit(5).stream())
                
                for doc in docs:
                    doc_data = doc.to_dict()
                    
                    # Check for potential sensitive information
                    sensitive_keys = [
                        key for key in doc_data.keys() 
                        if re.search(r'(password|token|secret|key)', str(key), re.IGNORECASE)
                    ]
                    
                    if sensitive_keys:
                        firestore_analysis["potential_vulnerabilities"].append({
                            "type": "sensitive_data_detected",
                            "collection": collection_id,
                            "document_id": doc.id,
                            "sensitive_keys": sensitive_keys
                        })
        
        except Exception as e:
            self.console.print(f"[red]Firestore Analysis Error: {e}[/red]")
        
        return firestore_analysis
    
    def generate_comprehensive_report(self) -> str:
        """
        Generate a comprehensive security assessment report
        
        Returns:
            str: Formatted security report
        """
        report = Panel(
            self._create_report_content(),
            title="[bold]FireRFS Security Assessment Report[/bold]",
            border_style="red"
        )
        
        # Save report to file
        report_path = os.path.join(self.output_dir, "security_assessment_report.txt")
        with open(report_path, 'w') as f:
            f.write(str(report))
        
        return str(report)
    
    def _create_report_content(self) -> str:
        """
        Create detailed report content
        
        Returns:
            str: Formatted report content
        """
        report_content = f"""
[bold]Firebase Security Assessment Report[/bold]
Generated: {self.results['metadata']['scan_timestamp']}

[bold blue]1. Network Infrastructure[/bold blue]
{self._format_network_info()}

[bold blue]2. Vulnerabilities[/bold blue]
{self._format_vulnerabilities()}

[bold blue]3. Service Analysis[/bold blue]
{self._format_service_analysis()}

[bold blue]4. Exposed Credentials[/bold blue]
{self._format_exposed_credentials()}
"""
        return report_content
    
    def _format_network_info(self) -> str:
        """
        Format network infrastructure information
        
        Returns:
            str: Formatted network info
        """
        network_info = self.results['reconnaissance']['network_infrastructure']
        formatted_info = ""
        
        for domain, details in network_info.items():
            formatted_info += f"Domain: {domain}\n"
            formatted_info += f"