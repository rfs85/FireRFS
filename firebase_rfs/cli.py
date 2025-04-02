#!/usr/bin/env python3

"""
FireRFS - Firebase Reconnaissance & Security Testing Tool
Command-Line Interface Module
"""

import os
import sys
import json
import argparse
import traceback
from datetime import datetime

# Rich library for enhanced console output
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.syntax import Syntax
from rich.table import Table

# Import core assessment modules
from . import FireRFS, FireRFSIntegration, create_archive, run_auto_exploitation, __version__

# Version and configuration
VERSION = __version__
console = Console()

class FireRFSCLI:
    """
    Command-line interface for FireRFS security assessment tool
    """
    
    def __init__(self, config_path=None):
        """
        Initialize the FireRFS CLI
        
        Args:
            config_path (str, optional): Path to configuration file
        """
        self.console = Console()
        self.config = self._load_config(config_path)
        self.version = VERSION
    
    def _load_config(self, config_path=None):
        """
        Load configuration from file or use default settings
        
        Args:
            config_path (str, optional): Path to JSON configuration file
        
        Returns:
            dict: Configuration dictionary
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
                with open(config_path, 'r') as config_file:
                    user_config = json.load(config_file)
                    # Merge user config with default config
                    default_config.update(user_config)
            except (json.JSONDecodeError, IOError) as e:
                self.console.print(f"[bold red]Error loading configuration: {e}[/bold red]")
        
        return default_config
    
    def validate_api_key(self, api_key):
        """
        Perform comprehensive validation of Firebase API key
        
        Args:
            api_key (str): Firebase API key to validate
        
        Returns:
            bool: Whether the key passes validation
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
    
    def run_security_assessment(self, api_key, options=None):
        """
        Perform a comprehensive security assessment of a Firebase project
        
        Args:
            api_key (str): Firebase API key
            options (dict, optional): Assessment configuration options
        
        Returns:
            dict: Comprehensive assessment results
        """
        # Validate input
        if not self.validate_api_key(api_key):
            self.console.print("[bold red]Invalid Firebase API Key[/bold red]")
            return None
        
        # Merge default and user-provided options
        default_options = {
            "project_id": None,
            "scan_mode": "comprehensive",
            "services": None,
            "data_dump": False,
            "auto_exploit": False,
            "output_dir": None
        }
        assessment_options = {**default_options, **(options or {})}
        
        # Determine services to scan
        services = (
            assessment_options['services'] or 
            self.config['scan_modes'][assessment_options['scan_mode']]['services']
        )
        
        # Prepare output directory
        output_dir = (
            assessment_options['output_dir'] or 
            f"firerfs_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        os.makedirs(output_dir, exist_ok=True)
        
        # Progress tracking
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn()
        ) as progress:
            # Initialize progress
            task = progress.add_task("[green]Initializing Firebase Security Assessment...", total=100)
            
            try:
                # Initialize FireRFS
                progress.update(task, description="[yellow]Preparing assessment environment...")
                firerfs = FireRFS(
                    api_key=api_key,
                    project_id=assessment_options['project_id'],
                    services=services,
                    html_report=True,
                    detailed=True,
                    data_dump=assessment_options['data_dump'],
                    output_dir=output_dir
                )
                
                # Create integration instance
                integration = FireRFSIntegration(firerfs)
                
                # Update progress
                progress.update(task, advance=20, description="[yellow]Running comprehensive assessment...")
                
                # Perform assessment based on scan mode
                if assessment_options['scan_mode'] == 'quick':
                    results = firerfs.run_quick_assessment()
                else:
                    results = integration.run_integrated_assessment()
                
                # Optional auto-exploitation
                if assessment_options['auto_exploit']:
                    progress.update(task, advance=20, description="[yellow]Performing vulnerability exploitation...")
                    run_auto_exploitation(firerfs)
                
                # Create results archive
                progress.update(task, advance=20, description="[yellow]Creating results archive...")
                create_archive(firerfs)
                
                # Finalize progress
                progress.update(task, completed=100, description="[green]Security Assessment Completed Successfully!")
                
                return results
            
            except Exception as e:
                progress.update(task, description="[bold red]Assessment Failed[/bold red]")
                self.console.print(f"[bold red]Security Assessment Error: {e}[/bold red]")
                traceback.print_exc()
                return None
    
    def generate_risk_report(self, results):
        """
        Generate a detailed risk assessment report
        
        Args:
            results (dict): Security assessment results
        
        Returns:
            str: Formatted risk report
        """
        if not results:
            return "No assessment results available."
        
        # Create risk report panel
        risk_report = Panel(
            self._analyze_vulnerabilities(results),
            title="[bold]Firebase Security Risk Assessment[/bold]",
            border_style="red"
        )
        
        return risk_report
    
    def _analyze_vulnerabilities(self, results):
        """
        Analyze and categorize vulnerabilities
        
        Args:
            results (dict): Security assessment results
        
        Returns:
            str: Formatted vulnerability analysis
        """
        vulnerabilities = results.get('vulnerabilities', [])
        
        # Categorize vulnerabilities by severity
        severity_categories = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': [],
            'INFO': []
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            severity_categories[severity].append(vuln)
        
        # Generate detailed report
        report = "Vulnerability Breakdown:\n\n"
        for severity, vulns in severity_categories.items():
            color_map = {
                'CRITICAL': 'bold red',
                'HIGH': 'red', 
                'MEDIUM': 'yellow', 
                'LOW': 'green', 
                'INFO': 'blue'
            }
            
            report += f"[{color_map[severity]}]{severity} Vulnerabilities: {len(vulns)}[/{color_map[severity]}]\n"
            
            # Add details for critical and high vulnerabilities
            if severity in ['CRITICAL', 'HIGH']:
                for vuln in vulns[:5]:  # Limit to top 5 to prevent overwhelm
                    report += f"  • {vuln.get('description', 'Unspecified vulnerability')}\n"
        
        return report
    
    def interactive_scan(self):
        """
        Interactive scanning mode with guided user input
        """
        self.console.print("[bold blue]FireRFS Interactive Security Scanner[/bold blue]")
        
        # API Key Input
        while True:
            api_key = self.console.input("[bold]Enter Firebase API Key: [/bold]").strip()
            if self.validate_api_key(api_key):
                break
            self.console.print("[bold red]Invalid API key. Please try again.[/bold red]")
        
        # Project ID (optional)
        project_id = self.console.input("[bold]Enter Project ID (optional): [/bold]").strip() or None
        
        # Scanning Options
        scan_mode = self.console.input(
            "[bold]Select Scan Mode (quick/comprehensive) [default: comprehensive]: [/bold]"
        ).strip().lower() or 'comprehensive'
        
        data_dump = self.console.input("[bold]Dump accessible data? (y/N): [/bold]").lower().strip() == 'y'
        auto_exploit = self.console.input("[bold]Perform auto-exploitation? (y/N): [/bold]").lower().strip() == 'y'
        
        # Run assessment
        assessment_options = {
            'project_id': project_id,
            'scan_mode': scan_mode,
            'data_dump': data_dump,
            'auto_exploit': auto_exploit
        }
        
        results = self.run_security_assessment(api_key, assessment_options)
        
        if results:
            # Display risk report
            risk_report = self.generate_risk_report(results)
            self.console.print(risk_report)
        
        return results

def main():
    """
    Main entry point for FireRFS CLI
    """
    parser = argparse.ArgumentParser(description="FireRFS - Firebase Security Assessment Tool")
    
    # Core arguments
    parser.add_argument("-k", "--api-key", help="Firebase API key")
    parser.add_argument("-p", "--project-id", help="Firebase Project ID")
    
    # Scanning mode arguments
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("--scan-mode", choices=['quick', 'comprehensive'], default='comprehensive', 
                        help="Scanning depth and comprehensiveness")
    
    # Additional options
    parser.add_argument("--data-dump", action="store_true", help="Dump accessible data")
    parser.add_argument("--auto-exploit", action="store_true", help="Attempt to exploit vulnerabilities")
    parser.add_argument("--config", help="Path to custom configuration file")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = FireRFSCLI(args.config)
    
    try:
        if args.interactive:
            # Run interactive mode
            results = scanner.interactive_scan()
        else:
            # Validate API key is provided
            if not args.api_key:
                console.print("[bold red]Error: API key is required[/bold red]")
                parser.print_help()
                return 1
            
            # Run security assessment
            results = scanner.run_security_assessment(
                args.api_key, 
                {
                    'project_id': args.project_id,
                    'scan_mode': args.scan_mode,
                    'data_dump': args.data_dump,
                    'auto_exploit': args.auto_exploit
                }
            )
        
        # Exit with appropriate status
        return 0 if results else 1
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user.[/yellow]")
        return 1
    except Exception as e:
        console.print(f"[bold red]Unexpected error: {e}[/bold red]")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())