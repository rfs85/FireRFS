#!/usr/bin/env python3

"""
FireRFS Integration Module
This module integrates all the components of FireRFS
"""

import os
import sys
import time
from datetime import datetime
import json
import shutil

# Import the console for rich output
from rich.console import Console
console = Console()

# Define constants
VERSION = "1.1.0"
SEVERITY_ORDER_MAP = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4
}

def create_archive(firerfs):
    """Create a ZIP archive of all results"""
    try:
        output_dir = firerfs.output_dir
        archive_name = f"{output_dir}_archive"
        
        # Create archive
        shutil.make_archive(archive_name, 'zip', output_dir)
        
        firerfs.console.print(f"\n[green]Results archived to {archive_name}.zip[/green]")
        return f"{archive_name}.zip"
    except Exception as e:
        firerfs.console.print(f"\n[bold red]Error creating archive: {str(e)}[/bold red]")
        return None

def run_auto_exploitation(firerfs, target_only=False):
    """Run automatic exploitation of discovered vulnerabilities
    
    Args:
        firerfs: FireRFS instance
        target_only: Only exploit critical vulnerabilities
    
    Returns:
        dict: Exploitation results
    """
    # This is a placeholder for auto-exploitation functionality
    # In a real implementation, this would attempt to exploit vulnerabilities
    
    firerfs.console.print("\n[bold yellow]Auto-exploitation module[/bold yellow]")
    firerfs.console.print("[yellow]Note: This is intended for authorized security testing only[/yellow]")
    
    if not firerfs.results["vulnerabilities"]:
        firerfs.console.print("[yellow]No vulnerabilities found to exploit[/yellow]")
        return {"exploited": 0, "failed": 0, "details": []}
    
    # Filter vulnerabilities based on target_only flag
    vulns_to_exploit = [v for v in firerfs.results["vulnerabilities"] 
                       if not target_only or v["severity"] == "CRITICAL"]
    
    if not vulns_to_exploit:
        firerfs.console.print("[yellow]No matching vulnerabilities to exploit[/yellow]")
        return {"exploited": 0, "failed": 0, "details": []}
    
    firerfs.console.print(f"[bold]Found {len(vulns_to_exploit)} vulnerabilities to attempt exploitation[/bold]")
    
    # Placeholder for exploitation results
    exploitation_results = {
        "exploited": 0,
        "failed": 0,
        "details": []
    }
    
    # In a real implementation, this would include actual exploitation code
    for vuln in vulns_to_exploit:
        firerfs.console.print(f"[bold]Attempting to exploit: {vuln['description']}[/bold]")
        
        # Placeholder for exploitation logic
        exploitation_results["details"].append({
            "vulnerability": vuln["description"],
            "service": vuln["service"],
            "severity": vuln["severity"],
            "result": "Exploitation not implemented in this version",
            "success": False
        })
        exploitation_results["failed"] += 1
    
    # Save exploitation results
    results_file = os.path.join(firerfs.output_dir, "exploitation_results.json")
    with open(results_file, 'w') as f:
        json.dump(exploitation_results, f, indent=4)
    
    firerfs.console.print(f"\n[yellow]Exploitation attempts completed. Successfully exploited: {exploitation_results['exploited']}, Failed: {exploitation_results['failed']}[/yellow]")
    firerfs.console.print(f"[dim]Results saved to {results_file}[/dim]")
    
    return exploitation_results

class FireRFSIntegration:
    """FireRFS Integration Class"""
    
    def __init__(self, firerfs_instance):
        """Initialize the integration class"""
        self.firerfs = firerfs_instance
        self.console = firerfs_instance.console
    
    def run_integrated_assessment(self):
        """Run the integrated assessment with all components"""
        start_time = time.time()
        
        # Step 1: Run basic assessment to gather information
        self.console.print("\n[bold blue]Phase 1:[/bold blue] Running basic reconnaissance...")
        self.firerfs.run_assessment_with_steps()
        
        # Save checkpoint after basic assessment
        checkpoint_file = os.path.join(self.firerfs.output_dir, "checkpoint_basic.json")
        with open(checkpoint_file, 'w') as f:
            json.dump(self.firerfs.results, f, indent=4)
        
        # Step 2: Run deep vulnerability assessment
        self.console.print("\n[bold blue]Phase 2:[/bold blue] Running deep vulnerability assessment...")
        self.firerfs.identify_advanced_vulnerabilities()
        
        # Save checkpoint after vulnerability assessment
        checkpoint_file = os.path.join(self.firerfs.output_dir, "checkpoint_vulns.json")
        with open(checkpoint_file, 'w') as f:
            json.dump(self.firerfs.results, f, indent=4)
        
        # Step 3: Extract credentials and sensitive data
        self.console.print("\n[bold blue]Phase 3:[/bold blue] Extracting credentials and sensitive data...")
        extracted_keys = self.firerfs.extract_keys_and_tokens()
        
        # Save extracted keys
        keys_file = os.path.join(self.firerfs.output_dir, "extracted_keys.json")
        with open(keys_file, 'w') as f:
            json.dump(extracted_keys, f, indent=4)
        
        # Step 4: Generate reports
        self.console.print("\n[bold blue]Phase 4:[/bold blue] Generating assessment reports...")
        
        # Generate HTML report
        if self.firerfs.html_report:
            output_file = os.path.join(self.firerfs.output_dir, f"firerfs_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
            self.firerfs.generate_html_report(output_file, extracted_keys)
        
        # Generate text report
        text_output_file = os.path.join(self.firerfs.output_dir, f"firerfs_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        self.firerfs.generate_text_report(text_output_file)
        
        # Save final results
        final_results_file = os.path.join(self.firerfs.output_dir, "final_results.json")
        with open(final_results_file, 'w') as f:
            json.dump(self.firerfs.results, f, indent=4)
        
        # Print terminal report
        self.firerfs.print_terminal_report()
        
        # Print completion message
        end_time = time.time()
        duration = end_time - start_time
        self.console.print(f"\n[bold green]Assessment completed in {duration:.2f} seconds[/bold green]")
        self.console.print(f"[bold]Results saved to: {self.firerfs.output_dir}[/bold]")
        
        summary = {
            "summary": {
                "duration": f"{duration:.2f} seconds",
                "vulnerabilities": {
                    "critical": len([v for v in self.firerfs.results["vulnerabilities"] if v["severity"] == "CRITICAL"]),
                    "high": len([v for v in self.firerfs.results["vulnerabilities"] if v["severity"] == "HIGH"]),
                    "medium": len([v for v in self.firerfs.results["vulnerabilities"] if v["severity"] == "MEDIUM"]),
                    "low": len([v for v in self.firerfs.results["vulnerabilities"] if v["severity"] == "LOW"]),
                    "info": len([v for v in self.firerfs.results["vulnerabilities"] if v["severity"] == "INFO"])
                },
                "services_accessible": sum(1 for s in self.firerfs.results["services"].values() if s.get("accessible", False)),
                "credentials_found": {
                    "api_keys": len(extracted_keys["api_keys"]),
                    "tokens": len(extracted_keys["tokens"]),
                    "secrets": len(extracted_keys["secrets"]),
                    "passwords": len(extracted_keys["passwords"]),
                    "other": len(extracted_keys["other_credentials"])
                },
                "data_extracted": bool(self.firerfs.data_dump)
            }
        }
        
        # Save summary
        summary_file = os.path.join(self.firerfs.output_dir, "assessment_summary.json")
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=4)
        
        return self.firerfs.results