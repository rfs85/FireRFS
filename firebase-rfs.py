#!/usr/bin/env python3

"""
FireRFS - Firebase Reconnaissance & Security Testing Tool
A tool for Firebase security assessment and data exfiltration

Author: Security Researcher
Version: 1.1.0
"""

import argparse
import json
import sys
import os
import time
from datetime import datetime
from rich.console import Console
from rich.prompt import Confirm

# Import the necessary modules
from firebase_rfs import FireRFS
from integration import FireRFSIntegration, create_archive, run_auto_exploitation

# Version information
VERSION = "1.1.0"
console = Console()

def banner():
    """Display the tool banner"""
    console.print()
    console.print("""[bold red]
    ███████╗██╗██████╗ ███████╗    ██████╗ ███████╗███████╗
    ██╔════╝██║██╔══██╗██╔════╝    ██╔══██╗██╔════╝██╔════╝
    █████╗  ██║██████╔╝█████╗      ██████╔╝█████╗  ███████╗
    ██╔══╝  ██║██╔══██╗██╔══╝      ██╔══██╗██╔══╝  ╚════██║
    ██║     ██║██║  ██║███████╗    ██║  ██║██║     ███████║
    ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝╚═╝     ╚══════╝
    [/bold red]""")
    console.print("[bold]Firebase Reconnaissance & Security Testing Tool[/bold]", justify="center")
    console.print(f"v{VERSION}", justify="center")
    console.print()
    console.print("[dim]A tool for Firebase security testing and data exfiltration[/dim]", justify="center")
    console.print()

def main():
    """Main function"""
    # Print the banner
    banner()
    
    # Parse arguments
    parser = argparse.ArgumentParser(description="Firebase Reconnaissance & Security Testing Tool")
    parser.add_argument("-k", "--key", help="Firebase API key", required=True)
    parser.add_argument("-p", "--project-id", help="Firebase project ID (will be enumerated if not provided)")
    parser.add_argument("-s", "--services", help="Services to test (comma-separated list: database,firestore,auth,storage,functions,hosting)")
    parser.add_argument("-o", "--output", help="Output directory", default=None)
    parser.add_argument("-d", "--data", help="Dump all accessible data", action="store_true")
    parser.add_argument("--html", help="Generate HTML report", action="store_true", default=True)
    parser.add_argument("--no-html", help="Do not generate HTML report", action="store_false", dest="html")
    parser.add_argument("--text", help="Generate text report", action="store_true")
    parser.add_argument("--detailed", help="Detailed output", action="store_true")
    parser.add_argument("--archive", help="Create ZIP archive of results", action="store_true")
    parser.add_argument("--auto-exploit", help="Attempt to automatically exploit vulnerabilities (USE WITH CAUTION - Only on systems you own or have permission to test)", action="store_true")
    parser.add_argument("--exploit-critical-only", help="Only exploit critical vulnerabilities with auto-exploit option", action="store_true")
    parser.add_argument("--steps", help="Save results for each step to separate files", action="store_true", default=True)
    parser.add_argument("--no-steps", help="Don't save intermediate step results", action="store_false", dest="steps")
    
    # Add modes for specific testing types
    group = parser.add_argument_group('Testing Modes')
    group.add_argument("--recon-only", help="Only perform reconnaissance, no vulnerability testing", action="store_true")
    group.add_argument("--vuln-only", help="Only perform vulnerability testing, skip reconnaissance", action="store_true")
    group.add_argument("--quick", help="Perform quick testing (less comprehensive)", action="store_true")
    group.add_argument("--thorough", help="Perform thorough testing (more comprehensive, slower)", action="store_true")
    
    args = parser.parse_args()
    
    # Ask for confirmation if auto-exploit is enabled
    if args.auto_exploit:
        console.print("[bold red]WARNING: Auto-exploitation is enabled. This will attempt to exploit vulnerabilities in the target system.[/bold red]")
        console.print("[bold red]Only proceed if you have proper authorization to test this system.[/bold red]")
        if not Confirm.ask("Do you want to continue?"):
            console.print("[yellow]Operation cancelled by user[/yellow]")
            return 1
    
    try:
        # Parse services
        services = None
        if args.services:
            services = args.services.split(",")
        
        # Create output directory
        output_dir = args.output
        if not output_dir:
            output_dir = f"firerfs_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Initialize FireRFS
        firerfs = FireRFS(
            api_key=args.key,
            project_id=args.project_id,
            services=services,
            html_report=args.html,
            detailed=args.detailed,
            data_dump=args.data,
            output_dir=output_dir
        )
        
        # Create integration instance
        integration = FireRFSIntegration(firerfs)
        
        # Run appropriate assessment based on mode
        if args.recon_only:
            console.print("[bold blue]Running reconnaissance only mode...[/bold blue]")
            firerfs.run_assessment_with_steps()
        elif args.vuln_only:
            console.print("[bold blue]Running vulnerability assessment only mode...[/bold blue]")
            firerfs.identify_advanced_vulnerabilities()
        elif args.quick:
            console.print("[bold blue]Running quick assessment mode...[/bold blue]")
            firerfs.run_quick_assessment()
        elif args.thorough:
            console.print("[bold blue]Running thorough assessment mode...[/bold blue]")
            integration.run_integrated_assessment()
        else:
            # Default: Run standard assessment
            console.print("[bold blue]Running standard assessment...[/bold blue]")
            firerfs.run()
        
        # Run auto-exploitation if enabled
        if args.auto_exploit:
            run_auto_exploitation(firerfs, args.exploit_critical_only)
        
        # Create archive if requested
        if args.archive:
            create_archive(firerfs)
        
        # Print completion message
        console.print("\n[bold green]Assessment completed successfully[/bold green]")
        console.print(f"[bold]Results saved to: {firerfs.output_dir}[/bold]")
        
        # Suggest next steps
        console.print("\n[bold]Suggested next steps:[/bold]")
        console.print("1. Review the generated reports for security findings")
        console.print("2. Fix any identified vulnerabilities")
        console.print("3. Re-run the assessment to verify fixes")
        
        return 0
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        return 1
    except Exception as e:
        console.print(f"\n[bold red]Error: {str(e)}[/bold red]")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())