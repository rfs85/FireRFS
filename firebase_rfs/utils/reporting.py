"""
Reporting utilities for FireRFS.
"""
from pathlib import Path
from datetime import datetime
import json
from typing import Dict, List, Any, Optional

from jinja2 import Environment, FileSystemLoader
from rich.console import Console
from rich.progress import Progress

class ReportGenerator:
    """Generates security assessment reports in various formats."""
    
    def __init__(self, template_dir: Optional[str] = None):
        """Initialize the report generator."""
        if template_dir is None:
            template_dir = str(Path(__file__).parent.parent / 'templates')
        self.template_dir = template_dir
        self.env = Environment(loader=FileSystemLoader(template_dir))
        self.console = Console()
    
    def generate_html_report(self, results: Dict[str, Any], output_dir: str) -> str:
        """Generate an HTML report from assessment results."""
        template = self.env.get_template('report.html')
        
        # Create timestamp for report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = Path(output_dir) / f'firerfs_results_{timestamp}'
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate report filename
        report_file = output_dir / f'firerfs_report_{timestamp}.html'
        
        # Add metadata to results
        results['generated_at'] = datetime.now().isoformat()
        results['firerfs_version'] = '1.2.0'
        
        # Render and save report
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(template.render(results=results))
        
        return str(report_file)
    
    def export_json(self, results: Dict[str, Any], output_file: str) -> None:
        """Export results to JSON format."""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
    
    def print_summary(self, results: Dict[str, Any]) -> None:
        """Print a summary of findings to the console."""
        self.console.print("\n[bold]Security Assessment Summary[/bold]")
        
        # Print vulnerabilities by severity
        vulnerabilities = results.get('vulnerabilities', [])
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            severity_counts[severity] += 1
        
        self.console.print(f"\nFound vulnerabilities:")
        self.console.print(f"  High: {severity_counts['high']}")
        self.console.print(f"  Medium: {severity_counts['medium']}")
        self.console.print(f"  Low: {severity_counts['low']}")
        
        # Print recommendations
        if 'recommendations' in results:
            self.console.print("\n[bold]Top Recommendations:[/bold]")
            for rec in results['recommendations'][:3]:
                self.console.print(f"- {rec}") 