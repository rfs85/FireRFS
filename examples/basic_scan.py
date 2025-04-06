#!/usr/bin/env python3

"""
Basic example of using FireRFS for Firebase security assessment
"""

from firebase_rfs import FirebaseScanner, SecurityAnalyzer
from pathlib import Path
import json

def main():
    # Initialize the scanner with your Firebase API key
    # You can also provide a project ID for more comprehensive scanning
    scanner = FirebaseScanner(
        api_key="YOUR_FIREBASE_API_KEY",
        project_id="YOUR_PROJECT_ID",  # Optional
        timeout=30  # Optional, default is 30 seconds
    )
    
    # Create output directory
    output_dir = Path("scan_results")
    output_dir.mkdir(exist_ok=True)
    
    # Step 1: Check API key restrictions
    print("Checking API key restrictions...")
    api_key_results = scanner.check_api_key_restrictions()
    
    # Step 2: Check service accessibility
    print("Checking service accessibility...")
    service_results = scanner.check_service_accessibility()
    
    # Step 3: Analyze security rules
    print("Analyzing security rules...")
    rules_results = scanner.analyze_security_rules()
    
    # Step 4: Scan for vulnerabilities
    print("Scanning for vulnerabilities...")
    vuln_results = scanner.scan_vulnerabilities(mode="quick")  # or "comprehensive"
    
    # Combine all results
    assessment_results = {
        "api_key": api_key_results,
        "services": service_results,
        "security_rules": rules_results,
        "vulnerabilities": vuln_results
    }
    
    # Initialize the security analyzer
    analyzer = SecurityAnalyzer()
    
    # Analyze the results
    print("Analyzing results...")
    analysis = analyzer.analyze_results(assessment_results)
    
    # Generate report
    print("Generating report...")
    report_path = scanner.generate_report(
        results={**assessment_results, "analysis": analysis},
        output_dir=str(output_dir)
    )
    
    # Save raw results
    with open(output_dir / "raw_results.json", "w") as f:
        json.dump(assessment_results, f, indent=2)
    
    # Print summary
    print("\nAssessment Summary:")
    print(f"Total Vulnerabilities: {analysis['summary']['total_vulnerabilities']}")
    print(f"Critical: {analysis['summary']['critical_vulnerabilities']}")
    print(f"High: {analysis['summary']['high_vulnerabilities']}")
    print(f"Medium: {analysis['summary']['medium_vulnerabilities']}")
    print(f"Low: {analysis['summary']['low_vulnerabilities']}")
    print(f"\nRisk Score: {analysis['risk_score']}/10")
    print(f"Risk Level: {analysis['metadata']['risk_level'].upper()}")
    print(f"\nReport saved to: {report_path}")

if __name__ == "__main__":
    main() 