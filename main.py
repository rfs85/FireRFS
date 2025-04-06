#!/usr/bin/env python3

"""
FireRFS - Main Entry Point

This script serves as the main entry point for running FireRFS tests and examples.
It provides a command-line interface to run different types of security assessments
and demonstrations.
"""

import argparse
import logging
import sys
from pathlib import Path
from datetime import datetime

from firebase_rfs import FirebaseScanner, SecurityAnalyzer
from firebase_rfs.utils.helpers import setup_logging, load_config

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="FireRFS - Firebase Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--config",
        help="Path to configuration file",
        type=str,
        default="config.yaml"
    )
    
    parser.add_argument(
        "--test",
        help="Run test suite",
        action="store_true"
    )
    
    parser.add_argument(
        "--example",
        help="Run example (basic, rules, discovery, monitoring)",
        choices=["basic", "rules", "discovery", "monitoring"],
        type=str
    )
    
    parser.add_argument(
        "--output-dir",
        help="Output directory for results",
        type=str,
        default="scan_results"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        help="Increase output verbosity",
        action="store_true"
    )
    
    return parser.parse_args()

def run_tests():
    """Run the test suite."""
    import pytest
    print("Running FireRFS test suite...")
    return pytest.main(["tests/", "-v"])

def run_example(example_name: str, config: dict, output_dir: str):
    """
    Run the specified example.
    
    Args:
        example_name: Name of the example to run
        config: Configuration dictionary
        output_dir: Output directory for results
    """
    examples = {
        "basic": run_basic_example,
        "rules": run_rules_example,
        "discovery": run_discovery_example,
        "monitoring": run_monitoring_example
    }
    
    if example_name in examples:
        print(f"Running {example_name} example...")
        examples[example_name](config, output_dir)
    else:
        print(f"Unknown example: {example_name}")

def run_basic_example(config: dict, output_dir: str):
    """Run basic security assessment example."""
    try:
        # Initialize scanner
        scanner = FirebaseScanner(
            api_key=config.get("api_key", "YOUR_API_KEY"),
            project_id=config.get("project_id"),
            timeout=config.get("timeout", 30)
        )
        
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Run security checks
        results = {
            "api_key": scanner.check_api_key_restrictions(),
            "services": scanner.check_service_accessibility(),
            "security_rules": scanner.analyze_security_rules(),
            "vulnerabilities": scanner.scan_vulnerabilities(
                mode=config.get("scan_mode", "quick")
            )
        }
        
        # Analyze results
        analyzer = SecurityAnalyzer()
        analysis = analyzer.analyze_results(results)
        
        # Generate report
        report_path = scanner.generate_report(
            results={**results, "analysis": analysis},
            output_dir=str(output_path)
        )
        
        print(f"\nScan completed. Report saved to: {report_path}")
        
    except Exception as e:
        logging.error(f"Error in basic example: {str(e)}")
        sys.exit(1)

def run_rules_example(config: dict, output_dir: str):
    """Run security rules analysis example."""
    print("Security rules analysis example - To be implemented")

def run_discovery_example(config: dict, output_dir: str):
    """Run data discovery example."""
    print("Data discovery example - To be implemented")

def run_monitoring_example(config: dict, output_dir: str):
    """Run continuous monitoring example."""
    print("Continuous monitoring example - To be implemented")

def main():
    """Main entry point."""
    args = parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)
    
    # Load configuration
    try:
        config = load_config(args.config)
    except Exception as e:
        logging.error(f"Error loading configuration: {str(e)}")
        sys.exit(1)
    
    # Run tests if requested
    if args.test:
        sys.exit(run_tests())
    
    # Run example if specified
    if args.example:
        run_example(args.example, config, args.output_dir)
        sys.exit(0)
    
    # If no specific action is requested, show help
    print("Please specify an action (--test or --example)")
    print("Use -h or --help for usage information")
    sys.exit(1)

if __name__ == "__main__":
    main() 