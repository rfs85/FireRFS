"""
Helper utilities for FireRFS.
"""
from typing import Dict, List, Any, Optional
import re
import yaml
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

def load_config(config_file: str) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    try:
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading config file: {e}")
        return {}

def validate_api_key(api_key: str) -> bool:
    """Validate Firebase API key format."""
    if not api_key:
        return False
    
    # Basic format validation for Firebase API keys
    pattern = r'^AIza[0-9A-Za-z-_]{35}$'
    return bool(re.match(pattern, api_key))

def validate_project_id(project_id: str) -> bool:
    """Validate Firebase project ID format."""
    if not project_id:
        return False
    
    # Project IDs must be between 6 and 30 characters
    if not 6 <= len(project_id) <= 30:
        return False
    
    # Must contain only lowercase letters, digits, or hyphens
    pattern = r'^[a-z0-9-]+$'
    return bool(re.match(pattern, project_id))

def create_output_directory(base_dir: str = None) -> Path:
    """Create and return path to output directory."""
    from datetime import datetime
    
    if base_dir is None:
        base_dir = Path.cwd()
    else:
        base_dir = Path(base_dir)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = base_dir / f'firerfs_results_{timestamp}'
    output_dir.mkdir(parents=True, exist_ok=True)
    
    return output_dir

def setup_logging(level: str = 'INFO') -> None:
    """Configure logging for the application."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def parse_scan_results(raw_results: Dict[str, Any]) -> Dict[str, Any]:
    """Parse and format scan results."""
    parsed = {
        'vulnerabilities': [],
        'recommendations': [],
        'metadata': {
            'scan_time': raw_results.get('scan_time'),
            'scan_mode': raw_results.get('scan_mode')
        }
    }
    
    # Process vulnerabilities
    for vuln in raw_results.get('findings', []):
        severity = vuln.get('severity', 'low').lower()
        if severity not in ['low', 'medium', 'high']:
            severity = 'low'
        
        parsed['vulnerabilities'].append({
            'title': vuln.get('title', 'Unknown Issue'),
            'description': vuln.get('description', ''),
            'severity': severity,
            'recommendation': vuln.get('recommendation', ''),
            'references': vuln.get('references', [])
        })
    
    # Generate recommendations
    parsed['recommendations'] = [
        vuln['recommendation']
        for vuln in parsed['vulnerabilities']
        if vuln['recommendation']
    ]
    
    return parsed 