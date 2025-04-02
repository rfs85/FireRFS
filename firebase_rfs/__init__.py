"""
FireRFS - Firebase Security Assessment Tool
"""

__version__ = '1.2.0'
__author__ = 'FireRFS Team'
__email__ = 'contact@firerfs.com'
__description__ = 'A comprehensive security assessment tool for Firebase applications'

from firebase_rfs.core.scanner import FirebaseScanner
from firebase_rfs.core.analyzer import SecurityAnalyzer
from firebase_rfs.utils.reporting import ReportGenerator
from firebase_rfs.utils.helpers import (
    validate_api_key,
    validate_project_id,
    load_config,
    setup_logging
)

# Set up default logging
setup_logging()

__all__ = [
    'FirebaseScanner',
    'SecurityAnalyzer',
    'ReportGenerator',
    'validate_api_key',
    'validate_project_id',
    'load_config',
    'setup_logging',
    '__version__',
    '__author__',
    '__email__',
    '__description__'
]
