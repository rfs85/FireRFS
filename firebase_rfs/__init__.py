"""
FireRFS - Firebase Reconnaissance & Security Testing Tool
Advanced Firebase Security Assessment Framework
"""

__version__ = "1.2.0"
__author__ = "FireRFS Team"
__email__ = "support@firerfs.com"

from .firebase_rfs import FireRFS
from .integration import FireRFSIntegration

# Import utility functions
def create_archive(firerfs_instance):
    """Create an archive of assessment results"""
    # This is a placeholder function that will be implemented later
    pass

def run_auto_exploitation(firerfs_instance):
    """Run automated exploitation based on discovered vulnerabilities"""
    # This is a placeholder function that will be implemented later
    pass

__all__ = [
    'FireRFS',
    'FireRFSIntegration',
    'create_archive',
    'run_auto_exploitation',
]
