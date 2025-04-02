"""
FireRFS - Firebase Reconnaissance & Security Testing Tool
Advanced Firebase Security Assessment Framework
"""

__version__ = "1.2.0"
__author__ = "FireRFS Team"
__email__ = "support@firerfs.com"

from .firebase_rfs import FireRFS
from .integration import FireRFSIntegration
from .cli import main

__all__ = ['FireRFS', 'FireRFSIntegration', 'main']
