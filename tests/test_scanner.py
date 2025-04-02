"""
Tests for the FireRFS scanner module.
"""
import pytest
from unittest.mock import Mock, patch
from pathlib import Path
import json

from firebase_rfs.core.scanner import FirebaseScanner
from firebase_rfs.utils.helpers import validate_api_key, validate_project_id

@pytest.fixture
def scanner():
    """Create a scanner instance for testing."""
    return FirebaseScanner(
        api_key="AIzaSyTestKey123456789",
        project_id="test-project-123"
    )

def test_validate_api_key():
    """Test API key validation."""
    # Valid API keys
    assert validate_api_key("AIzaSyTestKey123456789012345678901234567")
    assert validate_api_key("AIzaSy1234567890abcdefghijklmnopqrstuvw")
    
    # Invalid API keys
    assert not validate_api_key("")
    assert not validate_api_key("invalid-key")
    assert not validate_api_key("AIzaSy")  # Too short
    assert not validate_api_key("AIzaSy" + "a" * 100)  # Too long

def test_validate_project_id():
    """Test project ID validation."""
    # Valid project IDs
    assert validate_project_id("test-project-123")
    assert validate_project_id("myapp-dev")
    assert validate_project_id("firebase-demo")
    
    # Invalid project IDs
    assert not validate_project_id("")
    assert not validate_project_id("test")  # Too short
    assert not validate_project_id("a" * 31)  # Too long
    assert not validate_project_id("Test-Project")  # Uppercase not allowed
    assert not validate_project_id("test_project")  # Underscore not allowed

@patch('firebase_rfs.core.scanner.requests.get')
def test_check_api_key_restrictions(mock_get, scanner):
    """Test API key restrictions check."""
    # Mock response for valid API key
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "status": "success",
        "restrictions": {
            "android": True,
            "ios": True,
            "browser": ["example.com"]
        }
    }
    mock_get.return_value = mock_response
    
    result = scanner.check_api_key_restrictions()
    assert result["status"] == "success"
    assert "restrictions" in result
    assert result["restrictions"]["android"] is True

@patch('firebase_rfs.core.scanner.requests.get')
def test_check_service_accessibility(mock_get, scanner):
    """Test service accessibility check."""
    # Mock responses for different services
    responses = [
        Mock(status_code=200),  # Firestore
        Mock(status_code=403),  # Storage
        Mock(status_code=404)   # Database
    ]
    mock_get.side_effect = responses
    
    result = scanner.check_service_accessibility()
    assert "firestore" in result
    assert "storage" in result
    assert "database" in result
    assert result["firestore"]["accessible"] is True
    assert result["storage"]["accessible"] is False

def test_analyze_security_rules(scanner):
    """Test security rules analysis."""
    # Example security rules
    rules = {
        "rules": {
            ".read": "true",
            ".write": "auth != null",
            "users": {
                "$uid": {
                    ".read": "$uid === auth.uid",
                    ".write": "$uid === auth.uid"
                }
            }
        }
    }
    
    result = scanner.analyze_security_rules(rules)
    assert "findings" in result
    assert any(f["severity"] == "high" for f in result["findings"])
    assert any(f["title"] == "Public Read Access" for f in result["findings"])

def test_generate_report(scanner, tmp_path):
    """Test report generation."""
    # Sample scan results
    results = {
        "vulnerabilities": [
            {
                "title": "Public Read Access",
                "severity": "high",
                "description": "Database allows public read access",
                "recommendation": "Restrict read access with proper rules"
            }
        ],
        "metadata": {
            "scan_time": "2024-04-02T12:00:00",
            "scan_mode": "quick"
        }
    }
    
    report_file = scanner.generate_report(results, output_dir=str(tmp_path))
    assert Path(report_file).exists()
    assert Path(report_file).suffix == ".html" 