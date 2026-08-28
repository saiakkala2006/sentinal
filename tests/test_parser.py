"""
Unit tests for the EmailParser service.
"""

import pytest
import os
import sys

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.services.email_parser import EmailParser


def test_parser_extracts_headers():
    parser = EmailParser()
    sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "phishing.eml")
    with open(sample_path, "r", encoding="utf-8") as f:
        content = f.read()

    metadata = parser.parse(content)

    assert metadata["from"] is not None
    assert "sec-update-portal.xyz" in metadata["from"]
    assert metadata["subject"] == "URGENT: Mandatory Password Reset Required Within 24 Hours"
    assert metadata["spf"]["status"] == "fail"
    assert metadata["dkim"]["status"] == "fail"
    assert metadata["dmarc"]["status"] == "fail"
    assert metadata["x_originating_ip"] == "185.220.101.5"
    assert len(metadata["received_chain"]) >= 3
    assert metadata["charset"] == "windows-1251"
    assert metadata["return_path"] == "<bounce-daemon@botnet-node4.net>"


def test_parser_benign_email():
    parser = EmailParser()
    sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "benign.eml")
    with open(sample_path, "r", encoding="utf-8") as f:
        content = f.read()

    metadata = parser.parse(content)

    assert metadata["spf"]["status"] == "pass"
    assert metadata["dkim"]["status"] == "pass"
    assert metadata["dmarc"]["status"] == "pass"
    assert metadata["content_language"] == "en-US"
