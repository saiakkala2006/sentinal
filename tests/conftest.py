"""
Pytest configuration — sets up path so tests can import backend.app modules.
"""
import sys
import os

# Ensure the sentinel root is on the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
# Also insert backend so 'from app.xxx import ...' works
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
