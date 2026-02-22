#!/usr/bin/env python3
"""Run all unit tests. Use: python run_tests.py or python -m unittest discover -s tests -t ."""
import sys
import os
import unittest

if __name__ == "__main__":
    # Ensure project root is on path for "tests" package and "src" is added via tests/__init__.py
    root = os.path.dirname(os.path.abspath(__file__))
    if root not in sys.path:
        sys.path.insert(0, root)
    # Run discover from tests directory with project root as top-level
    loader = unittest.TestLoader()
    start_dir = os.path.join(root, "tests")
    suite = loader.discover(start_dir=start_dir, top_level_dir=root, pattern="test_*.py")
    runner = unittest.runner.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
