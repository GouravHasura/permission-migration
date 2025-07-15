#!/usr/bin/env python3
"""
Test runner for the HasuraV2 to HasuraDDN permission migration tool.

This script runs all tests and provides a comprehensive test report.
"""

import unittest
import sys
import os
from pathlib import Path
import logging

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

def run_tests():
    """Run all tests and return results."""
    # Configure logging for tests
    logging.basicConfig(level=logging.WARNING)
    
    # Discover and run tests
    loader = unittest.TestLoader()
    start_dir = Path(__file__).parent / 'tests'
    suite = loader.discover(start_dir, pattern='test_*.py')
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)
    
    return result

def print_test_summary(result):
    """Print a summary of test results."""
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped) if hasattr(result, 'skipped') else 0
    
    success_count = total_tests - failures - errors - skipped
    success_rate = (success_count / total_tests * 100) if total_tests > 0 else 0
    
    print(f"Total tests run: {total_tests}")
    print(f"Successful: {success_count}")
    print(f"Failures: {failures}")
    print(f"Errors: {errors}")
    print(f"Skipped: {skipped}")
    print(f"Success rate: {success_rate:.1f}%")
    
    if result.wasSuccessful():
        print("\n🎉 All tests passed!")
        return True
    else:
        print("\n❌ Some tests failed!")
        
        if result.failures:
            print("\nFAILURES:")
            for test, traceback in result.failures:
                print(f"  • {test}: {traceback.split('AssertionError:')[-1].strip()}")
        
        if result.errors:
            print("\nERRORS:")
            for test, traceback in result.errors:
                print(f"  • {test}: {traceback.split('Exception:')[-1].strip()}")
        
        return False

def main():
    """Main entry point."""
    print("🧪 Running HasuraV2 to HasuraDDN Permission Migration Tests")
    print("="*60)
    
    try:
        result = run_tests()
        success = print_test_summary(result)
        
        # Exit with appropriate code
        sys.exit(0 if success else 1)
        
    except Exception as e:
        print(f"❌ Test execution failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
