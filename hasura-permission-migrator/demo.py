#!/usr/bin/env python3
"""
Demo script showing the complete HasuraV2 to HasuraDDN permission migration workflow.

This script demonstrates:
1. Running the migration tool
2. Validating the migration results
3. Running tests to verify functionality
4. Generating reports
"""

import subprocess
import sys
import json
from pathlib import Path
import argparse

def run_command(cmd, description, cwd=None):
    """Run a command and return success status."""
    print(f"\n{'='*60}")
    print(f"🔄 {description}")
    print(f"{'='*60}")
    print(f"Command: {cmd}")
    print()
    
    try:
        result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=False, text=True)
        success = result.returncode == 0
        
        if success:
            print(f"\n✅ {description} completed successfully!")
        else:
            print(f"\n❌ {description} failed with return code {result.returncode}")
        
        return success
    except Exception as e:
        print(f"\n❌ {description} failed with error: {e}")
        return False

def main():
    """Main demo function."""
    parser = argparse.ArgumentParser(
        description="Demo the complete HasuraV2 to HasuraDDN migration workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run complete demo with default paths
  python demo.py
  
  # Run demo with custom paths
  python demo.py --v2-path ../hasurav2 --ddn-path ../hasuraDDN
  
  # Skip migration and only run validation/tests
  python demo.py --skip-migration
        """
    )
    
    parser.add_argument(
        '--v2-path',
        default='../hasurav2',
        help='Path to HasuraV2 directory (default: ../hasurav2)'
    )
    
    parser.add_argument(
        '--ddn-path', 
        default='../hasuraDDN',
        help='Path to HasuraDDN directory (default: ../hasuraDDN)'
    )
    
    parser.add_argument(
        '--skip-migration',
        action='store_true',
        help='Skip migration step (useful if already migrated)'
    )
    
    parser.add_argument(
        '--skip-tests',
        action='store_true',
        help='Skip running tests'
    )
    
    args = parser.parse_args()
    
    print("🚀 HasuraV2 to HasuraDDN Permission Migration Demo")
    print("="*60)
    print(f"HasuraV2 path: {args.v2_path}")
    print(f"HasuraDDN path: {args.ddn_path}")
    print()
    
    # Change to the script directory
    script_dir = Path(__file__).parent
    
    success_count = 0
    total_steps = 0
    
    # Step 1: Run tests first to ensure everything is working
    if not args.skip_tests:
        total_steps += 1
        if run_command("python3 run_tests.py", "Running Tests", cwd=script_dir):
            success_count += 1
    
    # Step 2: Run migration (with dry run first)
    if not args.skip_migration:
        total_steps += 2
        
        # Dry run first
        dry_run_cmd = f"python3 permission_migration.py --v2-path {args.v2_path} --ddn-path {args.ddn_path} --dry-run --verbose"
        if run_command(dry_run_cmd, "Running Migration Dry Run", cwd=script_dir):
            success_count += 1

        # Actual migration
        migration_cmd = f"python3 permission_migration.py --v2-path {args.v2_path} --ddn-path {args.ddn_path} --verbose"
        if run_command(migration_cmd, "Running Actual Migration", cwd=script_dir):
            success_count += 1

    # Step 3: Validate migration results
    total_steps += 1
    validation_cmd = f"python3 validate_migration.py --v2-path {args.v2_path} --ddn-path {args.ddn_path} --output demo_validation_report.json --verbose"
    if run_command(validation_cmd, "Validating Migration Results", cwd=script_dir):
        success_count += 1
        
        # Show validation report summary
        report_file = script_dir / "demo_validation_report.json"
        if report_file.exists():
            try:
                with open(report_file, 'r') as f:
                    report = json.load(f)
                
                print(f"\n📊 VALIDATION REPORT SUMMARY")
                print(f"{'='*40}")
                summary = report.get('summary', {})
                print(f"Total tables: {summary.get('total_tables', 'N/A')}")
                print(f"Successful migrations: {summary.get('successful_migrations', 'N/A')}")
                print(f"Failed migrations: {summary.get('failed_migrations', 'N/A')}")
                print(f"Consistency issues: {summary.get('consistency_issues', 'N/A')}")
                print(f"Overall success: {summary.get('overall_success', 'N/A')}")
                
            except Exception as e:
                print(f"Could not read validation report: {e}")
    
    # Final summary
    print(f"\n{'='*60}")
    print("🎯 DEMO SUMMARY")
    print(f"{'='*60}")
    print(f"Completed steps: {success_count}/{total_steps}")
    
    if success_count == total_steps:
        print("🎉 All steps completed successfully!")
        print("\n✅ Your HasuraV2 permissions have been successfully migrated to HasuraDDN!")
        print("\n📋 Next steps:")
        print("  1. Review the validation report: demo_validation_report.json")
        print("  2. Test your HasuraDDN setup with the migrated permissions")
        print("  3. Remove the backup once you're satisfied with the results")
        
        return True
    else:
        print("❌ Some steps failed. Please check the output above for details.")
        print("\n🔧 Troubleshooting:")
        print("  1. Ensure HasuraV2 and HasuraDDN paths are correct")
        print("  2. Check that all required DDN files exist")
        print("  3. Run with --verbose for more detailed error information")
        print("  4. Review the validation report for specific issues")
        
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
