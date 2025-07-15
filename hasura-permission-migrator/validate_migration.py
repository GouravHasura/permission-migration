#!/usr/bin/env python3
"""
Migration Validation CLI Tool

This script validates that HasuraV2 permissions were correctly migrated to HasuraDDN.
It checks for missing permissions, role consistency, and column mappings.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

# Add the validators directory to the path
sys.path.insert(0, str(Path(__file__).parent))

from validators.migration_validator import MigrationValidator

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def print_validation_results(results: dict, title: str):
    """Print validation results in a formatted way."""
    if not results:
        print(f"✅ {title}: All validations passed!")
        return
    
    print(f"❌ {title}: Found {len(results)} issues")
    for table_name, errors in results.items():
        print(f"\n  Table: {table_name}")
        for error in errors:
            print(f"    • {error}")

def print_summary(summary: dict):
    """Print validation summary."""
    print("\n" + "="*60)
    print("VALIDATION SUMMARY")
    print("="*60)
    
    print(f"Total tables: {summary['total_tables']}")
    print(f"Successful migrations: {summary['successful_migrations']}")
    print(f"Failed migrations: {summary['failed_migrations']}")
    print(f"Consistency issues: {summary['consistency_issues']}")
    
    if summary['overall_success']:
        print("\n🎉 Overall Status: SUCCESS - All permissions migrated correctly!")
    else:
        print("\n❌ Overall Status: FAILED - Some issues found")
        
    success_rate = (summary['successful_migrations'] / summary['total_tables']) * 100 if summary['total_tables'] > 0 else 0
    print(f"Success rate: {success_rate:.1f}%")

def save_report(report: dict, output_file: str):
    """Save validation report to a JSON file."""
    try:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n📄 Detailed report saved to: {output_file}")
    except Exception as e:
        logger.error(f"Failed to save report: {e}")

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Validate HasuraV2 to HasuraDDN permission migration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate migration using default paths
  python validate_migration.py
  
  # Validate with custom paths
  python validate_migration.py --v2-path ./hasurav2 --ddn-path ./hasuraDDN
  
  # Save detailed report to file
  python validate_migration.py --output validation_report.json
  
  # Enable debug logging
  python validate_migration.py --verbose
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
        '--output', '-o',
        help='Output file for detailed validation report (JSON format)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--migration-only',
        action='store_true',
        help='Only validate migration completeness (skip consistency checks)'
    )
    
    parser.add_argument(
        '--consistency-only',
        action='store_true',
        help='Only validate permission consistency (skip migration checks)'
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    print("🔍 HasuraV2 to HasuraDDN Permission Migration Validator")
    print("="*60)
    
    # Create validator instance
    validator = MigrationValidator(args.v2_path, args.ddn_path)
    
    try:
        if args.consistency_only:
            # Only run consistency validation
            print("Running consistency validation only...")
            consistency_results = validator.validate_permission_consistency()
            print_validation_results(consistency_results, "Permission Consistency")
            
        elif args.migration_only:
            # Only run migration validation
            print("Running migration validation only...")
            migration_results = validator.validate_all_migrations()
            print_validation_results(migration_results, "Migration Completeness")
            
        else:
            # Run full validation
            print("Running full validation...")
            report = validator.generate_validation_report()
            
            print_validation_results(report['migration_validation'], "Migration Completeness")
            print("\n" + "-"*60)
            print_validation_results(report['consistency_validation'], "Permission Consistency")
            
            print_summary(report['summary'])
            
            # Save detailed report if requested
            if args.output:
                save_report(report, args.output)
            
            # Exit with appropriate code
            if report['summary']['overall_success']:
                sys.exit(0)
            else:
                sys.exit(1)
                
    except Exception as e:
        logger.error(f"Validation failed with error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
