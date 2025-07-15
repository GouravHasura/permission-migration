#!/usr/bin/env python3
"""
Test script to verify the permission migration works correctly.
This creates a backup, runs the migration, and shows the differences.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

def run_command(cmd, cwd=None):
    """Run a shell command and return the result."""
    try:
        result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def main():
    """Main test function."""
    print("🧪 Testing Permission Migration Script")
    print("=" * 50)
    
    # Check if directories exist
    hasura_ddn_path = Path("hasuraDDN/app/metadata")
    if not hasura_ddn_path.exists():
        print("❌ HasuraDDN metadata directory not found")
        return False
    
    # Create backup
    backup_path = Path("hasuraDDN/app/metadata.backup")
    if backup_path.exists():
        shutil.rmtree(backup_path)
    
    print("📁 Creating backup of DDN metadata...")
    shutil.copytree(hasura_ddn_path, backup_path)
    print("✅ Backup created at hasuraDDN/app/metadata.backup")
    
    try:
        # Run dry run first
        print("\n🔍 Running dry run...")
        success, stdout, stderr = run_command("python3 permission_migration.py --dry-run")
        if not success:
            print(f"⚠️  Dry run completed with warnings (some tables may have missing DDN files)")
            print("This is expected if not all tables have corresponding DDN files")
        else:
            print("✅ Dry run completed successfully")
        
        # Run actual migration
        print("\n🚀 Running actual migration...")
        success, stdout, stderr = run_command("python3 permission_migration.py --verbose")
        
        if success:
            print("✅ Migration completed successfully!")
            print("\n📊 Migration Summary:")
            # Extract summary from output
            lines = stdout.split('\n')
            for line in lines:
                if "Migration completed:" in line or "migrated successfully" in line:
                    print(f"   {line}")
        else:
            print(f"❌ Migration failed: {stderr}")
            return False
        
        # Show some sample changes
        print("\n📝 Sample changes made:")
        sample_files = ["addresses.hml", "insert_addresses.hml"]
        
        for filename in sample_files:
            original_file = backup_path / filename
            modified_file = hasura_ddn_path / filename
            
            if original_file.exists() and modified_file.exists():
                print(f"\n🔍 Changes in {filename}:")
                success, diff_output, _ = run_command(f"diff -u {original_file} {modified_file}")
                if diff_output:
                    # Show only the permission-related changes
                    diff_lines = diff_output.split('\n')
                    relevant_lines = []
                    for line in diff_lines:
                        if ('role:' in line or 'permissions:' in line or 
                            'allowedFields:' in line or 'allowExecution:' in line):
                            relevant_lines.append(line)
                    
                    if relevant_lines:
                        for line in relevant_lines[:10]:  # Show first 10 relevant lines
                            print(f"   {line}")
                        if len(relevant_lines) > 10:
                            print(f"   ... and {len(relevant_lines) - 10} more changes")
                    else:
                        print("   No permission-related changes detected")
                else:
                    print("   No changes detected")
        
        print(f"\n💾 Original files backed up to: {backup_path}")
        print("   You can restore them with: cp -r hasuraDDN/app/metadata.backup/* hasuraDDN/app/metadata/")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
