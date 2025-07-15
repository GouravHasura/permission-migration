# HasuraV2 to HasuraDDN Permission Migration Tool

A comprehensive tool for migrating permissions from HasuraV2 metadata format to HasuraDDN format, with validation and testing capabilities.

## 📁 Project Structure

```
hasura-permission-migrator/
├── permission_migration.py      # Main migration script
├── validate_migration.py        # Validation CLI tool
├── run_tests.py                # Test runner
├── test_migration.py           # Legacy test script
├── requirements.txt            # Python dependencies
├── README.md                   # This file
├── validators/                 # Validation modules
│   ├── __init__.py
│   └── migration_validator.py  # Core validation logic
└── tests/                      # Test suite
    ├── __init__.py
    └── test_migration_tool.py   # Comprehensive tests
```

## 🚀 Quick Start

### 1. Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Make scripts executable
chmod +x permission_migration.py validate_migration.py run_tests.py
```

### 2. Run Migration

```bash
# Basic migration (assumes hasurav2/ and hasuraDDN/ in parent directory)
python permission_migration.py

# With custom paths
python permission_migration.py --v2-path /path/to/hasurav2 --ddn-path /path/to/hasuraDDN

# Dry run to preview changes
python permission_migration.py --dry-run --verbose
```

### 3. Validate Migration

```bash
# Validate migration results
python validate_migration.py

# Generate detailed report
python validate_migration.py --output validation_report.json

# Only check migration completeness
python validate_migration.py --migration-only
```

### 4. Run Tests

```bash
# Run all tests
python run_tests.py

# Run specific test class
python -m unittest tests.test_migration_tool.TestMigrationTool -v
```

## 🔧 Features

### Migration Tool (`permission_migration.py`)
- **Complete Permission Migration**: Migrates select, insert, update, and delete permissions
- **Dry Run Mode**: Preview changes without modifying files
- **Error Handling**: Graceful handling of missing files and malformed data
- **Verbose Logging**: Detailed logging of migration progress
- **Backup Recommendations**: Built-in guidance for backing up data

### Validation Tool (`validate_migration.py`)
- **Migration Completeness**: Verifies all permissions were migrated
- **Permission Consistency**: Validates column mappings and role consistency
- **Detailed Reports**: JSON reports with comprehensive validation results
- **Selective Validation**: Options to run only specific validation types

### Test Suite (`tests/`)
- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end workflow testing
- **Edge Case Testing**: Error conditions and missing file scenarios
- **Validation Testing**: Comprehensive validator testing

## 📋 Validation Rules

The migration validator checks for:

### 1. Migration Completeness
- ✅ All HasuraV2 roles are present in corresponding DDN files
- ✅ Select permissions → TypePermissions and ModelPermissions
- ✅ Insert permissions → CommandPermissions and TypePermissions
- ✅ Update permissions → CommandPermissions and TypePermissions
- ✅ Delete permissions → CommandPermissions and TypePermissions

### 2. Permission Consistency
- ✅ Column permissions match between V2 and DDN
- ✅ Role names are consistent across permission types
- ✅ Required DDN files exist for each table

### 3. Data Integrity
- ✅ YAML/HML files are valid and parseable
- ✅ Permission structures follow expected formats
- ✅ No duplicate or conflicting permissions

## 🧪 Testing

### Test Categories

1. **Unit Tests** (`TestMigrationTool`)
   - Tool initialization
   - File loading and parsing
   - Individual permission migration methods
   - Error handling

2. **Validation Tests** (`TestMigrationValidator`)
   - Validation rule enforcement
   - Missing permission detection
   - Report generation

3. **Integration Tests** (`TestIntegration`)
   - Complete migration workflows
   - Multi-table scenarios
   - End-to-end validation

### Running Tests

```bash
# Run all tests with detailed output
python run_tests.py

# Run specific test categories
python -m unittest tests.test_migration_tool.TestMigrationTool
python -m unittest tests.test_migration_tool.TestMigrationValidator
python -m unittest tests.test_migration_tool.TestIntegration

# Run with coverage (if coverage.py is installed)
coverage run run_tests.py
coverage report
coverage html
```

## 📊 Example Usage

### Complete Migration Workflow

```bash
# 1. Backup your DDN metadata
cp -r hasuraDDN/app/metadata hasuraDDN/app/metadata.backup

# 2. Run dry run to preview changes
python permission_migration.py --dry-run --verbose

# 3. Run actual migration
python permission_migration.py --verbose

# 4. Validate results
python validate_migration.py --output validation_report.json

# 5. Run tests to ensure everything works
python run_tests.py
```

### Sample Output

```
🔍 HasuraV2 to HasuraDDN Permission Migration Validator
============================================================
Running full validation...

✅ Migration Completeness: All validations passed!

------------------------------------------------------------

✅ Permission Consistency: All validations passed!

============================================================
VALIDATION SUMMARY
============================================================
Total tables: 10
Successful migrations: 10
Failed migrations: 0
Consistency issues: 0

🎉 Overall Status: SUCCESS - All permissions migrated correctly!
Success rate: 100.0%

📄 Detailed report saved to: validation_report.json
```

## 🐛 Troubleshooting

### Common Issues

1. **Missing DDN Files**
   ```
   Error: Insert DDN file insert_table.hml not found
   ```
   **Solution**: Ensure all required DDN files exist before migration

2. **Permission Validation Failures**
   ```
   Missing roles in TypePermissions for table: ['admin']
   ```
   **Solution**: Re-run migration or manually add missing permissions

3. **YAML Parsing Errors**
   ```
   Error loading file.yaml: invalid YAML syntax
   ```
   **Solution**: Fix YAML syntax in source files

### Debug Mode

Enable verbose logging for detailed troubleshooting:

```bash
python permission_migration.py --verbose
python validate_migration.py --verbose
```

## 🤝 Contributing

1. **Add New Validation Rules**: Extend `MigrationValidator` class
2. **Add New Tests**: Create tests in `tests/test_migration_tool.py`
3. **Improve Error Handling**: Add better error messages and recovery
4. **Performance Optimization**: Optimize for large metadata sets

## 📄 License

This tool is provided as-is for HasuraV2 to HasuraDDN migration purposes.

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section above
2. Run tests to identify specific problems
3. Use verbose logging for detailed error information
4. Review validation reports for specific issues
