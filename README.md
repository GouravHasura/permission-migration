# HasuraV2 to HasuraDDN Permission Migration Script

This Python script automates the migration of permissions from HasuraV2 metadata format to HasuraDDN format.

## Overview

The script reads permissions from HasuraV2 table YAML files and updates corresponding HasuraDDN HML files with the appropriate permission configurations.

### Permission Mapping

| HasuraV2 Permission Type | HasuraDDN Target Files | Permission Types Added |
|-------------------------|------------------------|----------------------|
| `select_permissions` | `<table>.hml` | ModelPermissions, TypePermissions |
| `insert_permissions` | `insert_<table>.hml` | CommandPermissions, TypePermissions |
| `update_permissions` | `update_<table>_by_id.hml` | CommandPermissions, TypePermissions |
| `delete_permissions` | `delete_<table>_by_id.hml` | CommandPermissions, TypePermissions |

## Prerequisites

- Python 3.6 or higher
- PyYAML library

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Make the script executable:
```bash
chmod +x permission_migration.py
```

## Usage

### Basic Usage

Run the script from the directory containing both `hasurav2` and `hasuraDDN` folders:

```bash
python permission_migration.py
```

### Custom Paths

Specify custom paths for HasuraV2 and HasuraDDN directories:

```bash
python permission_migration.py --v2-path /path/to/hasurav2 --ddn-path /path/to/hasuraDDN
```

### Verbose Logging

Enable detailed logging to see what the script is doing:

```bash
python permission_migration.py --verbose
```

### Dry Run

See what would be migrated without making any changes:

```bash
python permission_migration.py --dry-run
```

## Directory Structure

The script expects the following directory structure:

```
project/
├── hasurav2/
│   └── hasura-metadata/
│       └── metadata/
│           └── databases/
│               └── <database_name>/
│                   └── tables/
│                       ├── public_addresses.yaml
│                       ├── public_customers.yaml
│                       └── ...
└── hasuraDDN/
    └── app/
        └── metadata/
            ├── addresses.hml
            ├── insert_addresses.hml
            ├── update_addresses_by_id.hml
            ├── delete_addresses_by_id.hml
            └── ...
```

## What the Script Does

1. **Scans HasuraV2 tables**: Finds all `public_*.yaml` files in the HasuraV2 metadata
2. **Extracts permissions**: Reads select, insert, update, and delete permissions for each role
3. **Maps to DDN files**: Determines which DDN HML files need to be updated
4. **Updates permissions**: Adds new role permissions while preserving existing ones
5. **Saves changes**: Writes updated HML files back to disk

## Permission Details

### Select Permissions
- Added to `ModelPermissions` section in main table HML file
- Added to `TypePermissions` section for the table object type
- Includes filter expressions and allowed columns

### Insert Permissions
- Added to `CommandPermissions` for the insert command
- Added to `TypePermissions` for insert object and response types
- Includes allowed columns for insertion

### Update Permissions
- Added to `CommandPermissions` for the update command
- Added to `TypePermissions` for each column update type
- Added to `TypePermissions` for update columns object and response types
- Includes allowed columns for updates

### Delete Permissions
- Added to `CommandPermissions` for the delete command
- Added to `TypePermissions` for delete response type
- Includes filter expressions for deletion criteria

## Error Handling

The script includes comprehensive error handling:
- Validates that source and target directories exist
- Checks for missing HML files and logs warnings
- Continues processing other tables if one fails
- Provides detailed logging of success/failure for each table

## Backup Recommendation

**Important**: Always backup your HasuraDDN metadata before running the migration script, as it modifies the HML files in place.

```bash
cp -r hasuraDDN/app/metadata hasuraDDN/app/metadata.backup
```

## Troubleshooting

### Common Issues

1. **Missing HML files**: If DDN files don't exist for a table, the script will log warnings but continue
2. **YAML parsing errors**: Check that your HasuraV2 YAML files are valid
3. **Permission conflicts**: The script preserves existing permissions and adds new ones

### Debug Mode

Use verbose logging to see detailed information about what the script is doing:

```bash
python permission_migration.py --verbose
```

## Example Output

```
2024-01-15 10:30:00 - INFO - Starting permission migration from HasuraV2 to HasuraDDN
2024-01-15 10:30:00 - INFO - Found 10 table files to migrate
2024-01-15 10:30:00 - INFO - Migrating permissions for table: addresses
2024-01-15 10:30:00 - INFO - Migrating 3 select permissions
2024-01-15 10:30:00 - INFO - Added ModelPermissions for addresses, role: customer
2024-01-15 10:30:00 - INFO - ✓ Successfully migrated public_addresses.yaml
...
2024-01-15 10:30:05 - INFO - Migration completed: 10/10 tables migrated successfully
2024-01-15 10:30:05 - INFO - 🎉 All permissions migrated successfully!
```
