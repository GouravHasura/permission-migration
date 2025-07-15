#!/usr/bin/env python3
"""
Comprehensive tests for the HasuraV2 to HasuraDDN permission migration tool.

This test suite validates:
1. Migration tool functionality
2. Validation rules
3. Edge cases and error handling
4. End-to-end migration scenarios
"""

import unittest
import tempfile
import shutil
import yaml
import json
from pathlib import Path
import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from permission_migration import PermissionMigrator
from validators.migration_validator import MigrationValidator

class TestMigrationTool(unittest.TestCase):
    """Test cases for the permission migration tool."""
    
    def setUp(self):
        """Set up test environment with temporary directories and sample data."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.v2_dir = self.test_dir / "hasurav2"
        self.ddn_dir = self.test_dir / "hasuraDDN"
        
        # Create directory structure
        self.v2_tables_dir = self.v2_dir / "hasura-metadata" / "metadata" / "databases" / "testdb" / "tables"
        self.ddn_metadata_dir = self.ddn_dir / "app" / "metadata"
        
        self.v2_tables_dir.mkdir(parents=True)
        self.ddn_metadata_dir.mkdir(parents=True)
        
        # Create sample HasuraV2 table configuration
        self.create_sample_v2_table()
        self.create_sample_ddn_files()
        
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)
    
    def create_sample_v2_table(self):
        """Create a sample HasuraV2 table configuration."""
        v2_config = {
            'table': {
                'name': 'users',
                'schema': 'public'
            },
            'select_permissions': [
                {
                    'role': 'user',
                    'permission': {
                        'columns': ['id', 'name', 'email'],
                        'filter': {}
                    }
                },
                {
                    'role': 'admin',
                    'permission': {
                        'columns': ['id', 'name', 'email', 'created_at'],
                        'filter': {}
                    }
                }
            ],
            'insert_permissions': [
                {
                    'role': 'admin',
                    'permission': {
                        'check': {},
                        'columns': ['name', 'email']
                    }
                }
            ],
            'update_permissions': [
                {
                    'role': 'admin',
                    'permission': {
                        'columns': ['name', 'email'],
                        'filter': {},
                        'check': {}
                    }
                }
            ],
            'delete_permissions': [
                {
                    'role': 'admin',
                    'permission': {
                        'filter': {}
                    }
                }
            ]
        }
        
        v2_file = self.v2_tables_dir / "public_users.yaml"
        with open(v2_file, 'w') as f:
            yaml.dump(v2_config, f)
    
    def create_sample_ddn_files(self):
        """Create sample DDN files for testing."""
        # Main table file
        main_config = [
            {
                'kind': 'ObjectType',
                'version': 'v1',
                'definition': {
                    'name': 'users',
                    'fields': [
                        {'name': 'id', 'type': 'int32!'},
                        {'name': 'name', 'type': 'string'},
                        {'name': 'email', 'type': 'string'},
                        {'name': 'created_at', 'type': 'timestamp'}
                    ]
                }
            },
            {
                'kind': 'TypePermissions',
                'version': 'v1',
                'definition': {
                    'typeName': 'users',
                    'permissions': []
                }
            },
            {
                'kind': 'ModelPermissions',
                'version': 'v1',
                'definition': {
                    'modelName': 'users',
                    'permissions': []
                }
            }
        ]
        
        main_file = self.ddn_metadata_dir / "users.hml"
        with open(main_file, 'w') as f:
            for i, doc in enumerate(main_config):
                if i > 0:
                    f.write('\n---\n')
                else:
                    f.write('---\n')
                yaml.dump(doc, f)
        
        # Insert file
        insert_config = [
            {
                'kind': 'ObjectType',
                'version': 'v1',
                'definition': {
                    'name': 'insert_users_object',
                    'fields': [
                        {'name': 'name', 'type': 'string'},
                        {'name': 'email', 'type': 'string'}
                    ]
                }
            },
            {
                'kind': 'TypePermissions',
                'version': 'v1',
                'definition': {
                    'typeName': 'insert_users_object',
                    'permissions': []
                }
            },
            {
                'kind': 'TypePermissions',
                'version': 'v1',
                'definition': {
                    'typeName': 'insert_users_response',
                    'permissions': []
                }
            },
            {
                'kind': 'CommandPermissions',
                'version': 'v1',
                'definition': {
                    'commandName': 'insert_users',
                    'permissions': []
                }
            }
        ]
        
        insert_file = self.ddn_metadata_dir / "insert_users.hml"
        with open(insert_file, 'w') as f:
            for i, doc in enumerate(insert_config):
                if i > 0:
                    f.write('\n---\n')
                else:
                    f.write('---\n')
                yaml.dump(doc, f)
        
        # Update file
        update_config = [
            {
                'kind': 'TypePermissions',
                'version': 'v1',
                'definition': {
                    'typeName': 'update_users_by_id_update_columns',
                    'permissions': []
                }
            },
            {
                'kind': 'TypePermissions',
                'version': 'v1',
                'definition': {
                    'typeName': 'update_users_by_id_response',
                    'permissions': []
                }
            },
            {
                'kind': 'CommandPermissions',
                'version': 'v1',
                'definition': {
                    'commandName': 'update_users_by_id',
                    'permissions': []
                }
            }
        ]
        
        update_file = self.ddn_metadata_dir / "update_users_by_id.hml"
        with open(update_file, 'w') as f:
            for i, doc in enumerate(update_config):
                if i > 0:
                    f.write('\n---\n')
                else:
                    f.write('---\n')
                yaml.dump(doc, f)
        
        # Delete file
        delete_config = [
            {
                'kind': 'TypePermissions',
                'version': 'v1',
                'definition': {
                    'typeName': 'delete_users_by_id_response',
                    'permissions': []
                }
            },
            {
                'kind': 'CommandPermissions',
                'version': 'v1',
                'definition': {
                    'commandName': 'delete_users_by_id',
                    'permissions': []
                }
            }
        ]
        
        delete_file = self.ddn_metadata_dir / "delete_users_by_id.hml"
        with open(delete_file, 'w') as f:
            for i, doc in enumerate(delete_config):
                if i > 0:
                    f.write('\n---\n')
                else:
                    f.write('---\n')
                yaml.dump(doc, f)

    def test_migration_tool_initialization(self):
        """Test that the migration tool initializes correctly."""
        migrator = PermissionMigrator(str(self.v2_dir), str(self.ddn_dir))

        self.assertEqual(migrator.hasura_v2_path, self.v2_dir)
        self.assertEqual(migrator.hasura_ddn_path, self.ddn_dir)
        self.assertTrue(migrator.v2_tables_path.exists())
        self.assertTrue(migrator.ddn_metadata_path.exists())

    def test_find_v2_table_files(self):
        """Test finding HasuraV2 table files."""
        migrator = PermissionMigrator(str(self.v2_dir), str(self.ddn_dir))
        table_files = migrator.find_v2_table_files()

        self.assertEqual(len(table_files), 1)
        self.assertEqual(table_files[0].name, "public_users.yaml")

    def test_extract_table_name(self):
        """Test extracting table name from file path."""
        migrator = PermissionMigrator(str(self.v2_dir), str(self.ddn_dir))
        table_file = self.v2_tables_dir / "public_users.yaml"

        table_name = migrator.extract_table_name(table_file)
        self.assertEqual(table_name, "users")

    def test_load_yaml_file(self):
        """Test loading YAML files."""
        migrator = PermissionMigrator(str(self.v2_dir), str(self.ddn_dir))
        table_file = self.v2_tables_dir / "public_users.yaml"

        config = migrator.load_yaml_file(table_file)
        self.assertIsNotNone(config)
        self.assertIn('table', config)
        self.assertIn('select_permissions', config)

    def test_load_hml_file(self):
        """Test loading HML files."""
        migrator = PermissionMigrator(str(self.v2_dir), str(self.ddn_dir))
        main_file = self.ddn_metadata_dir / "users.hml"

        documents = migrator.load_hml_file(main_file)
        self.assertIsNotNone(documents)
        self.assertGreater(len(documents), 0)
        self.assertEqual(documents[0]['kind'], 'ObjectType')

    def test_find_permission_section(self):
        """Test finding permission sections in HML documents."""
        migrator = PermissionMigrator(str(self.v2_dir), str(self.ddn_dir))
        main_file = self.ddn_metadata_dir / "users.hml"
        documents = migrator.load_hml_file(main_file)

        type_perm_idx = migrator.find_permission_section(documents, 'TypePermissions', 'typeName', 'users')
        self.assertIsNotNone(type_perm_idx)

        model_perm_idx = migrator.find_permission_section(documents, 'ModelPermissions', 'modelName', 'users')
        self.assertIsNotNone(model_perm_idx)

    def test_migrate_select_permissions(self):
        """Test migrating select permissions."""
        migrator = PermissionMigrator(str(self.v2_dir), str(self.ddn_dir))

        select_permissions = [
            {
                'role': 'user',
                'permission': {
                    'columns': ['id', 'name', 'email'],
                    'filter': {}
                }
            }
        ]

        result = migrator.migrate_select_permissions('users', select_permissions)
        self.assertTrue(result)

        # Verify the permissions were added
        main_file = self.ddn_metadata_dir / "users.hml"
        documents = migrator.load_hml_file(main_file)

        type_perm_idx = migrator.find_permission_section(documents, 'TypePermissions', 'typeName', 'users')
        self.assertIsNotNone(type_perm_idx)

        permissions = documents[type_perm_idx]['definition']['permissions']
        user_perm = next((p for p in permissions if p['role'] == 'user'), None)
        self.assertIsNotNone(user_perm)
        self.assertEqual(set(user_perm['output']['allowedFields']), {'id', 'name', 'email'})

    def test_migrate_insert_permissions(self):
        """Test migrating insert permissions."""
        migrator = PermissionMigrator(str(self.v2_dir), str(self.ddn_dir))

        insert_permissions = [
            {
                'role': 'admin',
                'permission': {
                    'columns': ['name', 'email'],
                    'check': {}
                }
            }
        ]

        result = migrator.migrate_insert_permissions('users', insert_permissions)
        self.assertTrue(result)

        # Verify the permissions were added
        insert_file = self.ddn_metadata_dir / "insert_users.hml"
        documents = migrator.load_hml_file(insert_file)

        cmd_perm_idx = migrator.find_permission_section(documents, 'CommandPermissions', 'commandName', 'insert_users')
        self.assertIsNotNone(cmd_perm_idx)

        permissions = documents[cmd_perm_idx]['definition']['permissions']
        admin_perm = next((p for p in permissions if p['role'] == 'admin'), None)
        self.assertIsNotNone(admin_perm)
        self.assertTrue(admin_perm['allowExecution'])

    def test_end_to_end_migration(self):
        """Test complete end-to-end migration."""
        migrator = PermissionMigrator(str(self.v2_dir), str(self.ddn_dir))

        # Run the migration
        result = migrator.migrate_all_permissions()
        self.assertTrue(result)

        # Validate that all permissions were migrated
        validator = MigrationValidator(str(self.v2_dir), str(self.ddn_dir))
        validation_results = validator.validate_all_migrations()

        # Should have no errors
        self.assertEqual(len(validation_results), 0, f"Validation errors: {validation_results}")

    def test_dry_run_mode(self):
        """Test dry run mode doesn't make changes."""
        migrator = PermissionMigrator(str(self.v2_dir), str(self.ddn_dir), dry_run=True)

        # Get original file content
        main_file = self.ddn_metadata_dir / "users.hml"
        with open(main_file, 'r') as f:
            original_content = f.read()

        # Run migration in dry run mode
        result = migrator.migrate_all_permissions()
        self.assertTrue(result)

        # Verify file wasn't changed
        with open(main_file, 'r') as f:
            new_content = f.read()

        self.assertEqual(original_content, new_content)

    def test_missing_ddn_file_handling(self):
        """Test handling of missing DDN files."""
        migrator = PermissionMigrator(str(self.v2_dir), str(self.ddn_dir))

        # Remove insert file
        insert_file = self.ddn_metadata_dir / "insert_users.hml"
        insert_file.unlink()

        # Try to migrate insert permissions
        insert_permissions = [{'role': 'admin', 'permission': {'columns': ['name'], 'check': {}}}]
        result = migrator.migrate_insert_permissions('users', insert_permissions)

        # Should fail gracefully
        self.assertFalse(result)


class TestMigrationValidator(unittest.TestCase):
    """Test cases for the migration validator."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.v2_dir = self.test_dir / "hasurav2"
        self.ddn_dir = self.test_dir / "hasuraDDN"

        # Create directory structure
        self.v2_tables_dir = self.v2_dir / "hasura-metadata" / "metadata" / "databases" / "testdb" / "tables"
        self.ddn_metadata_dir = self.ddn_dir / "app" / "metadata"

        self.v2_tables_dir.mkdir(parents=True)
        self.ddn_metadata_dir.mkdir(parents=True)

        # Create sample data
        self.create_sample_data()

    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)

    def create_sample_data(self):
        """Create sample data for validation tests."""
        # Create V2 table with permissions
        v2_config = {
            'table': {'name': 'products', 'schema': 'public'},
            'select_permissions': [
                {'role': 'user', 'permission': {'columns': ['id', 'name'], 'filter': {}}},
                {'role': 'admin', 'permission': {'columns': ['id', 'name', 'price'], 'filter': {}}}
            ],
            'insert_permissions': [
                {'role': 'admin', 'permission': {'columns': ['name', 'price'], 'check': {}}}
            ]
        }

        v2_file = self.v2_tables_dir / "public_products.yaml"
        with open(v2_file, 'w') as f:
            yaml.dump(v2_config, f)

        # Create DDN files with some permissions already migrated
        main_config = [
            {
                'kind': 'TypePermissions',
                'version': 'v1',
                'definition': {
                    'typeName': 'products',
                    'permissions': [
                        {'role': 'user', 'output': {'allowedFields': ['id', 'name']}},
                        # Missing admin role
                    ]
                }
            },
            {
                'kind': 'ModelPermissions',
                'version': 'v1',
                'definition': {
                    'modelName': 'products',
                    'permissions': [
                        {'role': 'user', 'select': {'filter': None, 'allowSubscriptions': True}},
                        {'role': 'admin', 'select': {'filter': None, 'allowSubscriptions': True}}
                    ]
                }
            }
        ]

        main_file = self.ddn_metadata_dir / "products.hml"
        with open(main_file, 'w') as f:
            for i, doc in enumerate(main_config):
                if i > 0:
                    f.write('\n---\n')
                else:
                    f.write('---\n')
                yaml.dump(doc, f)

        # Create insert file with missing permissions
        insert_config = [
            {
                'kind': 'CommandPermissions',
                'version': 'v1',
                'definition': {
                    'commandName': 'insert_products',
                    'permissions': []  # Missing admin role
                }
            }
        ]

        insert_file = self.ddn_metadata_dir / "insert_products.hml"
        with open(insert_file, 'w') as f:
            for i, doc in enumerate(insert_config):
                if i > 0:
                    f.write('\n---\n')
                else:
                    f.write('---\n')
                yaml.dump(doc, f)

    def test_validator_initialization(self):
        """Test validator initialization."""
        validator = MigrationValidator(str(self.v2_dir), str(self.ddn_dir))

        self.assertEqual(validator.hasura_v2_path, self.v2_dir)
        self.assertEqual(validator.hasura_ddn_path, self.ddn_dir)

    def test_validate_select_permissions_missing_role(self):
        """Test validation detects missing roles in select permissions."""
        validator = MigrationValidator(str(self.v2_dir), str(self.ddn_dir))

        v2_permissions = [
            {'role': 'user', 'permission': {'columns': ['id', 'name'], 'filter': {}}},
            {'role': 'admin', 'permission': {'columns': ['id', 'name', 'price'], 'filter': {}}}
        ]

        errors = validator.validate_select_permissions('products', v2_permissions)

        # Should detect missing admin role in TypePermissions
        self.assertGreater(len(errors), 0)
        self.assertTrue(any('admin' in error for error in errors))

    def test_validate_insert_permissions_missing_role(self):
        """Test validation detects missing roles in insert permissions."""
        validator = MigrationValidator(str(self.v2_dir), str(self.ddn_dir))

        v2_permissions = [
            {'role': 'admin', 'permission': {'columns': ['name', 'price'], 'check': {}}}
        ]

        errors = validator.validate_insert_permissions('products', v2_permissions)

        # Should detect missing admin role in CommandPermissions
        self.assertGreater(len(errors), 0)
        self.assertTrue(any('admin' in error for error in errors))

    def test_validate_all_migrations(self):
        """Test validating all migrations."""
        validator = MigrationValidator(str(self.v2_dir), str(self.ddn_dir))

        results = validator.validate_all_migrations()

        # Should find issues with products table
        self.assertIn('products', results)
        self.assertGreater(len(results['products']), 0)

    def test_generate_validation_report(self):
        """Test generating validation report."""
        validator = MigrationValidator(str(self.v2_dir), str(self.ddn_dir))

        report = validator.generate_validation_report()

        self.assertIn('migration_validation', report)
        self.assertIn('consistency_validation', report)
        self.assertIn('summary', report)

        summary = report['summary']
        self.assertIn('total_tables', summary)
        self.assertIn('successful_migrations', summary)
        self.assertIn('failed_migrations', summary)
        self.assertIn('overall_success', summary)

        # Should not be successful due to missing permissions
        self.assertFalse(summary['overall_success'])


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete migration and validation workflow."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.v2_dir = self.test_dir / "hasurav2"
        self.ddn_dir = self.test_dir / "hasuraDDN"

        # Create directory structure
        self.v2_tables_dir = self.v2_dir / "hasura-metadata" / "metadata" / "databases" / "testdb" / "tables"
        self.ddn_metadata_dir = self.ddn_dir / "app" / "metadata"

        self.v2_tables_dir.mkdir(parents=True)
        self.ddn_metadata_dir.mkdir(parents=True)

    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)

    def create_complete_test_scenario(self):
        """Create a complete test scenario with multiple tables and permissions."""
        # Create multiple V2 tables
        tables_config = {
            'users': {
                'table': {'name': 'users', 'schema': 'public'},
                'select_permissions': [
                    {'role': 'user', 'permission': {'columns': ['id', 'name'], 'filter': {}}},
                    {'role': 'admin', 'permission': {'columns': ['id', 'name', 'email'], 'filter': {}}}
                ],
                'insert_permissions': [
                    {'role': 'admin', 'permission': {'columns': ['name', 'email'], 'check': {}}}
                ],
                'update_permissions': [
                    {'role': 'admin', 'permission': {'columns': ['name', 'email'], 'filter': {}, 'check': {}}}
                ],
                'delete_permissions': [
                    {'role': 'admin', 'permission': {'filter': {}}}
                ]
            },
            'orders': {
                'table': {'name': 'orders', 'schema': 'public'},
                'select_permissions': [
                    {'role': 'user', 'permission': {'columns': ['id', 'status'], 'filter': {}}},
                    {'role': 'admin', 'permission': {'columns': ['id', 'status', 'total'], 'filter': {}}}
                ],
                'insert_permissions': [
                    {'role': 'user', 'permission': {'columns': ['status'], 'check': {}}},
                    {'role': 'admin', 'permission': {'columns': ['status', 'total'], 'check': {}}}
                ]
            }
        }

        # Create V2 files
        for table_name, config in tables_config.items():
            v2_file = self.v2_tables_dir / f"public_{table_name}.yaml"
            with open(v2_file, 'w') as f:
                yaml.dump(config, f)

        # Create corresponding DDN files
        for table_name in tables_config.keys():
            self.create_empty_ddn_files(table_name)

    def create_empty_ddn_files(self, table_name: str):
        """Create empty DDN files for a table."""
        # Main file
        main_config = [
            {'kind': 'TypePermissions', 'version': 'v1', 'definition': {'typeName': table_name, 'permissions': []}},
            {'kind': 'ModelPermissions', 'version': 'v1', 'definition': {'modelName': table_name, 'permissions': []}}
        ]

        main_file = self.ddn_metadata_dir / f"{table_name}.hml"
        with open(main_file, 'w') as f:
            for i, doc in enumerate(main_config):
                if i > 0:
                    f.write('\n---\n')
                else:
                    f.write('---\n')
                yaml.dump(doc, f)

        # Insert file
        insert_config = [
            {'kind': 'TypePermissions', 'version': 'v1', 'definition': {'typeName': f'insert_{table_name}_object', 'permissions': []}},
            {'kind': 'TypePermissions', 'version': 'v1', 'definition': {'typeName': f'insert_{table_name}_response', 'permissions': []}},
            {'kind': 'CommandPermissions', 'version': 'v1', 'definition': {'commandName': f'insert_{table_name}', 'permissions': []}}
        ]

        insert_file = self.ddn_metadata_dir / f"insert_{table_name}.hml"
        with open(insert_file, 'w') as f:
            for i, doc in enumerate(insert_config):
                if i > 0:
                    f.write('\n---\n')
                else:
                    f.write('---\n')
                yaml.dump(doc, f)

        # Update file
        update_config = [
            {'kind': 'TypePermissions', 'version': 'v1', 'definition': {'typeName': f'update_{table_name}_by_id_update_columns', 'permissions': []}},
            {'kind': 'TypePermissions', 'version': 'v1', 'definition': {'typeName': f'update_{table_name}_by_id_response', 'permissions': []}},
            {'kind': 'CommandPermissions', 'version': 'v1', 'definition': {'commandName': f'update_{table_name}_by_id', 'permissions': []}}
        ]

        update_file = self.ddn_metadata_dir / f"update_{table_name}_by_id.hml"
        with open(update_file, 'w') as f:
            for i, doc in enumerate(update_config):
                if i > 0:
                    f.write('\n---\n')
                else:
                    f.write('---\n')
                yaml.dump(doc, f)

        # Delete file
        delete_config = [
            {'kind': 'TypePermissions', 'version': 'v1', 'definition': {'typeName': f'delete_{table_name}_by_id_response', 'permissions': []}},
            {'kind': 'CommandPermissions', 'version': 'v1', 'definition': {'commandName': f'delete_{table_name}_by_id', 'permissions': []}}
        ]

        delete_file = self.ddn_metadata_dir / f"delete_{table_name}_by_id.hml"
        with open(delete_file, 'w') as f:
            for i, doc in enumerate(delete_config):
                if i > 0:
                    f.write('\n---\n')
                else:
                    f.write('---\n')
                yaml.dump(doc, f)

    def test_complete_migration_workflow(self):
        """Test complete migration and validation workflow."""
        self.create_complete_test_scenario()

        # Step 1: Run migration
        migrator = PermissionMigrator(str(self.v2_dir), str(self.ddn_dir))
        migration_result = migrator.migrate_all_permissions()
        self.assertTrue(migration_result, "Migration should succeed")

        # Step 2: Validate migration
        validator = MigrationValidator(str(self.v2_dir), str(self.ddn_dir))
        validation_report = validator.generate_validation_report()

        # Step 3: Check results
        self.assertEqual(len(validation_report['migration_validation']), 0,
                        f"Should have no migration errors: {validation_report['migration_validation']}")

        self.assertTrue(validation_report['summary']['overall_success'],
                       f"Overall migration should be successful. Report: {validation_report['summary']}")

        self.assertEqual(validation_report['summary']['total_tables'], 2)
        self.assertEqual(validation_report['summary']['successful_migrations'], 2)
        self.assertEqual(validation_report['summary']['failed_migrations'], 0)


if __name__ == '__main__':
    # Configure logging for tests
    logging.basicConfig(level=logging.WARNING)

    # Run tests
    unittest.main(verbosity=2)
