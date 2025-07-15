#!/usr/bin/env python3
"""
HasuraV2 to HasuraDDN Permission Migration Script

This script migrates permissions from HasuraV2 metadata format to HasuraDDN format.
It reads permissions from HasuraV2 table YAML files and updates corresponding
HasuraDDN HML files with the appropriate permission configurations.
"""

import os
import yaml
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
import argparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PermissionMigrator:
    def __init__(self, hasura_v2_path: str, hasura_ddn_path: str, dry_run: bool = False):
        self.hasura_v2_path = Path(hasura_v2_path)
        self.hasura_ddn_path = Path(hasura_ddn_path)
        self.v2_tables_path = self.hasura_v2_path / "hasura-metadata" / "metadata" / "databases"
        self.ddn_metadata_path = self.hasura_ddn_path / "app" / "metadata"
        self.dry_run = dry_run

        # Migration statistics
        self.migration_stats = {
            'tables_processed': 0,
            'tables_successful': 0,
            'tables_failed': 0,
            'permissions_by_type': {
                'select': {'total': 0, 'migrated': 0, 'roles': set()},
                'insert': {'total': 0, 'migrated': 0, 'roles': set()},
                'update': {'total': 0, 'migrated': 0, 'roles': set()},
                'delete': {'total': 0, 'migrated': 0, 'roles': set()}
            },
            'unique_roles': set(),
            'failed_tables': []
        }

        # Detailed dry run tracking
        self.dry_run_details = {
            'files_to_modify': {},  # file_path -> list of changes
            'permissions_by_table': {},  # table -> permission details
            'role_permissions': {},  # role -> list of permissions
            'ddn_file_changes': {}  # file -> change details
        }
        
    def find_v2_table_files(self) -> List[Path]:
        """Find all HasuraV2 table YAML files."""
        table_files = []
        for db_dir in self.v2_tables_path.iterdir():
            if db_dir.is_dir():
                tables_dir = db_dir / "tables"
                if tables_dir.exists():
                    for file in tables_dir.glob("public_*.yaml"):
                        table_files.append(file)
        return table_files
    
    def extract_table_name(self, file_path: Path) -> str:
        """Extract table name from HasuraV2 file path."""
        # Remove 'public_' prefix and '.yaml' suffix
        filename = file_path.stem
        return filename.replace('public_', '')

    def update_permission_stats(self, permission_type: str, permissions: List[Dict[str, Any]], success: bool):
        """Update migration statistics for a permission type."""
        stats = self.migration_stats['permissions_by_type'][permission_type]
        stats['total'] += len(permissions)

        if success:
            stats['migrated'] += len(permissions)

        # Track unique roles
        for perm in permissions:
            role = perm.get('role')
            if role:
                stats['roles'].add(role)
                self.migration_stats['unique_roles'].add(role)

    def print_migration_summary(self):
        """Print a comprehensive migration summary."""
        stats = self.migration_stats

        print("\n" + "="*80)
        print("📊 MIGRATION SUMMARY")
        print("="*80)

        # Table summary
        print(f"📋 Tables:")
        print(f"   • Total processed: {stats['tables_processed']}")
        print(f"   • Successfully migrated: {stats['tables_successful']}")
        print(f"   • Failed: {stats['tables_failed']}")
        if stats['failed_tables']:
            print(f"   • Failed tables: {', '.join(stats['failed_tables'])}")

        # Permission summary
        print(f"\n🔐 Permissions:")
        total_permissions = sum(p['total'] for p in stats['permissions_by_type'].values())
        total_migrated = sum(p['migrated'] for p in stats['permissions_by_type'].values())

        print(f"   • Total permissions: {total_permissions}")
        print(f"   • Successfully migrated: {total_migrated}")
        print(f"   • Migration rate: {(total_migrated/total_permissions*100):.1f}%" if total_permissions > 0 else "   • Migration rate: N/A")

        # Permission breakdown by type
        print(f"\n📝 Permission Breakdown:")
        for perm_type, data in stats['permissions_by_type'].items():
            if data['total'] > 0:
                rate = (data['migrated'] / data['total'] * 100) if data['total'] > 0 else 0
                print(f"   • {perm_type.capitalize()}: {data['migrated']}/{data['total']} ({rate:.1f}%) - Roles: {len(data['roles'])}")

        # Role summary
        print(f"\n👥 Roles:")
        print(f"   • Total unique roles: {len(stats['unique_roles'])}")
        if stats['unique_roles']:
            roles_list = sorted(list(stats['unique_roles']))
            print(f"   • Roles migrated: {', '.join(roles_list)}")

        # Success indicator
        overall_success = stats['tables_failed'] == 0 and total_migrated == total_permissions
        if overall_success:
            print(f"\n🎉 MIGRATION SUCCESSFUL!")
            print(f"   All {stats['tables_successful']} tables and {total_migrated} permissions migrated successfully!")
        else:
            print(f"\n⚠️  MIGRATION COMPLETED WITH ISSUES")
            if stats['tables_failed'] > 0:
                print(f"   • {stats['tables_failed']} tables failed to migrate")
            if total_migrated < total_permissions:
                print(f"   • {total_permissions - total_migrated} permissions failed to migrate")

        print("="*80)

    def track_dry_run_change(self, file_path: Path, change_type: str, target: str, role: str, details: Dict[str, Any] = None):
        """Track detailed changes for dry run mode."""
        if not self.dry_run:
            return

        file_key = str(file_path)
        if file_key not in self.dry_run_details['files_to_modify']:
            self.dry_run_details['files_to_modify'][file_key] = []

        change_info = {
            'type': change_type,
            'target': target,
            'role': role,
            'details': details or {}
        }

        self.dry_run_details['files_to_modify'][file_key].append(change_info)

        # Track by role
        if role not in self.dry_run_details['role_permissions']:
            self.dry_run_details['role_permissions'][role] = []

        self.dry_run_details['role_permissions'][role].append({
            'file': file_key,
            'type': change_type,
            'target': target,
            'details': details or {}
        })

    def print_detailed_dry_run_summary(self):
        """Print detailed dry run summary showing exactly what will be changed."""
        if not self.dry_run:
            return

        print("\n" + "="*80)
        print("🔍 DETAILED DRY RUN ANALYSIS")
        print("="*80)

        # Files that will be modified
        print(f"📁 Files to be Modified: {len(self.dry_run_details['files_to_modify'])}")
        for file_path, changes in self.dry_run_details['files_to_modify'].items():
            file_name = Path(file_path).name
            print(f"\n  📄 {file_name}")
            print(f"     Path: {file_path}")
            print(f"     Changes: {len(changes)}")

            # Group changes by type
            changes_by_type = {}
            for change in changes:
                change_type = change['type']
                if change_type not in changes_by_type:
                    changes_by_type[change_type] = []
                changes_by_type[change_type].append(change)

            for change_type, type_changes in changes_by_type.items():
                print(f"     • {change_type}: {len(type_changes)} changes")
                for change in type_changes[:3]:  # Show first 3 changes
                    role = change['role']
                    target = change['target']
                    print(f"       - Role '{role}' → {target}")
                if len(type_changes) > 3:
                    print(f"       ... and {len(type_changes) - 3} more")

        # Permissions by role
        print(f"\n👥 Permissions by Role:")
        for role, permissions in self.dry_run_details['role_permissions'].items():
            print(f"\n  🔑 Role: {role}")
            print(f"     Total permissions: {len(permissions)}")

            # Group by permission type
            perm_by_type = {}
            for perm in permissions:
                perm_type = perm['type']
                if perm_type not in perm_by_type:
                    perm_by_type[perm_type] = []
                perm_by_type[perm_type].append(perm)

            for perm_type, type_perms in perm_by_type.items():
                files_affected = set(perm['file'] for perm in type_perms)
                print(f"     • {perm_type}: {len(type_perms)} permissions across {len(files_affected)} files")

        # Table-level analysis
        print(f"\n📊 Table-Level Analysis:")
        table_analysis = {}
        for file_path, changes in self.dry_run_details['files_to_modify'].items():
            # Extract table name from file path
            file_name = Path(file_path).name
            if file_name.endswith('.hml'):
                if file_name.startswith('insert_'):
                    table_name = file_name.replace('insert_', '').replace('.hml', '')
                    operation = 'insert'
                elif file_name.startswith('update_'):
                    table_name = file_name.replace('update_', '').replace('_by_id.hml', '')
                    operation = 'update'
                elif file_name.startswith('delete_'):
                    table_name = file_name.replace('delete_', '').replace('_by_id.hml', '')
                    operation = 'delete'
                else:
                    table_name = file_name.replace('.hml', '')
                    operation = 'select'

                if table_name not in table_analysis:
                    table_analysis[table_name] = {'operations': set(), 'roles': set(), 'total_changes': 0}

                table_analysis[table_name]['operations'].add(operation)
                table_analysis[table_name]['total_changes'] += len(changes)
                for change in changes:
                    table_analysis[table_name]['roles'].add(change['role'])

        for table_name, analysis in table_analysis.items():
            operations = sorted(list(analysis['operations']))
            roles = sorted(list(analysis['roles']))
            print(f"\n  📋 Table: {table_name}")
            print(f"     Operations: {', '.join(operations)}")
            print(f"     Roles affected: {', '.join(roles)}")
            print(f"     Total changes: {analysis['total_changes']}")

        print("="*80)
    
    def load_yaml_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Load and parse a YAML file."""
        try:
            with open(file_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading {file_path}: {e}")
            return None
    
    def load_hml_file(self, file_path: Path) -> Optional[List[Dict[str, Any]]]:
        """Load and parse an HML file (YAML with multiple documents)."""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                # Split by document separator and parse each document
                documents = []
                for doc in yaml.safe_load_all(content):
                    if doc:
                        documents.append(doc)
                return documents
        except Exception as e:
            logger.error(f"Error loading {file_path}: {e}")
            return None
    
    def save_hml_file(self, file_path: Path, documents: List[Dict[str, Any]]) -> bool:
        """Save documents to an HML file."""
        if self.dry_run:
            logger.info(f"[DRY RUN] Would save changes to {file_path}")
            return True

        try:
            with open(file_path, 'w') as f:
                for i, doc in enumerate(documents):
                    if i > 0:
                        f.write('\n---\n')
                    else:
                        f.write('---\n')
                    yaml.dump(doc, f, default_flow_style=False, sort_keys=False)
                f.write('\n')
            return True
        except Exception as e:
            logger.error(f"Error saving {file_path}: {e}")
            return False
    
    def find_permission_section(self, documents: List[Dict[str, Any]], kind: str, 
                               name_field: str, name_value: str) -> Optional[int]:
        """Find the index of a specific permission section in HML documents."""
        for i, doc in enumerate(documents):
            if (doc.get('kind') == kind and 
                doc.get('definition', {}).get(name_field) == name_value):
                return i
        return None
    
    def add_role_to_type_permissions(self, documents: List[Dict[str, Any]],
                                   type_name: str, role: str, allowed_fields: List[str],
                                   optional: bool = False) -> bool:
        """Add a role to TypePermissions section."""
        idx = self.find_permission_section(documents, 'TypePermissions', 'typeName', type_name)
        if idx is None:
            if optional:
                logger.debug(f"TypePermissions for {type_name} not found (optional)")
                return True
            else:
                logger.warning(f"TypePermissions for {type_name} not found")
                return False
        
        permissions = documents[idx]['definition'].setdefault('permissions', [])
        
        # Check if role already exists
        for perm in permissions:
            if perm.get('role') == role:
                # Update existing role
                if not self.dry_run:
                    perm['output'] = {'allowedFields': allowed_fields}
                else:
                    # Track dry run change
                    self.track_dry_run_change(
                        Path("unknown"),  # Will be set by caller
                        'TypePermissions',
                        type_name,
                        role,
                        {'action': 'update', 'allowedFields': allowed_fields}
                    )
                logger.info(f"{'[DRY RUN] Would update' if self.dry_run else 'Updated'} TypePermissions for {type_name}, role: {role}")
                return True

        # Add new role
        if not self.dry_run:
            permissions.append({
                'role': role,
                'output': {'allowedFields': allowed_fields}
            })
        else:
            # Track dry run change
            self.track_dry_run_change(
                Path("unknown"),  # Will be set by caller
                'TypePermissions',
                type_name,
                role,
                {'action': 'add', 'allowedFields': allowed_fields}
            )
        logger.info(f"{'[DRY RUN] Would add' if self.dry_run else 'Added'} TypePermissions for {type_name}, role: {role}")
        return True
    
    def add_role_to_model_permissions(self, documents: List[Dict[str, Any]], 
                                    model_name: str, role: str, filter_expr: Dict[str, Any]) -> bool:
        """Add a role to ModelPermissions section."""
        idx = self.find_permission_section(documents, 'ModelPermissions', 'modelName', model_name)
        if idx is None:
            logger.warning(f"ModelPermissions for {model_name} not found")
            return False
        
        permissions = documents[idx]['definition'].setdefault('permissions', [])
        
        # Check if role already exists
        for perm in permissions:
            if perm.get('role') == role:
                # Update existing role
                if not self.dry_run:
                    perm['select'] = {
                        'filter': filter_expr if filter_expr else None,
                        'allowSubscriptions': True
                    }
                else:
                    # Track dry run change
                    self.track_dry_run_change(
                        Path("unknown"),  # Will be set by caller
                        'ModelPermissions',
                        model_name,
                        role,
                        {'action': 'update', 'filter': filter_expr, 'allowSubscriptions': True}
                    )
                logger.info(f"{'[DRY RUN] Would update' if self.dry_run else 'Updated'} ModelPermissions for {model_name}, role: {role}")
                return True

        # Add new role
        if not self.dry_run:
            permissions.append({
                'role': role,
                'select': {
                    'filter': filter_expr if filter_expr else None,
                    'allowSubscriptions': True
                }
            })
        else:
            # Track dry run change
            self.track_dry_run_change(
                Path("unknown"),  # Will be set by caller
                'ModelPermissions',
                model_name,
                role,
                {'action': 'add', 'filter': filter_expr, 'allowSubscriptions': True}
            )
        logger.info(f"{'[DRY RUN] Would add' if self.dry_run else 'Added'} ModelPermissions for {model_name}, role: {role}")
        return True
    
    def add_role_to_command_permissions(self, documents: List[Dict[str, Any]], 
                                      command_name: str, role: str) -> bool:
        """Add a role to CommandPermissions section."""
        idx = self.find_permission_section(documents, 'CommandPermissions', 'commandName', command_name)
        if idx is None:
            logger.warning(f"CommandPermissions for {command_name} not found")
            return False
        
        permissions = documents[idx]['definition'].setdefault('permissions', [])
        
        # Check if role already exists
        for perm in permissions:
            if perm.get('role') == role:
                if self.dry_run:
                    # Track dry run change
                    self.track_dry_run_change(
                        Path("unknown"),  # Will be set by caller
                        'CommandPermissions',
                        command_name,
                        role,
                        {'action': 'exists', 'allowExecution': True}
                    )
                logger.info(f"{'[DRY RUN] ' if self.dry_run else ''}Role {role} already exists in CommandPermissions for {command_name}")
                return True

        # Add new role
        if not self.dry_run:
            permissions.append({
                'role': role,
                'allowExecution': True
            })
        else:
            # Track dry run change
            self.track_dry_run_change(
                Path("unknown"),  # Will be set by caller
                'CommandPermissions',
                command_name,
                role,
                {'action': 'add', 'allowExecution': True}
            )
        logger.info(f"{'[DRY RUN] Would add' if self.dry_run else 'Added'} CommandPermissions for {command_name}, role: {role}")
        return True

    def migrate_select_permissions(self, table_name: str, permissions: List[Dict[str, Any]]) -> bool:
        """Migrate select permissions to main table HML file."""
        main_file = self.ddn_metadata_path / f"{table_name}.hml"
        if not main_file.exists():
            logger.warning(f"Main file {main_file} not found")
            return False

        documents = self.load_hml_file(main_file)
        if not documents:
            return False

        success = True
        for perm in permissions:
            role = perm.get('role')
            columns = perm.get('permission', {}).get('columns', [])
            filter_expr = perm.get('permission', {}).get('filter', {})

            # Track detailed permission info for dry run
            if self.dry_run:
                self.track_dry_run_change(
                    main_file,
                    'SELECT_PERMISSION',
                    f"{table_name} (TypePermissions + ModelPermissions)",
                    role,
                    {'columns': columns, 'filter': filter_expr}
                )

            # Add to TypePermissions
            if not self.add_role_to_type_permissions(documents, table_name, role, columns):
                success = False

            # Add to ModelPermissions
            if not self.add_role_to_model_permissions(documents, table_name, role, filter_expr):
                success = False

        result = self.save_hml_file(main_file, documents) and success
        self.update_permission_stats('select', permissions, result)
        return result

    def migrate_insert_permissions(self, table_name: str, permissions: List[Dict[str, Any]]) -> bool:
        """Migrate insert permissions to insert HML file."""
        insert_file = self.ddn_metadata_path / f"insert_{table_name}.hml"
        if not insert_file.exists():
            logger.warning(f"Insert file {insert_file} not found")
            return False

        documents = self.load_hml_file(insert_file)
        if not documents:
            return False

        success = True
        for perm in permissions:
            role = perm.get('role')
            columns = perm.get('permission', {}).get('columns', [])

            # Track detailed permission info for dry run
            if self.dry_run:
                self.track_dry_run_change(
                    insert_file,
                    'INSERT_PERMISSION',
                    f"insert_{table_name} (CommandPermissions + TypePermissions)",
                    role,
                    {'columns': columns, 'targets': ['object', 'response', 'command']}
                )

            # Add to TypePermissions for insert object
            object_type_name = f"insert_{table_name}_object"
            if not self.add_role_to_type_permissions(documents, object_type_name, role, columns):
                success = False

            # Add to TypePermissions for response
            response_type_name = f"insert_{table_name}_response"
            response_fields = ['affected_rows', 'returning']
            if not self.add_role_to_type_permissions(documents, response_type_name, role, response_fields):
                success = False

            # Add to CommandPermissions
            command_name = f"insert_{table_name}"
            if not self.add_role_to_command_permissions(documents, command_name, role):
                success = False

        result = self.save_hml_file(insert_file, documents) and success
        self.update_permission_stats('insert', permissions, result)
        return result

    def migrate_update_permissions(self, table_name: str, permissions: List[Dict[str, Any]]) -> bool:
        """Migrate update permissions to update HML file."""
        update_file = self.ddn_metadata_path / f"update_{table_name}_by_id.hml"
        if not update_file.exists():
            logger.warning(f"Update file {update_file} not found")
            return False

        documents = self.load_hml_file(update_file)
        if not documents:
            return False

        success = True
        for perm in permissions:
            role = perm.get('role')
            columns = perm.get('permission', {}).get('columns', [])

            # Track detailed permission info for dry run
            if self.dry_run:
                self.track_dry_run_change(
                    update_file,
                    'UPDATE_PERMISSION',
                    f"update_{table_name}_by_id (CommandPermissions + TypePermissions)",
                    role,
                    {'columns': columns, 'targets': ['column_types', 'update_columns', 'response', 'command']}
                )

            # Try to add to TypePermissions for each column update type (optional)
            # These may not exist in all DDN files, so we don't fail if they're missing
            for column in columns:
                column_type_name = f"update_column_{table_name}_{column}"
                self.add_role_to_type_permissions(documents, column_type_name, role, ['_set'], optional=True)

            # Add to TypePermissions for update columns object (this should always exist)
            update_columns_type = f"update_{table_name}_by_id_update_columns"
            if not self.add_role_to_type_permissions(documents, update_columns_type, role, columns):
                success = False

            # Add to TypePermissions for response
            response_type_name = f"update_{table_name}_by_id_response"
            response_fields = ['affected_rows', 'returning']
            if not self.add_role_to_type_permissions(documents, response_type_name, role, response_fields):
                success = False

            # Add to CommandPermissions
            command_name = f"update_{table_name}_by_id"
            if not self.add_role_to_command_permissions(documents, command_name, role):
                success = False

        result = self.save_hml_file(update_file, documents) and success
        self.update_permission_stats('update', permissions, result)
        return result

    def migrate_delete_permissions(self, table_name: str, permissions: List[Dict[str, Any]]) -> bool:
        """Migrate delete permissions to delete HML file."""
        delete_file = self.ddn_metadata_path / f"delete_{table_name}_by_id.hml"
        if not delete_file.exists():
            logger.warning(f"Delete file {delete_file} not found")
            return False

        documents = self.load_hml_file(delete_file)
        if not documents:
            return False

        success = True
        for perm in permissions:
            role = perm.get('role')

            # Track detailed permission info for dry run
            if self.dry_run:
                filter_expr = perm.get('permission', {}).get('filter', {})
                self.track_dry_run_change(
                    delete_file,
                    'DELETE_PERMISSION',
                    f"delete_{table_name}_by_id (CommandPermissions + TypePermissions)",
                    role,
                    {'filter': filter_expr, 'targets': ['response', 'command']}
                )

            # Add to TypePermissions for response
            response_type_name = f"delete_{table_name}_by_id_response"
            response_fields = ['affected_rows', 'returning']
            if not self.add_role_to_type_permissions(documents, response_type_name, role, response_fields):
                success = False

            # Add to CommandPermissions
            command_name = f"delete_{table_name}_by_id"
            if not self.add_role_to_command_permissions(documents, command_name, role):
                success = False

        result = self.save_hml_file(delete_file, documents) and success
        self.update_permission_stats('delete', permissions, result)
        return result

    def migrate_table_permissions(self, table_file: Path) -> bool:
        """Migrate all permissions for a single table."""
        table_name = self.extract_table_name(table_file)
        logger.info(f"Migrating permissions for table: {table_name}")

        # Update table statistics
        self.migration_stats['tables_processed'] += 1

        # Load HasuraV2 table configuration
        v2_config = self.load_yaml_file(table_file)
        if not v2_config:
            self.migration_stats['tables_failed'] += 1
            self.migration_stats['failed_tables'].append(table_name)
            return False

        success = True

        # Migrate select permissions
        if 'select_permissions' in v2_config:
            logger.info(f"Migrating {len(v2_config['select_permissions'])} select permissions")
            if not self.migrate_select_permissions(table_name, v2_config['select_permissions']):
                success = False

        # Migrate insert permissions
        if 'insert_permissions' in v2_config:
            logger.info(f"Migrating {len(v2_config['insert_permissions'])} insert permissions")
            if not self.migrate_insert_permissions(table_name, v2_config['insert_permissions']):
                success = False

        # Migrate update permissions
        if 'update_permissions' in v2_config:
            logger.info(f"Migrating {len(v2_config['update_permissions'])} update permissions")
            if not self.migrate_update_permissions(table_name, v2_config['update_permissions']):
                success = False

        # Migrate delete permissions
        if 'delete_permissions' in v2_config:
            logger.info(f"Migrating {len(v2_config['delete_permissions'])} delete permissions")
            if not self.migrate_delete_permissions(table_name, v2_config['delete_permissions']):
                success = False

        # Update success/failure statistics
        if success:
            self.migration_stats['tables_successful'] += 1
        else:
            self.migration_stats['tables_failed'] += 1
            self.migration_stats['failed_tables'].append(table_name)

        return success

    def migrate_all_permissions(self) -> bool:
        """Migrate permissions for all tables."""
        logger.info("Starting permission migration from HasuraV2 to HasuraDDN")

        # Validate paths
        if not self.v2_tables_path.exists():
            logger.error(f"HasuraV2 tables path not found: {self.v2_tables_path}")
            return False

        if not self.ddn_metadata_path.exists():
            logger.error(f"HasuraDDN metadata path not found: {self.ddn_metadata_path}")
            return False

        # Find all table files
        table_files = self.find_v2_table_files()
        if not table_files:
            logger.warning("No HasuraV2 table files found")
            return False

        logger.info(f"Found {len(table_files)} table files to migrate")

        success_count = 0
        total_count = len(table_files)

        for table_file in table_files:
            try:
                if self.migrate_table_permissions(table_file):
                    success_count += 1
                    logger.info(f"✓ Successfully migrated {table_file.name}")
                else:
                    logger.error(f"✗ Failed to migrate {table_file.name}")
            except Exception as e:
                logger.error(f"✗ Error migrating {table_file.name}: {e}")

        logger.info(f"Migration completed: {success_count}/{total_count} tables migrated successfully")

        # Print detailed dry run analysis if in dry run mode
        if self.dry_run:
            self.print_detailed_dry_run_summary()

        # Print comprehensive summary
        self.print_migration_summary()

        return success_count == total_count


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Migrate permissions from HasuraV2 to HasuraDDN",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Migrate permissions using default paths
  python permission_migration.py

  # Migrate permissions with custom paths
  python permission_migration.py --v2-path ./hasurav2 --ddn-path ./hasuraDDN

  # Enable debug logging
  python permission_migration.py --verbose
        """
    )

    parser.add_argument(
        '--v2-path',
        default='./hasurav2',
        help='Path to HasuraV2 directory (default: ./hasurav2)'
    )

    parser.add_argument(
        '--ddn-path',
        default='./hasuraDDN',
        help='Path to HasuraDDN directory (default: ./hasuraDDN)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be migrated without making changes'
    )

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create migrator instance
    migrator = PermissionMigrator(args.v2_path, args.ddn_path, dry_run=args.dry_run)

    if args.dry_run:
        logger.info("DRY RUN MODE - No changes will be made")

    # Run migration
    success = migrator.migrate_all_permissions()

    if success:
        logger.info("🎉 All permissions migrated successfully!")
        exit(0)
    else:
        logger.error("❌ Some permissions failed to migrate. Check the logs above.")
        exit(1)


if __name__ == "__main__":
    main()
