#!/usr/bin/env python3
"""
Migration Validation Rules for HasuraV2 to HasuraDDN Permission Migration

This module contains validation rules to verify that the migration was successful
and that the permissions were correctly transferred from HasuraV2 to HasuraDDN.
"""

import os
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set
import logging

logger = logging.getLogger(__name__)

class MigrationValidator:
    """Validates that HasuraV2 permissions were correctly migrated to HasuraDDN."""
    
    def __init__(self, hasura_v2_path: str, hasura_ddn_path: str):
        self.hasura_v2_path = Path(hasura_v2_path)
        self.hasura_ddn_path = Path(hasura_ddn_path)
        self.v2_tables_path = self.hasura_v2_path / "hasura-metadata" / "metadata" / "databases"
        self.ddn_metadata_path = self.hasura_ddn_path / "app" / "metadata"
        
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
                documents = []
                for doc in yaml.safe_load_all(content):
                    if doc:
                        documents.append(doc)
                return documents
        except Exception as e:
            logger.error(f"Error loading {file_path}: {e}")
            return None
    
    def extract_table_name(self, file_path: Path) -> str:
        """Extract table name from HasuraV2 file path."""
        filename = file_path.stem
        return filename.replace('public_', '')
    
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
    
    def find_permission_section(self, documents: List[Dict[str, Any]], kind: str, 
                               name_field: str, name_value: str) -> Optional[Dict[str, Any]]:
        """Find a specific permission section in HML documents."""
        for doc in documents:
            if (doc.get('kind') == kind and 
                doc.get('definition', {}).get(name_field) == name_value):
                return doc.get('definition', {})
        return None
    
    def get_roles_from_permissions(self, permissions: List[Dict[str, Any]]) -> Set[str]:
        """Extract role names from a permissions list."""
        return {perm.get('role') for perm in permissions if perm.get('role')}
    
    def validate_select_permissions(self, table_name: str, v2_permissions: List[Dict[str, Any]]) -> List[str]:
        """Validate that select permissions were correctly migrated."""
        errors = []
        main_file = self.ddn_metadata_path / f"{table_name}.hml"
        
        if not main_file.exists():
            errors.append(f"Main DDN file {main_file} not found")
            return errors
        
        documents = self.load_hml_file(main_file)
        if not documents:
            errors.append(f"Failed to load {main_file}")
            return errors
        
        # Check TypePermissions
        type_permissions = self.find_permission_section(documents, 'TypePermissions', 'typeName', table_name)
        if not type_permissions:
            errors.append(f"TypePermissions for {table_name} not found")
        else:
            ddn_roles = self.get_roles_from_permissions(type_permissions.get('permissions', []))
            v2_roles = self.get_roles_from_permissions(v2_permissions)
            
            missing_roles = v2_roles - ddn_roles
            if missing_roles:
                errors.append(f"Missing roles in TypePermissions for {table_name}: {missing_roles}")
        
        # Check ModelPermissions
        model_permissions = self.find_permission_section(documents, 'ModelPermissions', 'modelName', table_name)
        if not model_permissions:
            errors.append(f"ModelPermissions for {table_name} not found")
        else:
            ddn_roles = self.get_roles_from_permissions(model_permissions.get('permissions', []))
            v2_roles = self.get_roles_from_permissions(v2_permissions)
            
            missing_roles = v2_roles - ddn_roles
            if missing_roles:
                errors.append(f"Missing roles in ModelPermissions for {table_name}: {missing_roles}")
        
        return errors
    
    def validate_insert_permissions(self, table_name: str, v2_permissions: List[Dict[str, Any]]) -> List[str]:
        """Validate that insert permissions were correctly migrated."""
        errors = []
        insert_file = self.ddn_metadata_path / f"insert_{table_name}.hml"
        
        if not insert_file.exists():
            errors.append(f"Insert DDN file {insert_file} not found")
            return errors
        
        documents = self.load_hml_file(insert_file)
        if not documents:
            errors.append(f"Failed to load {insert_file}")
            return errors
        
        v2_roles = self.get_roles_from_permissions(v2_permissions)
        
        # Check CommandPermissions
        command_permissions = self.find_permission_section(documents, 'CommandPermissions', 'commandName', f"insert_{table_name}")
        if not command_permissions:
            errors.append(f"CommandPermissions for insert_{table_name} not found")
        else:
            ddn_roles = self.get_roles_from_permissions(command_permissions.get('permissions', []))
            missing_roles = v2_roles - ddn_roles
            if missing_roles:
                errors.append(f"Missing roles in CommandPermissions for insert_{table_name}: {missing_roles}")
        
        # Check TypePermissions for insert object
        object_type_permissions = self.find_permission_section(documents, 'TypePermissions', 'typeName', f"insert_{table_name}_object")
        if object_type_permissions:
            ddn_roles = self.get_roles_from_permissions(object_type_permissions.get('permissions', []))
            missing_roles = v2_roles - ddn_roles
            if missing_roles:
                errors.append(f"Missing roles in TypePermissions for insert_{table_name}_object: {missing_roles}")
        
        return errors
    
    def validate_update_permissions(self, table_name: str, v2_permissions: List[Dict[str, Any]]) -> List[str]:
        """Validate that update permissions were correctly migrated."""
        errors = []
        update_file = self.ddn_metadata_path / f"update_{table_name}_by_id.hml"
        
        if not update_file.exists():
            errors.append(f"Update DDN file {update_file} not found")
            return errors
        
        documents = self.load_hml_file(update_file)
        if not documents:
            errors.append(f"Failed to load {update_file}")
            return errors
        
        v2_roles = self.get_roles_from_permissions(v2_permissions)
        
        # Check CommandPermissions
        command_permissions = self.find_permission_section(documents, 'CommandPermissions', 'commandName', f"update_{table_name}_by_id")
        if not command_permissions:
            errors.append(f"CommandPermissions for update_{table_name}_by_id not found")
        else:
            ddn_roles = self.get_roles_from_permissions(command_permissions.get('permissions', []))
            missing_roles = v2_roles - ddn_roles
            if missing_roles:
                errors.append(f"Missing roles in CommandPermissions for update_{table_name}_by_id: {missing_roles}")
        
        # Check TypePermissions for update columns
        update_columns_permissions = self.find_permission_section(documents, 'TypePermissions', 'typeName', f"update_{table_name}_by_id_update_columns")
        if update_columns_permissions:
            ddn_roles = self.get_roles_from_permissions(update_columns_permissions.get('permissions', []))
            missing_roles = v2_roles - ddn_roles
            if missing_roles:
                errors.append(f"Missing roles in TypePermissions for update_{table_name}_by_id_update_columns: {missing_roles}")
        
        return errors
    
    def validate_delete_permissions(self, table_name: str, v2_permissions: List[Dict[str, Any]]) -> List[str]:
        """Validate that delete permissions were correctly migrated."""
        errors = []
        delete_file = self.ddn_metadata_path / f"delete_{table_name}_by_id.hml"
        
        if not delete_file.exists():
            errors.append(f"Delete DDN file {delete_file} not found")
            return errors
        
        documents = self.load_hml_file(delete_file)
        if not documents:
            errors.append(f"Failed to load {delete_file}")
            return errors
        
        v2_roles = self.get_roles_from_permissions(v2_permissions)
        
        # Check CommandPermissions
        command_permissions = self.find_permission_section(documents, 'CommandPermissions', 'commandName', f"delete_{table_name}_by_id")
        if not command_permissions:
            errors.append(f"CommandPermissions for delete_{table_name}_by_id not found")
        else:
            ddn_roles = self.get_roles_from_permissions(command_permissions.get('permissions', []))
            missing_roles = v2_roles - ddn_roles
            if missing_roles:
                errors.append(f"Missing roles in CommandPermissions for delete_{table_name}_by_id: {missing_roles}")
        
        return errors

    def validate_table_migration(self, table_file: Path) -> Tuple[str, List[str]]:
        """Validate migration for a single table."""
        table_name = self.extract_table_name(table_file)
        all_errors = []

        # Load HasuraV2 table configuration
        v2_config = self.load_yaml_file(table_file)
        if not v2_config:
            return table_name, [f"Failed to load HasuraV2 config from {table_file}"]

        # Validate select permissions
        if 'select_permissions' in v2_config:
            errors = self.validate_select_permissions(table_name, v2_config['select_permissions'])
            all_errors.extend(errors)

        # Validate insert permissions
        if 'insert_permissions' in v2_config:
            errors = self.validate_insert_permissions(table_name, v2_config['insert_permissions'])
            all_errors.extend(errors)

        # Validate update permissions
        if 'update_permissions' in v2_config:
            errors = self.validate_update_permissions(table_name, v2_config['update_permissions'])
            all_errors.extend(errors)

        # Validate delete permissions
        if 'delete_permissions' in v2_config:
            errors = self.validate_delete_permissions(table_name, v2_config['delete_permissions'])
            all_errors.extend(errors)

        return table_name, all_errors

    def validate_all_migrations(self) -> Dict[str, List[str]]:
        """Validate all table migrations."""
        logger.info("Starting migration validation")

        # Validate paths
        if not self.v2_tables_path.exists():
            return {"validation_error": [f"HasuraV2 tables path not found: {self.v2_tables_path}"]}

        if not self.ddn_metadata_path.exists():
            return {"validation_error": [f"HasuraDDN metadata path not found: {self.ddn_metadata_path}"]}

        # Find all table files
        table_files = self.find_v2_table_files()
        if not table_files:
            return {"validation_error": ["No HasuraV2 table files found"]}

        logger.info(f"Validating {len(table_files)} table migrations")

        results = {}
        for table_file in table_files:
            table_name, errors = self.validate_table_migration(table_file)
            if errors:
                results[table_name] = errors

        return results

    def validate_column_permissions(self, table_name: str, v2_columns: List[str],
                                  ddn_permissions: Dict[str, Any], permission_type: str) -> List[str]:
        """Validate that column permissions match between V2 and DDN."""
        errors = []

        if not ddn_permissions or 'permissions' not in ddn_permissions:
            return errors

        for perm in ddn_permissions['permissions']:
            if 'output' in perm and 'allowedFields' in perm['output']:
                ddn_columns = set(perm['output']['allowedFields'])
                v2_columns_set = set(v2_columns)

                # Check if all V2 columns are present in DDN
                missing_columns = v2_columns_set - ddn_columns
                if missing_columns:
                    role = perm.get('role', 'unknown')
                    errors.append(f"Missing columns in {permission_type} for role {role} in {table_name}: {missing_columns}")

        return errors

    def validate_column_permissions_for_role(self, table_name: str, v2_role: str, v2_columns: List[str],
                                           ddn_permissions: Dict[str, Any], permission_type: str) -> List[str]:
        """Validate that column permissions match between V2 and DDN for a specific role."""
        errors = []

        if not ddn_permissions or 'permissions' not in ddn_permissions:
            return errors

        # Find the matching role in DDN permissions
        ddn_role_perm = None
        for perm in ddn_permissions['permissions']:
            if perm.get('role') == v2_role:
                ddn_role_perm = perm
                break

        if not ddn_role_perm:
            errors.append(f"Role {v2_role} not found in DDN {permission_type} permissions for {table_name}")
            return errors

        if 'output' in ddn_role_perm and 'allowedFields' in ddn_role_perm['output']:
            ddn_columns = set(ddn_role_perm['output']['allowedFields'])
            v2_columns_set = set(v2_columns)

            # Check if all V2 columns are present in DDN for this specific role
            missing_columns = v2_columns_set - ddn_columns
            if missing_columns:
                errors.append(f"Missing columns in {permission_type} for role {v2_role} in {table_name}: {missing_columns}")

        return errors

    def validate_permission_consistency(self) -> Dict[str, List[str]]:
        """Validate consistency between HasuraV2 and HasuraDDN permissions."""
        logger.info("Validating permission consistency")

        table_files = self.find_v2_table_files()
        results = {}

        for table_file in table_files:
            table_name = self.extract_table_name(table_file)
            errors = []

            v2_config = self.load_yaml_file(table_file)
            if not v2_config:
                continue

            # Validate select permission columns
            if 'select_permissions' in v2_config:
                main_file = self.ddn_metadata_path / f"{table_name}.hml"
                if main_file.exists():
                    documents = self.load_hml_file(main_file)
                    if documents:
                        type_permissions = self.find_permission_section(documents, 'TypePermissions', 'typeName', table_name)

                        for v2_perm in v2_config['select_permissions']:
                            v2_role = v2_perm.get('role')
                            v2_columns = v2_perm.get('permission', {}).get('columns', [])
                            column_errors = self.validate_column_permissions_for_role(table_name, v2_role, v2_columns, type_permissions, 'select')
                            errors.extend(column_errors)

            if errors:
                results[table_name] = errors

        return results

    def generate_validation_report(self) -> Dict[str, Any]:
        """Generate a comprehensive validation report."""
        logger.info("Generating validation report")

        report = {
            'timestamp': str(Path().cwd()),
            'migration_validation': self.validate_all_migrations(),
            'consistency_validation': self.validate_permission_consistency(),
            'summary': {}
        }

        # Generate summary
        migration_errors = report['migration_validation']
        consistency_errors = report['consistency_validation']

        total_tables = len(self.find_v2_table_files())
        failed_migrations = len(migration_errors)
        failed_consistency = len(consistency_errors)

        report['summary'] = {
            'total_tables': total_tables,
            'successful_migrations': total_tables - failed_migrations,
            'failed_migrations': failed_migrations,
            'consistency_issues': failed_consistency,
            'overall_success': failed_migrations == 0 and failed_consistency == 0
        }

        return report
