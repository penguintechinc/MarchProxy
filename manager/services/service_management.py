"""
Service Management Service for MarchProxy
Handles service CRUD operations, authentication configuration, and cluster assignments
"""

import base64
import hashlib
import json
import logging
import secrets
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import jwt
from py4web import Field, abort, request
from py4web.utils.auth import Auth

from ..models import get_db
from .license_service import LicenseService

logger = logging.getLogger(__name__)


class ServiceManagementService:
    """Service for managing MarchProxy services and their authentication"""

    def __init__(self, license_service: LicenseService, auth: Auth):
        self.license_service = license_service
        self.auth = auth
        self.db = get_db()

    def create_service(self, service_data: Dict, user_id: int) -> Dict:
        """Create a new service with cluster assignment and authentication"""

        # Validate cluster access
        cluster_id = service_data.get('cluster_id')
        if not self._user_has_cluster_access(user_id, cluster_id):
            abort(403, "Access denied to specified cluster")

        # Validate authentication method
        auth_type = service_data.get('auth_type', 'none')
        if auth_type not in ['none', 'token', 'jwt']:
            abort(400, "Invalid authentication type")

        # Generate authentication credentials based on type
        auth_config = self._generate_auth_config(auth_type)

        # Create service record
        service_id = self.db.services.insert(
            name=service_data['name'],
            ip_fqdn=service_data['ip_fqdn'],
            collection=service_data.get('collection', 'default'),
            cluster_id=cluster_id,
            auth_type=auth_type,
            token_base64=auth_config.get('token_base64'),
            jwt_secret=auth_config.get('jwt_secret'),
            jwt_expiry=auth_config.get('jwt_expiry'),
            description=service_data.get('description', ''),
            is_active=True,
            created_by=user_id,
            created_at=datetime.utcnow()
        )

        # Assign service to user
        self.db.user_service_assignments.insert(
            user_id=user_id,
            service_id=service_id,
            role='owner',
            assigned_at=datetime.utcnow(),
            assigned_by=user_id
        )

        self.db.commit()

        service = self.db.services[service_id]
        logger.info(f"Created service '{service.name}' (ID: {service_id}) in cluster {cluster_id}")

        return self._service_to_dict(service, include_secrets=True)

    def get_service(self, service_id: int, user_id: int, include_secrets: bool = False) -> Dict:
        """Get service by ID with access control"""

        service = self.db.services[service_id]
        if not service or not service.is_active:
            abort(404, "Service not found")

        # Check access permissions
        if not self._user_has_service_access(user_id, service_id):
            abort(403, "Access denied to service")

        return self._service_to_dict(service, include_secrets)

    def update_service(self, service_id: int, service_data: Dict, user_id: int) -> Dict:
        """Update service with access control"""

        service = self.db.services[service_id]
        if not service or not service.is_active:
            abort(404, "Service not found")

        # Check write permissions
        if not self._user_has_service_write_access(user_id, service_id):
            abort(403, "Write access denied to service")

        # Validate cluster change
        if 'cluster_id' in service_data:
            new_cluster_id = service_data['cluster_id']
            if new_cluster_id != service.cluster_id:
                if not self._user_has_cluster_access(user_id, new_cluster_id):
                    abort(403, "Access denied to target cluster")

        # Handle authentication type changes
        if 'auth_type' in service_data and service_data['auth_type'] != service.auth_type:
            auth_config = self._generate_auth_config(service_data['auth_type'])
            service_data.update(auth_config)

        # Update service
        update_fields = {
            'updated_at': datetime.utcnow(),
            'updated_by': user_id
        }

        # Update allowed fields
        allowed_fields = [
            'name', 'ip_fqdn', 'collection', 'cluster_id', 'auth_type',
            'description', 'token_base64', 'jwt_secret', 'jwt_expiry'
        ]

        for field in allowed_fields:
            if field in service_data:
                update_fields[field] = service_data[field]

        self.db(self.db.services.id == service_id).update(**update_fields)
        self.db.commit()

        updated_service = self.db.services[service_id]
        logger.info(f"Updated service '{updated_service.name}' (ID: {service_id})")

        return self._service_to_dict(updated_service, include_secrets=True)

    def delete_service(self, service_id: int, user_id: int) -> bool:
        """Soft delete service (mark as inactive)"""

        service = self.db.services[service_id]
        if not service or not service.is_active:
            abort(404, "Service not found")

        # Check write permissions
        if not self._user_has_service_write_access(user_id, service_id):
            abort(403, "Delete access denied")

        # Soft delete
        self.db(self.db.services.id == service_id).update(
            is_active=False,
            updated_at=datetime.utcnow(),
            updated_by=user_id
        )
        self.db.commit()

        logger.info(f"Deleted service '{service.name}' (ID: {service_id})")
        return True

    def list_services(self, user_id: int, cluster_id: Optional[int] = None,
                     page: int = 1, per_page: int = 50) -> Dict:
        """List services accessible to user"""

        # Build base query for user's accessible services
        query = self._build_user_services_query(user_id, cluster_id)

        # Get total count
        total_count = self.db(query).count()

        # Apply pagination
        offset = (page - 1) * per_page
        services = self.db(query).select(
            self.db.services.ALL,
            limitby=(offset, offset + per_page),
            orderby=self.db.services.name
        )

        service_list = [self._service_to_dict(service, include_secrets=False) for service in services]

        return {
            'services': service_list,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_count,
                'pages': (total_count + per_page - 1) // per_page
            }
        }

    def assign_user_to_service(self, service_id: int, target_user_id: int,
                              role: str, assigner_user_id: int) -> bool:
        """Assign user to service"""

        # Validate service exists and user has access
        if not self._user_has_service_write_access(assigner_user_id, service_id):
            abort(403, "Access denied")

        # Validate role
        if role not in ['viewer', 'editor', 'owner']:
            abort(400, "Invalid role")

        # Check if assignment already exists
        existing = self.db(
            (self.db.user_service_assignments.user_id == target_user_id) &
            (self.db.user_service_assignments.service_id == service_id)
        ).select().first()

        if existing:
            # Update existing assignment
            self.db(
                (self.db.user_service_assignments.user_id == target_user_id) &
                (self.db.user_service_assignments.service_id == service_id)
            ).update(
                role=role,
                assigned_at=datetime.utcnow(),
                assigned_by=assigner_user_id
            )
        else:
            # Create new assignment
            self.db.user_service_assignments.insert(
                user_id=target_user_id,
                service_id=service_id,
                role=role,
                assigned_at=datetime.utcnow(),
                assigned_by=assigner_user_id
            )

        self.db.commit()
        logger.info(f"Assigned user {target_user_id} to service {service_id} with role {role}")
        return True

    def remove_user_from_service(self, service_id: int, target_user_id: int,
                                remover_user_id: int) -> bool:
        """Remove user from service"""

        if not self._user_has_service_write_access(remover_user_id, service_id):
            abort(403, "Access denied")

        self.db(
            (self.db.user_service_assignments.user_id == target_user_id) &
            (self.db.user_service_assignments.service_id == service_id)
        ).delete()

        self.db.commit()
        logger.info(f"Removed user {target_user_id} from service {service_id}")
        return True

    def rotate_jwt_secret(self, service_id: int, user_id: int) -> Dict:
        """Rotate JWT secret with zero-downtime"""

        service = self.db.services[service_id]
        if not service or not service.is_active:
            abort(404, "Service not found")

        if service.auth_type != 'jwt':
            abort(400, "Service does not use JWT authentication")

        if not self._user_has_service_write_access(user_id, service_id):
            abort(403, "Access denied")

        # Generate new JWT secret
        new_secret = self._generate_jwt_secret()

        # Store old secret temporarily for zero-downtime rotation
        old_secret = service.jwt_secret
        rotation_data = {
            'old_secret': old_secret,
            'new_secret': new_secret,
            'rotation_started': datetime.utcnow().isoformat(),
            'rotation_window': 300  # 5 minutes
        }

        # Update service with new secret and rotation data
        self.db(self.db.services.id == service_id).update(
            jwt_secret=new_secret,
            jwt_rotation_data=json.dumps(rotation_data),
            updated_at=datetime.utcnow(),
            updated_by=user_id
        )
        self.db.commit()

        logger.info(f"Initiated JWT secret rotation for service {service_id}")

        return {
            'old_secret': old_secret,
            'new_secret': new_secret,
            'rotation_window_seconds': 300,
            'message': 'JWT secret rotated. Old secret valid for 5 minutes.'
        }

    def finalize_jwt_rotation(self, service_id: int, user_id: int) -> bool:
        """Finalize JWT rotation (remove old secret)"""

        service = self.db.services[service_id]
        if not service or not service.is_active:
            abort(404, "Service not found")

        if not self._user_has_service_write_access(user_id, service_id):
            abort(403, "Access denied")

        # Clear rotation data
        self.db(self.db.services.id == service_id).update(
            jwt_rotation_data=None,
            updated_at=datetime.utcnow()
        )
        self.db.commit()

        logger.info(f"Finalized JWT secret rotation for service {service_id}")
        return True

    def regenerate_token(self, service_id: int, user_id: int) -> Dict:
        """Regenerate Base64 token for service"""

        service = self.db.services[service_id]
        if not service or not service.is_active:
            abort(404, "Service not found")

        if service.auth_type != 'token':
            abort(400, "Service does not use token authentication")

        if not self._user_has_service_write_access(user_id, service_id):
            abort(403, "Access denied")

        # Generate new token
        new_token = self._generate_base64_token()

        self.db(self.db.services.id == service_id).update(
            token_base64=new_token,
            updated_at=datetime.utcnow(),
            updated_by=user_id
        )
        self.db.commit()

        logger.info(f"Regenerated token for service {service_id}")

        return {
            'token': new_token,
            'message': 'Token regenerated successfully'
        }

    def get_service_auth_config(self, service_id: int) -> Dict:
        """Get service authentication configuration for proxy"""

        service = self.db.services[service_id]
        if not service or not service.is_active:
            return None

        auth_config = {
            'service_id': service_id,
            'auth_type': service.auth_type
        }

        if service.auth_type == 'token' and service.token_base64:
            auth_config['token'] = service.token_base64

        elif service.auth_type == 'jwt' and service.jwt_secret:
            auth_config['jwt_secret'] = service.jwt_secret
            auth_config['jwt_expiry'] = service.jwt_expiry

            # Include old secret during rotation
            if service.jwt_rotation_data:
                try:
                    rotation_data = json.loads(service.jwt_rotation_data)
                    rotation_started = datetime.fromisoformat(rotation_data['rotation_started'])
                    window_seconds = rotation_data.get('rotation_window', 300)

                    if datetime.utcnow() < rotation_started + timedelta(seconds=window_seconds):
                        auth_config['jwt_secret_old'] = rotation_data['old_secret']
                except (json.JSONDecodeError, ValueError, KeyError):
                    pass

        return auth_config

    def _generate_auth_config(self, auth_type: str) -> Dict:
        """Generate authentication configuration for new service"""

        if auth_type == 'token':
            return {'token_base64': self._generate_base64_token()}

        elif auth_type == 'jwt':
            return {
                'jwt_secret': self._generate_jwt_secret(),
                'jwt_expiry': 3600  # 1 hour default
            }

        else:  # 'none'
            return {}

    def _generate_base64_token(self) -> str:
        """Generate secure Base64 token"""
        # Generate 32 bytes of random data
        token_bytes = secrets.token_bytes(32)
        return base64.b64encode(token_bytes).decode('ascii')

    def _generate_jwt_secret(self) -> str:
        """Generate secure JWT signing secret"""
        # Generate 64 bytes of random data for HS512
        secret_bytes = secrets.token_bytes(64)
        return base64.b64encode(secret_bytes).decode('ascii')

    def _user_has_cluster_access(self, user_id: int, cluster_id: int) -> bool:
        """Check if user has access to cluster"""

        user = self.db.auth_user[user_id]
        if not user:
            return False

        # Admins have access to all clusters
        if user.is_admin:
            return True

        # Check cluster assignment
        assignment = self.db(
            (self.db.user_cluster_assignments.user_id == user_id) &
            (self.db.user_cluster_assignments.cluster_id == cluster_id)
        ).select().first()

        return assignment is not None

    def _user_has_service_access(self, user_id: int, service_id: int) -> bool:
        """Check if user has read access to service"""

        user = self.db.auth_user[user_id]
        if not user:
            return False

        # Admins have access to all services
        if user.is_admin:
            return True

        # Check service assignment
        assignment = self.db(
            (self.db.user_service_assignments.user_id == user_id) &
            (self.db.user_service_assignments.service_id == service_id)
        ).select().first()

        return assignment is not None

    def _user_has_service_write_access(self, user_id: int, service_id: int) -> bool:
        """Check if user has write access to service"""

        user = self.db.auth_user[user_id]
        if not user:
            return False

        # Admins have write access to all services
        if user.is_admin:
            return True

        # Check service assignment with appropriate role
        assignment = self.db(
            (self.db.user_service_assignments.user_id == user_id) &
            (self.db.user_service_assignments.service_id == service_id)
        ).select().first()

        return assignment and assignment.role in ['editor', 'owner']

    def _build_user_services_query(self, user_id: int, cluster_id: Optional[int] = None):
        """Build query for user's accessible services"""

        user = self.db.auth_user[user_id]

        # Start with active services
        query = (self.db.services.is_active == True)

        # Add cluster filter if specified
        if cluster_id:
            query &= (self.db.services.cluster_id == cluster_id)

        # If not admin, filter by service assignments
        if not user.is_admin:
            query &= (
                self.db.services.id.belongs(
                    self.db(self.db.user_service_assignments.user_id == user_id)
                    ._select(self.db.user_service_assignments.service_id)
                )
            )

        return query

    def _service_to_dict(self, service, include_secrets: bool = False) -> Dict:
        """Convert service record to dictionary"""

        result = {
            'id': service.id,
            'name': service.name,
            'ip_fqdn': service.ip_fqdn,
            'collection': service.collection,
            'cluster_id': service.cluster_id,
            'auth_type': service.auth_type,
            'description': service.description,
            'is_active': service.is_active,
            'created_at': service.created_at.isoformat() if service.created_at else None,
            'updated_at': service.updated_at.isoformat() if service.updated_at else None
        }

        # Include authentication secrets only when requested
        if include_secrets:
            if service.auth_type == 'token' and service.token_base64:
                result['token_base64'] = service.token_base64

            elif service.auth_type == 'jwt':
                result['jwt_secret'] = service.jwt_secret
                result['jwt_expiry'] = service.jwt_expiry

                # Include rotation status
                if service.jwt_rotation_data:
                    try:
                        rotation_data = json.loads(service.jwt_rotation_data)
                        result['jwt_rotation_active'] = True
                        result['jwt_rotation_started'] = rotation_data.get('rotation_started')
                    except (json.JSONDecodeError, ValueError):
                        pass

        return result