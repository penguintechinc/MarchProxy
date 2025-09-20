"""
SCIM (System for Cross-domain Identity Management) Service for MarchProxy Enterprise
Handles automated user provisioning from enterprise identity providers
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from py4web import Field, abort, request
from py4web.utils.auth import Auth

from ...models import get_db
from ..license_service import LicenseService

logger = logging.getLogger(__name__)


class SCIMService:
    """SCIM 2.0 Service for enterprise user provisioning"""

    def __init__(self, auth: Auth, license_service: LicenseService):
        self.auth = auth
        self.license_service = license_service
        self.db = get_db()
        self.scim_version = "2.0"
        self.base_url = "/api/scim/v2"

    def is_enabled(self) -> bool:
        """Check if SCIM provisioning is enabled"""
        return self.license_service.has_feature('scim_provisioning')

    def get_service_provider_config(self) -> Dict:
        """Return SCIM Service Provider Configuration"""
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": "https://docs.marchproxy.com/scim",
            "patch": {
                "supported": True
            },
            "bulk": {
                "supported": False,
                "maxOperations": 0,
                "maxPayloadSize": 0
            },
            "filter": {
                "supported": True,
                "maxResults": 200
            },
            "changePassword": {
                "supported": False
            },
            "sort": {
                "supported": True
            },
            "etag": {
                "supported": True
            },
            "authenticationSchemes": [
                {
                    "name": "HTTP Basic",
                    "description": "Authentication scheme using HTTP Basic",
                    "specUri": "http://www.rfc-editor.org/info/rfc2617",
                    "type": "httpbasic"
                },
                {
                    "name": "Bearer Token",
                    "description": "Authentication scheme using Bearer Token",
                    "specUri": "http://www.rfc-editor.org/info/rfc6750",
                    "type": "oauthbearertoken"
                }
            ],
            "meta": {
                "location": f"{self.base_url}/ServiceProviderConfig",
                "resourceType": "ServiceProviderConfig"
            }
        }

    def get_resource_types(self) -> List[Dict]:
        """Return supported SCIM resource types"""
        return [
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "description": "User Account",
                "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
                "schemaExtensions": [
                    {
                        "schema": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
                        "required": False
                    }
                ],
                "meta": {
                    "location": f"{self.base_url}/ResourceTypes/User",
                    "resourceType": "ResourceType"
                }
            },
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "Group",
                "name": "Group",
                "endpoint": "/Groups",
                "description": "Group",
                "schema": "urn:ietf:params:scim:schemas:core:2.0:Group",
                "meta": {
                    "location": f"{self.base_url}/ResourceTypes/Group",
                    "resourceType": "ResourceType"
                }
            }
        ]

    def get_schemas(self) -> List[Dict]:
        """Return SCIM schemas"""
        return [
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
                "id": "urn:ietf:params:scim:schemas:core:2.0:User",
                "name": "User",
                "description": "User Account",
                "attributes": [
                    {
                        "name": "userName",
                        "type": "string",
                        "multiValued": False,
                        "description": "Unique identifier for the User",
                        "required": True,
                        "caseExact": False,
                        "mutability": "readWrite",
                        "returned": "default",
                        "uniqueness": "server"
                    },
                    {
                        "name": "name",
                        "type": "complex",
                        "multiValued": False,
                        "description": "The components of the user's real name",
                        "required": False,
                        "subAttributes": [
                            {
                                "name": "formatted",
                                "type": "string",
                                "multiValued": False,
                                "description": "The full name",
                                "required": False,
                                "caseExact": False,
                                "mutability": "readWrite",
                                "returned": "default",
                                "uniqueness": "none"
                            },
                            {
                                "name": "familyName",
                                "type": "string",
                                "multiValued": False,
                                "description": "The family name",
                                "required": False,
                                "caseExact": False,
                                "mutability": "readWrite",
                                "returned": "default",
                                "uniqueness": "none"
                            },
                            {
                                "name": "givenName",
                                "type": "string",
                                "multiValued": False,
                                "description": "The given name",
                                "required": False,
                                "caseExact": False,
                                "mutability": "readWrite",
                                "returned": "default",
                                "uniqueness": "none"
                            }
                        ],
                        "mutability": "readWrite",
                        "returned": "default",
                        "uniqueness": "none"
                    },
                    {
                        "name": "emails",
                        "type": "complex",
                        "multiValued": True,
                        "description": "Email addresses for the user",
                        "required": False,
                        "subAttributes": [
                            {
                                "name": "value",
                                "type": "string",
                                "multiValued": False,
                                "description": "Email addresses for the user",
                                "required": False,
                                "caseExact": False,
                                "mutability": "readWrite",
                                "returned": "default",
                                "uniqueness": "none"
                            },
                            {
                                "name": "primary",
                                "type": "boolean",
                                "multiValued": False,
                                "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute",
                                "required": False,
                                "mutability": "readWrite",
                                "returned": "default"
                            }
                        ],
                        "mutability": "readWrite",
                        "returned": "default",
                        "uniqueness": "none"
                    },
                    {
                        "name": "active",
                        "type": "boolean",
                        "multiValued": False,
                        "description": "A Boolean value indicating the User's administrative status",
                        "required": False,
                        "mutability": "readWrite",
                        "returned": "default"
                    }
                ],
                "meta": {
                    "resourceType": "Schema",
                    "location": f"{self.base_url}/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"
                }
            }
        ]

    def create_user(self, user_data: Dict) -> Dict:
        """Create a new user via SCIM"""
        if not self.is_enabled():
            abort(403, "SCIM provisioning not available")

        # Validate required fields
        if 'userName' not in user_data:
            abort(400, "userName is required")

        username = user_data['userName']

        # Check if user already exists
        existing_user = self.db(self.db.auth_user.username == username).select().first()
        if existing_user:
            abort(409, f"User with userName '{username}' already exists")

        # Extract user attributes
        user_attrs = self._extract_user_attributes(user_data)

        # Create user
        user_id = self.db.auth_user.insert(
            username=username,
            email=user_attrs.get('email', ''),
            first_name=user_attrs.get('first_name', ''),
            last_name=user_attrs.get('last_name', ''),
            is_admin=user_attrs.get('is_admin', False),
            external_id=user_attrs.get('external_id', str(uuid.uuid4())),
            auth_provider='scim',
            password_hash='',  # SCIM users don't have local passwords
            registration_date=datetime.utcnow(),
            last_login=None
        )
        self.db.commit()

        user = self.db.auth_user[user_id]

        logger.info(f"SCIM: Created user {username}")
        return self._user_to_scim(user)

    def get_user(self, user_id: str) -> Dict:
        """Get user by ID via SCIM"""
        if not self.is_enabled():
            abort(403, "SCIM provisioning not available")

        user = self.db.auth_user[user_id]
        if not user:
            abort(404, f"User with id '{user_id}' not found")

        return self._user_to_scim(user)

    def update_user(self, user_id: str, user_data: Dict) -> Dict:
        """Update user via SCIM"""
        if not self.is_enabled():
            abort(403, "SCIM provisioning not available")

        user = self.db.auth_user[user_id]
        if not user:
            abort(404, f"User with id '{user_id}' not found")

        # Extract updated attributes
        user_attrs = self._extract_user_attributes(user_data)

        # Update user
        update_data = {}
        if 'userName' in user_data:
            update_data['username'] = user_data['userName']
        if 'email' in user_attrs:
            update_data['email'] = user_attrs['email']
        if 'first_name' in user_attrs:
            update_data['first_name'] = user_attrs['first_name']
        if 'last_name' in user_attrs:
            update_data['last_name'] = user_attrs['last_name']
        if 'active' in user_data:
            update_data['is_active'] = user_data['active']

        if update_data:
            self.db(self.db.auth_user.id == user_id).update(**update_data)
            self.db.commit()

        updated_user = self.db.auth_user[user_id]

        logger.info(f"SCIM: Updated user {updated_user.username}")
        return self._user_to_scim(updated_user)

    def patch_user(self, user_id: str, patch_data: Dict) -> Dict:
        """Patch user via SCIM PATCH operation"""
        if not self.is_enabled():
            abort(403, "SCIM provisioning not available")

        user = self.db.auth_user[user_id]
        if not user:
            abort(404, f"User with id '{user_id}' not found")

        operations = patch_data.get('Operations', [])

        for operation in operations:
            op = operation.get('op', '').lower()
            path = operation.get('path', '')
            value = operation.get('value')

            if op == 'replace':
                if path == 'active':
                    self.db(self.db.auth_user.id == user_id).update(is_active=value)
                elif path == 'userName':
                    self.db(self.db.auth_user.id == user_id).update(username=value)
                elif path.startswith('emails'):
                    if isinstance(value, list) and value:
                        primary_email = next((email['value'] for email in value if email.get('primary')), None)
                        if primary_email:
                            self.db(self.db.auth_user.id == user_id).update(email=primary_email)
                elif path.startswith('name'):
                    if 'givenName' in value:
                        self.db(self.db.auth_user.id == user_id).update(first_name=value['givenName'])
                    if 'familyName' in value:
                        self.db(self.db.auth_user.id == user_id).update(last_name=value['familyName'])

        self.db.commit()
        updated_user = self.db.auth_user[user_id]

        logger.info(f"SCIM: Patched user {updated_user.username}")
        return self._user_to_scim(updated_user)

    def delete_user(self, user_id: str) -> None:
        """Delete user via SCIM"""
        if not self.is_enabled():
            abort(403, "SCIM provisioning not available")

        user = self.db.auth_user[user_id]
        if not user:
            abort(404, f"User with id '{user_id}' not found")

        username = user.username

        # Soft delete - mark as inactive
        self.db(self.db.auth_user.id == user_id).update(
            is_active=False,
            external_id=f"deleted_{user.external_id}"
        )
        self.db.commit()

        logger.info(f"SCIM: Deleted user {username}")

    def list_users(self, start_index: int = 1, count: int = 100, filter_expr: str = None) -> Dict:
        """List users via SCIM"""
        if not self.is_enabled():
            abort(403, "SCIM provisioning not available")

        # Build query
        query = self.db.auth_user.id > 0

        # Apply filter if provided
        if filter_expr:
            query = self._apply_scim_filter(query, filter_expr)

        # Get total count
        total_results = self.db(query).count()

        # Apply pagination
        offset = start_index - 1
        users = self.db(query).select(
            limitby=(offset, offset + count),
            orderby=self.db.auth_user.username
        )

        # Convert to SCIM format
        scim_users = [self._user_to_scim(user) for user in users]

        return {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": total_results,
            "startIndex": start_index,
            "itemsPerPage": len(scim_users),
            "Resources": scim_users
        }

    def _extract_user_attributes(self, user_data: Dict) -> Dict:
        """Extract user attributes from SCIM user data"""
        attrs = {}

        # Extract email
        emails = user_data.get('emails', [])
        if emails:
            primary_email = next((email['value'] for email in emails if email.get('primary')), None)
            if primary_email:
                attrs['email'] = primary_email
            elif emails[0].get('value'):
                attrs['email'] = emails[0]['value']

        # Extract name
        name = user_data.get('name', {})
        if 'givenName' in name:
            attrs['first_name'] = name['givenName']
        if 'familyName' in name:
            attrs['last_name'] = name['familyName']

        # Extract other attributes
        if 'externalId' in user_data:
            attrs['external_id'] = user_data['externalId']

        # Enterprise extension
        enterprise = user_data.get('urn:ietf:params:scim:schemas:extension:enterprise:2.0:User', {})
        if 'department' in enterprise:
            attrs['department'] = enterprise['department']
        if 'manager' in enterprise:
            attrs['manager'] = enterprise['manager']

        return attrs

    def _user_to_scim(self, user) -> Dict:
        """Convert database user to SCIM format"""
        scim_user = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": str(user.id),
            "userName": user.username,
            "name": {
                "givenName": user.first_name or "",
                "familyName": user.last_name or "",
                "formatted": f"{user.first_name} {user.last_name}".strip()
            },
            "emails": [
                {
                    "value": user.email,
                    "primary": True
                }
            ] if user.email else [],
            "active": getattr(user, 'is_active', True),
            "meta": {
                "resourceType": "User",
                "created": user.registration_date.isoformat() + 'Z' if user.registration_date else None,
                "lastModified": user.last_login.isoformat() + 'Z' if user.last_login else None,
                "location": f"{self.base_url}/Users/{user.id}",
                "version": f'W/"{user.id}"'
            }
        }

        # Add external ID if present
        if user.external_id:
            scim_user["externalId"] = user.external_id

        return scim_user

    def _apply_scim_filter(self, query, filter_expr: str):
        """Apply SCIM filter expression to query"""
        # Simplified filter parsing - in production use proper SCIM filter parser
        if 'userName eq' in filter_expr:
            username = filter_expr.split('"')[1]
            query &= (self.db.auth_user.username == username)
        elif 'emails.value eq' in filter_expr:
            email = filter_expr.split('"')[1]
            query &= (self.db.auth_user.email == email)
        elif 'active eq' in filter_expr:
            active = 'true' in filter_expr.lower()
            query &= (self.db.auth_user.is_active == active)

        return query

    def handle_bulk_operation(self, bulk_data: Dict) -> Dict:
        """Handle SCIM bulk operations"""
        if not self.is_enabled():
            abort(403, "SCIM provisioning not available")

        # Bulk operations not implemented yet
        abort(501, "Bulk operations not supported")

    def get_groups(self) -> Dict:
        """Get groups via SCIM (placeholder)"""
        if not self.is_enabled():
            abort(403, "SCIM provisioning not available")

        # Groups functionality would be implemented here
        return {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 0,
            "startIndex": 1,
            "itemsPerPage": 0,
            "Resources": []
        }