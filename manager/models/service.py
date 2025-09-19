"""
Service management models for MarchProxy Manager

Copyright (C) 2025 MarchProxy Contributors
Licensed under GNU Affero General Public License v3.0
"""

import secrets
import jwt
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from pydal import DAL, Field
from pydantic import BaseModel, validator


class ServiceModel:
    """Service model for proxy target configuration"""

    @staticmethod
    def define_table(db: DAL):
        """Define service table in database"""
        return db.define_table(
            'services',
            Field('name', type='string', unique=True, required=True, length=100),
            Field('ip_fqdn', type='string', required=True, length=255),
            Field('port', type='integer', required=True),
            Field('protocol', type='string', default='tcp', length=10),
            Field('collection', type='string', length=100),
            Field('cluster_id', type='reference clusters', required=True),
            Field('auth_type', type='string', default='none', length=20),
            Field('token_base64', type='string', length=255),
            Field('jwt_secret', type='string', length=255),
            Field('jwt_expiry', type='integer', default=3600),
            Field('jwt_algorithm', type='string', default='HS256', length=10),
            Field('tls_enabled', type='boolean', default=False),
            Field('tls_verify', type='boolean', default=True),
            Field('health_check_enabled', type='boolean', default=False),
            Field('health_check_path', type='string', length=255),
            Field('health_check_interval', type='integer', default=30),
            Field('is_active', type='boolean', default=True),
            Field('created_by', type='reference users', required=True),
            Field('created_at', type='datetime', default=datetime.utcnow),
            Field('updated_at', type='datetime', update=datetime.utcnow),
            Field('metadata', type='json'),
        )

    @staticmethod
    def create_service(db: DAL, name: str, ip_fqdn: str, port: int,
                      cluster_id: int, created_by: int, protocol: str = 'tcp',
                      collection: str = None, auth_type: str = 'none',
                      tls_enabled: bool = False, tls_verify: bool = True) -> int:
        """Create new service"""
        service_id = db.services.insert(
            name=name,
            ip_fqdn=ip_fqdn,
            port=port,
            protocol=protocol,
            collection=collection,
            cluster_id=cluster_id,
            auth_type=auth_type,
            tls_enabled=tls_enabled,
            tls_verify=tls_verify,
            created_by=created_by
        )

        return service_id

    @staticmethod
    def generate_base64_token() -> str:
        """Generate Base64 token for service authentication"""
        token_bytes = secrets.token_bytes(32)
        return base64.b64encode(token_bytes).decode('utf-8')

    @staticmethod
    def generate_jwt_secret() -> str:
        """Generate JWT secret for service authentication"""
        return secrets.token_urlsafe(48)

    @staticmethod
    def set_base64_auth(db: DAL, service_id: int) -> Optional[str]:
        """Set Base64 token authentication for service"""
        service = db.services[service_id]
        if not service:
            return None

        # Clear JWT settings (mutually exclusive)
        token = ServiceModel.generate_base64_token()
        service.update_record(
            auth_type='base64',
            token_base64=token,
            jwt_secret=None,
            jwt_expiry=None,
            updated_at=datetime.utcnow()
        )

        return token

    @staticmethod
    def set_jwt_auth(db: DAL, service_id: int, expiry_seconds: int = 3600,
                    algorithm: str = 'HS256') -> Optional[str]:
        """Set JWT authentication for service"""
        service = db.services[service_id]
        if not service:
            return None

        # Clear Base64 settings (mutually exclusive)
        jwt_secret = ServiceModel.generate_jwt_secret()
        service.update_record(
            auth_type='jwt',
            token_base64=None,
            jwt_secret=jwt_secret,
            jwt_expiry=expiry_seconds,
            jwt_algorithm=algorithm,
            updated_at=datetime.utcnow()
        )

        return jwt_secret

    @staticmethod
    def rotate_jwt_secret(db: DAL, service_id: int) -> Optional[str]:
        """Rotate JWT secret for zero-downtime updates"""
        service = db.services[service_id]
        if not service or service.auth_type != 'jwt':
            return None

        new_secret = ServiceModel.generate_jwt_secret()
        service.update_record(
            jwt_secret=new_secret,
            updated_at=datetime.utcnow()
        )

        return new_secret

    @staticmethod
    def validate_service_token(db: DAL, service_id: int, token: str) -> bool:
        """Validate token against service authentication"""
        service = db.services[service_id]
        if not service or not service.is_active:
            return False

        if service.auth_type == 'base64':
            return service.token_base64 == token

        elif service.auth_type == 'jwt':
            try:
                payload = jwt.decode(
                    token,
                    service.jwt_secret,
                    algorithms=[service.jwt_algorithm],
                    options={"verify_exp": True}
                )
                return payload.get('service_id') == service_id
            except jwt.InvalidTokenError:
                return False

        return service.auth_type == 'none'

    @staticmethod
    def create_jwt_token(db: DAL, service_id: int, additional_claims: Dict = None) -> Optional[str]:
        """Create JWT token for service"""
        service = db.services[service_id]
        if not service or service.auth_type != 'jwt':
            return None

        payload = {
            'service_id': service_id,
            'service_name': service.name,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=service.jwt_expiry),
            'iss': 'marchproxy'
        }

        if additional_claims:
            payload.update(additional_claims)

        return jwt.encode(payload, service.jwt_secret, algorithm=service.jwt_algorithm)

    @staticmethod
    def get_cluster_services(db: DAL, cluster_id: int, user_id: int = None) -> List[Dict[str, Any]]:
        """Get services for cluster (with user access control)"""
        query = (db.services.cluster_id == cluster_id) & (db.services.is_active == True)

        # If user_id provided, filter by user assignments
        if user_id:
            # Check if user is admin
            user = db.users[user_id]
            if not user or not user.is_admin:
                # Filter by user service assignments
                query = query & (
                    db.user_service_assignments.user_id == user_id
                ) & (
                    db.user_service_assignments.service_id == db.services.id
                )

        services = db(query).select()
        return [
            {
                'id': service.id,
                'name': service.name,
                'ip_fqdn': service.ip_fqdn,
                'port': service.port,
                'protocol': service.protocol,
                'collection': service.collection,
                'auth_type': service.auth_type,
                'tls_enabled': service.tls_enabled,
                'health_check_enabled': service.health_check_enabled,
                'created_at': service.created_at
            }
            for service in services
        ]

    @staticmethod
    def get_service_config(db: DAL, service_id: int) -> Optional[Dict[str, Any]]:
        """Get complete service configuration for proxy"""
        service = db(
            (db.services.id == service_id) &
            (db.services.is_active == True)
        ).select().first()

        if not service:
            return None

        config = {
            'id': service.id,
            'name': service.name,
            'ip_fqdn': service.ip_fqdn,
            'port': service.port,
            'protocol': service.protocol,
            'collection': service.collection,
            'tls_enabled': service.tls_enabled,
            'tls_verify': service.tls_verify,
            'auth_type': service.auth_type
        }

        # Include auth configuration based on type
        if service.auth_type == 'base64':
            config['token_base64'] = service.token_base64
        elif service.auth_type == 'jwt':
            config['jwt_secret'] = service.jwt_secret
            config['jwt_expiry'] = service.jwt_expiry
            config['jwt_algorithm'] = service.jwt_algorithm

        # Include health check configuration
        if service.health_check_enabled:
            config.update({
                'health_check_path': service.health_check_path,
                'health_check_interval': service.health_check_interval
            })

        return config


class UserServiceAssignmentModel:
    """User-service assignment model for access control"""

    @staticmethod
    def define_table(db: DAL):
        """Define user service assignment table"""
        return db.define_table(
            'user_service_assignments',
            Field('user_id', type='reference users', required=True),
            Field('service_id', type='reference services', required=True),
            Field('assigned_by', type='reference users', required=True),
            Field('assigned_at', type='datetime', default=datetime.utcnow),
            Field('is_active', type='boolean', default=True),
        )

    @staticmethod
    def assign_user_to_service(db: DAL, user_id: int, service_id: int, assigned_by: int) -> bool:
        """Assign user to service"""
        # Check if assignment already exists
        existing = db(
            (db.user_service_assignments.user_id == user_id) &
            (db.user_service_assignments.service_id == service_id) &
            (db.user_service_assignments.is_active == True)
        ).select().first()

        if existing:
            return True

        db.user_service_assignments.insert(
            user_id=user_id,
            service_id=service_id,
            assigned_by=assigned_by
        )
        return True

    @staticmethod
    def remove_user_from_service(db: DAL, user_id: int, service_id: int) -> bool:
        """Remove user from service"""
        return db(
            (db.user_service_assignments.user_id == user_id) &
            (db.user_service_assignments.service_id == service_id)
        ).update(is_active=False) > 0

    @staticmethod
    def get_user_services(db: DAL, user_id: int) -> List[Dict[str, Any]]:
        """Get all services assigned to user"""
        assignments = db(
            (db.user_service_assignments.user_id == user_id) &
            (db.user_service_assignments.is_active == True) &
            (db.services.is_active == True)
        ).select(
            db.user_service_assignments.ALL,
            db.services.ALL,
            left=db.services.on(db.services.id == db.user_service_assignments.service_id)
        )

        return [
            {
                'service_id': assignment.services.id,
                'service_name': assignment.services.name,
                'ip_fqdn': assignment.services.ip_fqdn,
                'port': assignment.services.port,
                'protocol': assignment.services.protocol,
                'collection': assignment.services.collection,
                'cluster_id': assignment.services.cluster_id,
                'assigned_at': assignment.user_service_assignments.assigned_at
            }
            for assignment in assignments
        ]

    @staticmethod
    def check_user_service_access(db: DAL, user_id: int, service_id: int) -> bool:
        """Check if user has access to service"""
        # Check if user is admin
        user = db.users[user_id]
        if user and user.is_admin:
            return True

        # Check service assignment
        assignment = db(
            (db.user_service_assignments.user_id == user_id) &
            (db.user_service_assignments.service_id == service_id) &
            (db.user_service_assignments.is_active == True)
        ).select().first()

        return assignment is not None


# Pydantic models for request/response validation
class CreateServiceRequest(BaseModel):
    name: str
    ip_fqdn: str
    port: int
    protocol: str = 'tcp'
    collection: Optional[str] = None
    cluster_id: int
    auth_type: str = 'none'
    tls_enabled: bool = False
    tls_verify: bool = True
    health_check_enabled: bool = False
    health_check_path: Optional[str] = None
    health_check_interval: int = 30

    @validator('name')
    def validate_name(cls, v):
        if len(v) < 3:
            raise ValueError('Service name must be at least 3 characters long')
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError('Service name can only contain alphanumeric characters, hyphens, and underscores')
        return v.lower()

    @validator('port')
    def validate_port(cls, v):
        if v < 1 or v > 65535:
            raise ValueError('Port must be between 1 and 65535')
        return v

    @validator('protocol')
    def validate_protocol(cls, v):
        if v not in ['tcp', 'udp', 'icmp', 'http', 'https']:
            raise ValueError('Protocol must be one of: tcp, udp, icmp, http, https')
        return v.lower()

    @validator('auth_type')
    def validate_auth_type(cls, v):
        if v not in ['none', 'base64', 'jwt']:
            raise ValueError('Auth type must be one of: none, base64, jwt')
        return v.lower()


class UpdateServiceRequest(BaseModel):
    name: Optional[str] = None
    ip_fqdn: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    collection: Optional[str] = None
    auth_type: Optional[str] = None
    tls_enabled: Optional[bool] = None
    tls_verify: Optional[bool] = None
    health_check_enabled: Optional[bool] = None
    health_check_path: Optional[str] = None
    health_check_interval: Optional[int] = None

    @validator('port')
    def validate_port(cls, v):
        if v is not None and (v < 1 or v > 65535):
            raise ValueError('Port must be between 1 and 65535')
        return v


class SetServiceAuthRequest(BaseModel):
    auth_type: str
    jwt_expiry: int = 3600
    jwt_algorithm: str = 'HS256'

    @validator('auth_type')
    def validate_auth_type(cls, v):
        if v not in ['none', 'base64', 'jwt']:
            raise ValueError('Auth type must be one of: none, base64, jwt')
        return v

    @validator('jwt_algorithm')
    def validate_jwt_algorithm(cls, v):
        if v not in ['HS256', 'HS384', 'HS512']:
            raise ValueError('JWT algorithm must be one of: HS256, HS384, HS512')
        return v


class CreateJwtTokenRequest(BaseModel):
    service_id: int
    additional_claims: Optional[Dict[str, Any]] = None


class ServiceResponse(BaseModel):
    id: int
    name: str
    ip_fqdn: str
    port: int
    protocol: str
    collection: Optional[str]
    cluster_id: int
    auth_type: str
    tls_enabled: bool
    health_check_enabled: bool
    created_at: datetime


class ServiceAuthResponse(BaseModel):
    service_id: int
    auth_type: str
    token: Optional[str] = None
    jwt_secret: Optional[str] = None
    jwt_expiry: Optional[int] = None


class AssignUserToServiceRequest(BaseModel):
    user_id: int