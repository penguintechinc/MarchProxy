"""
Cluster management models for MarchProxy Manager

Copyright (C) 2025 MarchProxy Contributors
Licensed under GNU Affero General Public License v3.0
"""

import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from pydal import DAL, Field
from pydantic import BaseModel, validator


class ClusterModel:
    """Cluster model for multi-tenant proxy management"""

    @staticmethod
    def define_table(db: DAL):
        """Define cluster table in database"""
        return db.define_table(
            'clusters',
            Field('name', type='string', unique=True, required=True, length=100),
            Field('description', type='text'),
            Field('api_key_hash', type='string', required=True, length=255),
            Field('syslog_endpoint', type='string', length=255),
            Field('log_auth', type='boolean', default=True),
            Field('log_netflow', type='boolean', default=True),
            Field('log_debug', type='boolean', default=False),
            Field('is_active', type='boolean', default=True),
            Field('is_default', type='boolean', default=False),
            Field('max_proxies', type='integer', default=3),
            Field('created_by', type='reference users', required=True),
            Field('created_at', type='datetime', default=datetime.utcnow),
            Field('updated_at', type='datetime', update=datetime.utcnow),
            Field('metadata', type='json'),
        )

    @staticmethod
    def generate_api_key() -> str:
        """Generate secure cluster API key"""
        return secrets.token_urlsafe(48)

    @staticmethod
    def hash_api_key(api_key: str) -> str:
        """Hash API key for storage"""
        return hashlib.sha256(api_key.encode('utf-8')).hexdigest()

    @staticmethod
    def verify_api_key(api_key: str, api_key_hash: str) -> bool:
        """Verify API key against hash"""
        return hashlib.sha256(api_key.encode('utf-8')).hexdigest() == api_key_hash

    @staticmethod
    def create_cluster(db: DAL, name: str, description: str = None,
                      created_by: int = None, syslog_endpoint: str = None,
                      log_auth: bool = True, log_netflow: bool = True,
                      log_debug: bool = False, max_proxies: int = 3) -> tuple[int, str]:
        """Create new cluster and return (cluster_id, api_key)"""
        api_key = ClusterModel.generate_api_key()
        api_key_hash = ClusterModel.hash_api_key(api_key)

        cluster_id = db.clusters.insert(
            name=name,
            description=description,
            api_key_hash=api_key_hash,
            syslog_endpoint=syslog_endpoint,
            log_auth=log_auth,
            log_netflow=log_netflow,
            log_debug=log_debug,
            max_proxies=max_proxies,
            created_by=created_by
        )

        return cluster_id, api_key

    @staticmethod
    def create_default_cluster(db: DAL, created_by: int) -> tuple[int, str]:
        """Create default cluster for Community edition"""
        # Check if default cluster already exists
        existing = db(db.clusters.is_default == True).select().first()
        if existing:
            return existing.id, None

        api_key = ClusterModel.generate_api_key()
        api_key_hash = ClusterModel.hash_api_key(api_key)

        cluster_id = db.clusters.insert(
            name="default",
            description="Default cluster for Community edition",
            api_key_hash=api_key_hash,
            is_default=True,
            is_active=True,
            max_proxies=3,
            created_by=created_by
        )

        return cluster_id, api_key

    @staticmethod
    def validate_api_key(db: DAL, api_key: str) -> Optional[Dict[str, Any]]:
        """Validate cluster API key and return cluster info"""
        api_key_hash = ClusterModel.hash_api_key(api_key)
        cluster = db(
            (db.clusters.api_key_hash == api_key_hash) &
            (db.clusters.is_active == True)
        ).select().first()

        if cluster:
            return {
                'cluster_id': cluster.id,
                'name': cluster.name,
                'description': cluster.description,
                'syslog_endpoint': cluster.syslog_endpoint,
                'log_auth': cluster.log_auth,
                'log_netflow': cluster.log_netflow,
                'log_debug': cluster.log_debug,
                'max_proxies': cluster.max_proxies,
                'is_default': cluster.is_default
            }

        return None

    @staticmethod
    def rotate_api_key(db: DAL, cluster_id: int) -> str:
        """Rotate cluster API key and return new key"""
        new_api_key = ClusterModel.generate_api_key()
        new_api_key_hash = ClusterModel.hash_api_key(new_api_key)

        cluster = db.clusters[cluster_id]
        if cluster:
            cluster.update_record(
                api_key_hash=new_api_key_hash,
                updated_at=datetime.utcnow()
            )
            return new_api_key

        return None

    @staticmethod
    def update_logging_config(db: DAL, cluster_id: int, syslog_endpoint: str = None,
                             log_auth: bool = None, log_netflow: bool = None,
                             log_debug: bool = None) -> bool:
        """Update cluster logging configuration"""
        cluster = db.clusters[cluster_id]
        if not cluster:
            return False

        update_data = {'updated_at': datetime.utcnow()}
        if syslog_endpoint is not None:
            update_data['syslog_endpoint'] = syslog_endpoint
        if log_auth is not None:
            update_data['log_auth'] = log_auth
        if log_netflow is not None:
            update_data['log_netflow'] = log_netflow
        if log_debug is not None:
            update_data['log_debug'] = log_debug

        cluster.update_record(**update_data)
        return True

    @staticmethod
    def get_cluster_config(db: DAL, cluster_id: int) -> Optional[Dict[str, Any]]:
        """Get complete cluster configuration for proxy"""
        cluster = db(
            (db.clusters.id == cluster_id) &
            (db.clusters.is_active == True)
        ).select().first()

        if not cluster:
            return None

        # Get services for this cluster
        services = db(
            (db.services.cluster_id == cluster_id) &
            (db.services.is_active == True)
        ).select()

        # Get mappings for this cluster
        mappings = db(
            (db.mappings.cluster_id == cluster_id) &
            (db.mappings.is_active == True)
        ).select()

        # Get certificates available to this cluster
        certificates = db(db.certificates.is_active == True).select()

        return {
            'cluster': {
                'id': cluster.id,
                'name': cluster.name,
                'syslog_endpoint': cluster.syslog_endpoint,
                'log_auth': cluster.log_auth,
                'log_netflow': cluster.log_netflow,
                'log_debug': cluster.log_debug
            },
            'services': [dict(service) for service in services],
            'mappings': [dict(mapping) for mapping in mappings],
            'certificates': [dict(cert) for cert in certificates]
        }

    @staticmethod
    def count_active_proxies(db: DAL, cluster_id: int) -> int:
        """Count active proxies in cluster"""
        return db(
            (db.proxy_servers.cluster_id == cluster_id) &
            (db.proxy_servers.status == 'active') &
            (db.proxy_servers.last_seen > datetime.utcnow() - timedelta(minutes=5))
        ).count()

    @staticmethod
    def check_proxy_limit(db: DAL, cluster_id: int) -> bool:
        """Check if cluster can accept more proxies"""
        cluster = db.clusters[cluster_id]
        if not cluster:
            return False

        active_count = ClusterModel.count_active_proxies(db, cluster_id)
        return active_count < cluster.max_proxies


class UserClusterAssignmentModel:
    """User-cluster assignment model for Enterprise multi-cluster access"""

    @staticmethod
    def define_table(db: DAL):
        """Define user cluster assignment table"""
        return db.define_table(
            'user_cluster_assignments',
            Field('user_id', type='reference users', required=True),
            Field('cluster_id', type='reference clusters', required=True),
            Field('role', type='string', default='service_owner', length=50),
            Field('assigned_by', type='reference users', required=True),
            Field('assigned_at', type='datetime', default=datetime.utcnow),
            Field('is_active', type='boolean', default=True),
        )

    @staticmethod
    def assign_user_to_cluster(db: DAL, user_id: int, cluster_id: int,
                              role: str = 'service_owner', assigned_by: int = None) -> bool:
        """Assign user to cluster with role"""
        # Check if assignment already exists
        existing = db(
            (db.user_cluster_assignments.user_id == user_id) &
            (db.user_cluster_assignments.cluster_id == cluster_id) &
            (db.user_cluster_assignments.is_active == True)
        ).select().first()

        if existing:
            existing.update_record(role=role, assigned_by=assigned_by)
            return True

        db.user_cluster_assignments.insert(
            user_id=user_id,
            cluster_id=cluster_id,
            role=role,
            assigned_by=assigned_by
        )
        return True

    @staticmethod
    def get_user_clusters(db: DAL, user_id: int) -> List[Dict[str, Any]]:
        """Get all clusters assigned to user"""
        assignments = db(
            (db.user_cluster_assignments.user_id == user_id) &
            (db.user_cluster_assignments.is_active == True) &
            (db.clusters.is_active == True)
        ).select(
            db.user_cluster_assignments.ALL,
            db.clusters.ALL,
            left=db.clusters.on(db.clusters.id == db.user_cluster_assignments.cluster_id)
        )

        return [
            {
                'cluster_id': assignment.clusters.id,
                'cluster_name': assignment.clusters.name,
                'cluster_description': assignment.clusters.description,
                'role': assignment.user_cluster_assignments.role,
                'assigned_at': assignment.user_cluster_assignments.assigned_at
            }
            for assignment in assignments
        ]

    @staticmethod
    def check_user_cluster_access(db: DAL, user_id: int, cluster_id: int) -> Optional[str]:
        """Check if user has access to cluster and return role"""
        assignment = db(
            (db.user_cluster_assignments.user_id == user_id) &
            (db.user_cluster_assignments.cluster_id == cluster_id) &
            (db.user_cluster_assignments.is_active == True)
        ).select().first()

        return assignment.role if assignment else None


# Pydantic models for request/response validation
class CreateClusterRequest(BaseModel):
    name: str
    description: Optional[str] = None
    syslog_endpoint: Optional[str] = None
    log_auth: bool = True
    log_netflow: bool = True
    log_debug: bool = False
    max_proxies: int = 3

    @validator('name')
    def validate_name(cls, v):
        if len(v) < 3:
            raise ValueError('Cluster name must be at least 3 characters long')
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError('Cluster name can only contain alphanumeric characters, hyphens, and underscores')
        return v.lower()

    @validator('max_proxies')
    def validate_max_proxies(cls, v):
        if v < 1 or v > 1000:
            raise ValueError('Max proxies must be between 1 and 1000')
        return v


class UpdateClusterRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    syslog_endpoint: Optional[str] = None
    log_auth: Optional[bool] = None
    log_netflow: Optional[bool] = None
    log_debug: Optional[bool] = None
    max_proxies: Optional[int] = None

    @validator('max_proxies')
    def validate_max_proxies(cls, v):
        if v is not None and (v < 1 or v > 1000):
            raise ValueError('Max proxies must be between 1 and 1000')
        return v


class ClusterResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    syslog_endpoint: Optional[str]
    log_auth: bool
    log_netflow: bool
    log_debug: bool
    is_active: bool
    is_default: bool
    max_proxies: int
    active_proxies: int
    created_at: datetime
    updated_at: datetime


class AssignUserToClusterRequest(BaseModel):
    user_id: int
    role: str = 'service_owner'

    @validator('role')
    def validate_role(cls, v):
        if v not in ['admin', 'service_owner']:
            raise ValueError('Role must be either "admin" or "service_owner"')
        return v