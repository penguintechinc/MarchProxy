"""
Proxy server registration and management models for MarchProxy Manager

Copyright (C) 2025 MarchProxy Contributors
Licensed under GNU Affero General Public License v3.0
"""

import socket
import ipaddress
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from pydal import DAL, Field
from pydantic import BaseModel, validator


class ProxyServerModel:
    """Proxy server registration and status management"""

    @staticmethod
    def define_table(db: DAL):
        """Define proxy server table in database"""
        return db.define_table(
            'proxy_servers',
            Field('name', type='string', unique=True, required=True, length=100),
            Field('hostname', type='string', required=True, length=255),
            Field('ip_address', type='string', required=True, length=45),
            Field('port', type='integer', default=8080),
            Field('cluster_id', type='reference clusters', required=True),
            Field('status', type='string', default='pending', length=20),
            Field('version', type='string', length=50),
            Field('capabilities', type='json'),
            Field('license_validated', type='boolean', default=False),
            Field('license_validation_at', type='datetime'),
            Field('last_seen', type='datetime'),
            Field('last_config_fetch', type='datetime'),
            Field('config_version', type='string', length=64),
            Field('registered_at', type='datetime', default=datetime.utcnow),
            Field('metadata', type='json'),
        )

    @staticmethod
    def register_proxy(db: DAL, name: str, hostname: str, cluster_api_key: str,
                      ip_address: str = None, port: int = 8080,
                      version: str = None, capabilities: Dict = None) -> Optional[int]:
        """Register new proxy server with cluster API key validation"""
        from .cluster import ClusterModel

        # Validate cluster API key
        cluster_info = ClusterModel.validate_api_key(db, cluster_api_key)
        if not cluster_info:
            return None

        cluster_id = cluster_info['cluster_id']

        # Check proxy limit for cluster
        if not ClusterModel.check_proxy_limit(db, cluster_id):
            return None

        # Resolve IP address if not provided
        if not ip_address:
            try:
                ip_address = socket.gethostbyname(hostname)
            except socket.gaierror:
                return None

        # Validate IP address format
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return None

        # Check if proxy already exists
        existing = db(
            (db.proxy_servers.name == name) |
            ((db.proxy_servers.hostname == hostname) & (db.proxy_servers.port == port))
        ).select().first()

        if existing:
            # Update existing proxy
            existing.update_record(
                cluster_id=cluster_id,
                ip_address=ip_address,
                port=port,
                version=version,
                capabilities=capabilities or {},
                status='active',
                last_seen=datetime.utcnow(),
                registered_at=datetime.utcnow()
            )
            return existing.id

        # Create new proxy registration
        proxy_id = db.proxy_servers.insert(
            name=name,
            hostname=hostname,
            ip_address=ip_address,
            port=port,
            cluster_id=cluster_id,
            version=version,
            capabilities=capabilities or {},
            status='active',
            last_seen=datetime.utcnow()
        )

        return proxy_id

    @staticmethod
    def update_heartbeat(db: DAL, proxy_name: str, cluster_api_key: str,
                        status_data: Dict = None) -> bool:
        """Update proxy heartbeat and status"""
        from .cluster import ClusterModel

        # Validate cluster API key
        cluster_info = ClusterModel.validate_api_key(db, cluster_api_key)
        if not cluster_info:
            return False

        proxy = db(
            (db.proxy_servers.name == proxy_name) &
            (db.proxy_servers.cluster_id == cluster_info['cluster_id'])
        ).select().first()

        if not proxy:
            return False

        update_data = {
            'last_seen': datetime.utcnow(),
            'status': 'active'
        }

        if status_data:
            if 'version' in status_data:
                update_data['version'] = status_data['version']
            if 'capabilities' in status_data:
                update_data['capabilities'] = status_data['capabilities']
            if 'config_version' in status_data:
                update_data['config_version'] = status_data['config_version']

        proxy.update_record(**update_data)
        return True

    @staticmethod
    def validate_license(db: DAL, proxy_id: int, license_valid: bool) -> bool:
        """Update proxy license validation status"""
        proxy = db.proxy_servers[proxy_id]
        if proxy:
            proxy.update_record(
                license_validated=license_valid,
                license_validation_at=datetime.utcnow()
            )
            return True
        return False

    @staticmethod
    def get_proxy_config(db: DAL, proxy_name: str, cluster_api_key: str) -> Optional[Dict[str, Any]]:
        """Get configuration for specific proxy"""
        from .cluster import ClusterModel

        # Validate cluster API key
        cluster_info = ClusterModel.validate_api_key(db, cluster_api_key)
        if not cluster_info:
            return None

        proxy = db(
            (db.proxy_servers.name == proxy_name) &
            (db.proxy_servers.cluster_id == cluster_info['cluster_id'])
        ).select().first()

        if not proxy:
            return None

        # Update config fetch timestamp
        proxy.update_record(last_config_fetch=datetime.utcnow())

        # Get cluster configuration
        cluster_config = ClusterModel.get_cluster_config(db, cluster_info['cluster_id'])
        if not cluster_config:
            return None

        return {
            'proxy': {
                'id': proxy.id,
                'name': proxy.name,
                'hostname': proxy.hostname,
                'cluster_id': proxy.cluster_id
            },
            'config': cluster_config,
            'config_version': f"{cluster_info['cluster_id']}_{datetime.utcnow().timestamp()}"
        }

    @staticmethod
    def cleanup_stale_proxies(db: DAL, timeout_minutes: int = 10) -> int:
        """Mark proxies as inactive if they haven't sent heartbeat"""
        cutoff_time = datetime.utcnow() - timedelta(minutes=timeout_minutes)
        return db(
            (db.proxy_servers.last_seen < cutoff_time) &
            (db.proxy_servers.status == 'active')
        ).update(status='inactive')

    @staticmethod
    def get_cluster_proxies(db: DAL, cluster_id: int) -> List[Dict[str, Any]]:
        """Get all proxies for a cluster"""
        proxies = db(db.proxy_servers.cluster_id == cluster_id).select()
        return [
            {
                'id': proxy.id,
                'name': proxy.name,
                'hostname': proxy.hostname,
                'ip_address': proxy.ip_address,
                'port': proxy.port,
                'status': proxy.status,
                'version': proxy.version,
                'license_validated': proxy.license_validated,
                'last_seen': proxy.last_seen,
                'registered_at': proxy.registered_at
            }
            for proxy in proxies
        ]

    @staticmethod
    def get_proxy_stats(db: DAL, cluster_id: int = None) -> Dict[str, Any]:
        """Get proxy statistics"""
        query = db.proxy_servers
        if cluster_id:
            query = db(db.proxy_servers.cluster_id == cluster_id)

        total = query.count()
        active = query(db.proxy_servers.status == 'active').count()
        inactive = query(db.proxy_servers.status == 'inactive').count()
        pending = query(db.proxy_servers.status == 'pending').count()

        return {
            'total': total,
            'active': active,
            'inactive': inactive,
            'pending': pending
        }


class ProxyMetricsModel:
    """Proxy metrics and performance tracking"""

    @staticmethod
    def define_table(db: DAL):
        """Define proxy metrics table"""
        return db.define_table(
            'proxy_metrics',
            Field('proxy_id', type='reference proxy_servers', required=True),
            Field('timestamp', type='datetime', default=datetime.utcnow),
            Field('cpu_usage', type='double'),
            Field('memory_usage', type='double'),
            Field('connections_active', type='integer'),
            Field('connections_total', type='integer'),
            Field('bytes_sent', type='bigint'),
            Field('bytes_received', type='bigint'),
            Field('requests_per_second', type='double'),
            Field('latency_avg', type='double'),
            Field('latency_p95', type='double'),
            Field('errors_per_second', type='double'),
            Field('metadata', type='json'),
        )

    @staticmethod
    def record_metrics(db: DAL, proxy_id: int, metrics: Dict[str, Any]) -> int:
        """Record proxy metrics"""
        return db.proxy_metrics.insert(
            proxy_id=proxy_id,
            cpu_usage=metrics.get('cpu_usage'),
            memory_usage=metrics.get('memory_usage'),
            connections_active=metrics.get('connections_active'),
            connections_total=metrics.get('connections_total'),
            bytes_sent=metrics.get('bytes_sent'),
            bytes_received=metrics.get('bytes_received'),
            requests_per_second=metrics.get('requests_per_second'),
            latency_avg=metrics.get('latency_avg'),
            latency_p95=metrics.get('latency_p95'),
            errors_per_second=metrics.get('errors_per_second'),
            metadata=metrics.get('metadata', {})
        )

    @staticmethod
    def get_metrics(db: DAL, proxy_id: int, hours: int = 24) -> List[Dict[str, Any]]:
        """Get metrics for proxy within time range"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        metrics = db(
            (db.proxy_metrics.proxy_id == proxy_id) &
            (db.proxy_metrics.timestamp > cutoff_time)
        ).select(orderby=db.proxy_metrics.timestamp)

        return [dict(metric) for metric in metrics]

    @staticmethod
    def cleanup_old_metrics(db: DAL, days: int = 30) -> int:
        """Clean up old metrics data"""
        cutoff_time = datetime.utcnow() - timedelta(days=days)
        return db(db.proxy_metrics.timestamp < cutoff_time).delete()


# Pydantic models for request/response validation
class ProxyRegistrationRequest(BaseModel):
    name: str
    hostname: str
    cluster_api_key: str
    ip_address: Optional[str] = None
    port: int = 8080
    version: Optional[str] = None
    capabilities: Optional[Dict[str, Any]] = None

    @validator('name')
    def validate_name(cls, v):
        if len(v) < 3:
            raise ValueError('Proxy name must be at least 3 characters long')
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError('Proxy name can only contain alphanumeric characters, hyphens, and underscores')
        return v.lower()

    @validator('port')
    def validate_port(cls, v):
        if v < 1 or v > 65535:
            raise ValueError('Port must be between 1 and 65535')
        return v

    @validator('hostname')
    def validate_hostname(cls, v):
        if len(v) < 1 or len(v) > 253:
            raise ValueError('Hostname must be between 1 and 253 characters')
        return v


class ProxyHeartbeatRequest(BaseModel):
    proxy_name: str
    cluster_api_key: str
    status: Optional[str] = 'active'
    version: Optional[str] = None
    capabilities: Optional[Dict[str, Any]] = None
    config_version: Optional[str] = None
    metrics: Optional[Dict[str, Any]] = None


class ProxyConfigRequest(BaseModel):
    proxy_name: str
    cluster_api_key: str


class ProxyResponse(BaseModel):
    id: int
    name: str
    hostname: str
    ip_address: str
    port: int
    cluster_id: int
    status: str
    version: Optional[str]
    license_validated: bool
    last_seen: Optional[datetime]
    registered_at: datetime


class ProxyStatsResponse(BaseModel):
    total: int
    active: int
    inactive: int
    pending: int


class ProxyMetricsResponse(BaseModel):
    proxy_id: int
    timestamp: datetime
    cpu_usage: Optional[float]
    memory_usage: Optional[float]
    connections_active: Optional[int]
    connections_total: Optional[int]
    bytes_sent: Optional[int]
    bytes_received: Optional[int]
    requests_per_second: Optional[float]
    latency_avg: Optional[float]
    latency_p95: Optional[float]
    errors_per_second: Optional[float]