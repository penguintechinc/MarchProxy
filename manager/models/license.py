"""
License validation and management models for MarchProxy Manager

Copyright (C) 2025 MarchProxy Contributors
Licensed under GNU Affero General Public License v3.0
"""

import httpx
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from pydal import DAL, Field
from pydantic import BaseModel, validator
import logging

logger = logging.getLogger(__name__)


class LicenseCacheModel:
    """License cache model for storing validation results"""

    @staticmethod
    def define_table(db: DAL):
        """Define license cache table"""
        return db.define_table(
            'license_cache',
            Field('license_key', type='string', unique=True, required=True, length=255),
            Field('validation_data', type='json'),
            Field('is_valid', type='boolean', default=False),
            Field('is_enterprise', type='boolean', default=False),
            Field('max_proxies', type='integer', default=3),
            Field('features', type='json'),
            Field('expires_at', type='datetime'),
            Field('last_validated', type='datetime', default=datetime.utcnow),
            Field('last_keepalive', type='datetime'),
            Field('keepalive_count', type='integer', default=0),
            Field('validation_count', type='integer', default=0),
            Field('error_message', type='text'),
        )

    @staticmethod
    def cache_validation(db: DAL, license_key: str, validation_data: Dict[str, Any],
                        is_valid: bool, expires_at: datetime = None) -> bool:
        """Cache license validation result"""
        # Extract enterprise features
        is_enterprise = validation_data.get('tier') == 'enterprise'
        max_proxies = validation_data.get('max_proxies', 3)
        features = validation_data.get('features', {})

        # Check if entry exists
        existing = db(db.license_cache.license_key == license_key).select().first()

        if existing:
            existing.update_record(
                validation_data=validation_data,
                is_valid=is_valid,
                is_enterprise=is_enterprise,
                max_proxies=max_proxies,
                features=features,
                expires_at=expires_at,
                last_validated=datetime.utcnow(),
                validation_count=existing.validation_count + 1,
                error_message=validation_data.get('error'),
                # Initialize keepalive timestamp for enterprise licenses
                last_keepalive=datetime.utcnow() if is_enterprise and is_valid else existing.last_keepalive
            )
        else:
            db.license_cache.insert(
                license_key=license_key,
                validation_data=validation_data,
                is_valid=is_valid,
                is_enterprise=is_enterprise,
                max_proxies=max_proxies,
                features=features,
                expires_at=expires_at,
                validation_count=1,
                error_message=validation_data.get('error'),
                # Initialize keepalive timestamp for enterprise licenses
                last_keepalive=datetime.utcnow() if is_enterprise and is_valid else None,
                keepalive_count=0
            )

        return True

    @staticmethod
    def get_cached_validation(db: DAL, license_key: str) -> Optional[Dict[str, Any]]:
        """Get cached license validation if still valid"""
        cache_entry = db(db.license_cache.license_key == license_key).select().first()

        if not cache_entry:
            return None

        # Check if cache is still valid (1 hour cache time)
        if cache_entry.last_validated < datetime.utcnow() - timedelta(hours=1):
            return None

        # CRITICAL: Check for missed keepalives (24 hour grace period)
        # If more than 24 hours since last keepalive, treat license as expired
        if cache_entry.is_enterprise and cache_entry.last_keepalive:
            keepalive_cutoff = datetime.utcnow() - timedelta(hours=24)
            if cache_entry.last_keepalive < keepalive_cutoff:
                logger.warning(f"License {license_key} expired due to missed keepalives (last: {cache_entry.last_keepalive})")
                return {
                    'is_valid': False,
                    'is_enterprise': False,
                    'max_proxies': 3,  # Fallback to community limits
                    'features': {},
                    'validation_data': {'error': 'License expired due to missed keepalives'},
                    'expires_at': cache_entry.expires_at,
                    'cached_at': cache_entry.last_validated,
                    'keepalive_expired': True
                }

        return {
            'is_valid': cache_entry.is_valid,
            'is_enterprise': cache_entry.is_enterprise,
            'max_proxies': cache_entry.max_proxies,
            'features': cache_entry.features,
            'validation_data': cache_entry.validation_data,
            'expires_at': cache_entry.expires_at,
            'cached_at': cache_entry.last_validated,
            'last_keepalive': cache_entry.last_keepalive,
            'keepalive_count': cache_entry.keepalive_count
        }

    @staticmethod
    def update_keepalive(db: DAL, license_key: str) -> bool:
        """Update keepalive timestamp for license"""
        cache_entry = db(db.license_cache.license_key == license_key).select().first()

        if cache_entry:
            cache_entry.update_record(
                last_keepalive=datetime.utcnow(),
                keepalive_count=cache_entry.keepalive_count + 1
            )
            return True

        return False

    @staticmethod
    def check_keepalive_health(db: DAL, license_key: str) -> Dict[str, Any]:
        """Check keepalive health status"""
        cache_entry = db(db.license_cache.license_key == license_key).select().first()

        if not cache_entry or not cache_entry.is_enterprise:
            return {'status': 'not_applicable', 'message': 'Community edition or no license'}

        if not cache_entry.last_keepalive:
            return {'status': 'warning', 'message': 'No keepalives sent yet'}

        now = datetime.utcnow()
        time_since_keepalive = now - cache_entry.last_keepalive

        if time_since_keepalive > timedelta(hours=24):
            return {
                'status': 'expired',
                'message': f'License expired due to missed keepalives (last: {cache_entry.last_keepalive})',
                'hours_since_keepalive': time_since_keepalive.total_seconds() / 3600
            }
        elif time_since_keepalive > timedelta(hours=20):
            return {
                'status': 'critical',
                'message': f'Keepalive critical - will expire in {24 - time_since_keepalive.total_seconds() / 3600:.1f} hours',
                'hours_since_keepalive': time_since_keepalive.total_seconds() / 3600
            }
        elif time_since_keepalive > timedelta(hours=12):
            return {
                'status': 'warning',
                'message': f'Keepalive warning - {time_since_keepalive.total_seconds() / 3600:.1f} hours since last keepalive',
                'hours_since_keepalive': time_since_keepalive.total_seconds() / 3600
            }
        else:
            return {
                'status': 'healthy',
                'message': f'Keepalive healthy - last sent {time_since_keepalive.total_seconds() / 3600:.1f} hours ago',
                'hours_since_keepalive': time_since_keepalive.total_seconds() / 3600,
                'keepalive_count': cache_entry.keepalive_count
            }


class LicenseValidator:
    """License validation service for Enterprise features"""

    def __init__(self, license_server_url: str = "https://license.penguintech.io"):
        self.license_server_url = license_server_url
        self.timeout = 30.0
        self.grace_period_hours = 24

    async def validate_license(self, db: DAL, license_key: str,
                              force_refresh: bool = False) -> Dict[str, Any]:
        """Validate license with license server"""
        # Check cache first unless forced refresh
        if not force_refresh:
            cached = LicenseCacheModel.get_cached_validation(db, license_key)
            if cached:
                return cached

        try:
            # Call license server API
            validation_result = await self._call_license_server(license_key)

            # Cache the result
            expires_at = None
            if validation_result.get('expires_at'):
                expires_at = datetime.fromisoformat(validation_result['expires_at'].replace('Z', '+00:00'))

            LicenseCacheModel.cache_validation(
                db, license_key, validation_result,
                validation_result.get('valid', False), expires_at
            )

            return {
                'is_valid': validation_result.get('valid', False),
                'is_enterprise': validation_result.get('tier') == 'enterprise',
                'max_proxies': validation_result.get('max_proxies', 3),
                'features': validation_result.get('features', {}),
                'validation_data': validation_result,
                'expires_at': expires_at
            }

        except Exception as e:
            logger.error(f"License validation failed: {e}")

            # During grace period, use last known good validation
            cached = db(db.license_cache.license_key == license_key).select().first()
            if cached and cached.is_valid:
                grace_cutoff = datetime.utcnow() - timedelta(hours=self.grace_period_hours)
                if cached.last_validated > grace_cutoff:
                    logger.warning(f"Using cached license validation during grace period")
                    return {
                        'is_valid': cached.is_valid,
                        'is_enterprise': cached.is_enterprise,
                        'max_proxies': cached.max_proxies,
                        'features': cached.features,
                        'validation_data': cached.validation_data,
                        'expires_at': cached.expires_at,
                        'grace_period': True
                    }

            # Cache the failure
            error_data = {'error': str(e), 'valid': False}
            LicenseCacheModel.cache_validation(db, license_key, error_data, False)

            return {
                'is_valid': False,
                'is_enterprise': False,
                'max_proxies': 3,
                'features': {},
                'error': str(e)
            }

    async def _call_license_server(self, license_key: str) -> Dict[str, Any]:
        """Call license server for validation using v2 API"""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.license_server_url}/api/v2/validate",
                json={
                    'product': 'marchproxy'
                },
                headers={
                    'Authorization': f'Bearer {license_key}',
                    'Content-Type': 'application/json',
                    'User-Agent': 'MarchProxy-Manager/1.0'
                }
            )

            if response.status_code == 200:
                data = response.json()
                # Convert v2 API response to our internal format
                return {
                    'valid': data.get('valid', False),
                    'tier': data.get('tier', 'community'),
                    'max_proxies': data.get('limits', {}).get('max_servers', 3),
                    'features': self._convert_features_to_dict(data.get('features', [])),
                    'expires_at': data.get('expires_at'),
                    'customer': data.get('customer'),
                    'license_version': data.get('license_version'),
                    'raw_response': data
                }
            elif response.status_code == 404:
                return {'valid': False, 'error': 'License not found, inactive, or expired'}
            elif response.status_code == 403:
                data = response.json()
                return {
                    'valid': False,
                    'error': data.get('message', 'Product not included in license'),
                    'available_products': data.get('available_products', [])
                }
            elif response.status_code == 400:
                data = response.json()
                return {'valid': False, 'error': data.get('message', 'Bad request')}
            else:
                response.raise_for_status()

    def _convert_features_to_dict(self, features_list: List[Dict]) -> Dict[str, bool]:
        """Convert v2 API features list to feature dict"""
        features_dict = {}
        for feature in features_list:
            feature_name = feature.get('name', '')
            entitled = feature.get('entitled', False)
            features_dict[feature_name] = entitled
        return features_dict

    def check_feature_enabled(self, license_data: Dict[str, Any], feature: str) -> bool:
        """Check if specific feature is enabled in license"""
        if not license_data.get('is_valid', False):
            return False

        # Community features always available
        community_features = {
            'basic_proxy', 'tcp_proxy', 'udp_proxy', 'icmp_proxy',
            'basic_auth', 'api_tokens', 'single_cluster'
        }

        if feature in community_features:
            return True

        # Enterprise features require valid enterprise license
        if not license_data.get('is_enterprise', False):
            return False

        features = license_data.get('features', {})
        return features.get(feature, False)

    def get_proxy_limit(self, license_data: Dict[str, Any]) -> int:
        """Get maximum proxy count from license"""
        if not license_data.get('is_valid', False):
            return 3  # Community default

        return license_data.get('max_proxies', 3)

    def enforce_proxy_limits(self, db: DAL, license_key: str) -> bool:
        """Enforce proxy count limits across all clusters"""
        from .proxy import ProxyServerModel

        # Get license validation
        license_data = LicenseCacheModel.get_cached_validation(db, license_key)
        if not license_data:
            return False

        max_proxies = self.get_proxy_limit(license_data)

        # Count active proxies across all clusters
        active_proxies = db(
            (db.proxy_servers.status == 'active') &
            (db.proxy_servers.last_seen > datetime.utcnow() - timedelta(minutes=5))
        ).count()

        return active_proxies <= max_proxies


class LicenseManager:
    """License management for MarchProxy deployment"""

    def __init__(self, db: DAL, license_key: str = None):
        self.db = db
        self.license_key = license_key
        self.validator = LicenseValidator()
        self.server_id = None
        import time
        self._start_time = time.time()

    async def get_license_status(self) -> Dict[str, Any]:
        """Get current license status"""
        if not self.license_key:
            # Community edition
            active_proxies = self.db(
                (self.db.proxy_servers.status == 'active') &
                (self.db.proxy_servers.last_seen > datetime.utcnow() - timedelta(minutes=5))
            ).count()

            return {
                'valid': True,
                'tier': 'community',
                'edition': 'Community',
                'is_enterprise': False,
                'max_proxies': 3,
                'active_proxies': active_proxies,
                'features': {},
                'license_configured': False
            }

        # Get enterprise license validation
        license_data = await self.validator.validate_license(self.db, self.license_key)

        # Store server_id for keepalives
        if license_data.get('validation_data', {}).get('metadata', {}).get('server_id'):
            self.server_id = license_data['validation_data']['metadata']['server_id']

        # Count active proxies
        active_proxies = self.db(
            (self.db.proxy_servers.status == 'active') &
            (self.db.proxy_servers.last_seen > datetime.utcnow() - timedelta(minutes=5))
        ).count()

        return {
            'valid': license_data.get('is_valid', False),
            'tier': 'enterprise' if license_data.get('is_enterprise') else 'community',
            'edition': 'Enterprise' if license_data.get('is_enterprise') else 'Community',
            'is_enterprise': license_data.get('is_enterprise', False),
            'max_proxies': license_data.get('max_proxies', 3),
            'active_proxies': active_proxies,
            'features': license_data.get('features', {}),
            'expires_at': license_data.get('expires_at'),
            'license_configured': True,
            'error': license_data.get('error'),
            'grace_period': license_data.get('grace_period', False),
            'server_id': self.server_id,
            'customer': license_data.get('validation_data', {}).get('customer'),
            'license_version': license_data.get('validation_data', {}).get('license_version')
        }

    def get_license_status_sync(self) -> Dict[str, Any]:
        """Get current license status synchronously (for non-async contexts)"""
        if not self.license_key:
            # Community edition
            active_proxies = self.db(
                (self.db.proxy_servers.status == 'active') &
                (self.db.proxy_servers.last_seen > datetime.utcnow() - timedelta(minutes=5))
            ).count()

            return {
                'valid': True,
                'tier': 'community',
                'edition': 'Community',
                'is_enterprise': False,
                'max_proxies': 3,
                'active_proxies': active_proxies,
                'features': {},
                'license_configured': False
            }

        # Get cached license data only (no validation)
        license_data = LicenseCacheModel.get_cached_validation(self.db, self.license_key)
        if not license_data:
            license_data = {
                'is_valid': False,
                'is_enterprise': False,
                'max_proxies': 3,
                'features': {},
                'error': 'License not validated yet'
            }

        # Count active proxies
        active_proxies = self.db(
            (self.db.proxy_servers.status == 'active') &
            (self.db.proxy_servers.last_seen > datetime.utcnow() - timedelta(minutes=5))
        ).count()

        return {
            'valid': license_data.get('is_valid', False),
            'tier': 'enterprise' if license_data.get('is_enterprise') else 'community',
            'edition': 'Enterprise' if license_data.get('is_enterprise') else 'Community',
            'is_enterprise': license_data.get('is_enterprise', False),
            'max_proxies': license_data.get('max_proxies', 3),
            'active_proxies': active_proxies,
            'features': license_data.get('features', {}),
            'expires_at': license_data.get('expires_at'),
            'license_configured': True,
            'error': license_data.get('error')
        }

    async def check_proxy_registration(self, cluster_id: int) -> bool:
        """Check if new proxy can be registered"""
        if not self.license_key:
            # Community edition - check cluster limit
            from .cluster import ClusterModel
            return ClusterModel.check_proxy_limit(self.db, cluster_id)

        # Enterprise edition - check global limit
        license_status = await self.get_license_status()
        if not license_status['valid']:
            return False

        active_proxies = license_status['active_proxies']
        max_proxies = license_status['max_proxies']

        return active_proxies < max_proxies

    async def get_available_features(self) -> List[str]:
        """Get list of available features based on license"""
        if not self.license_key:
            return [
                'basic_proxy', 'tcp_proxy', 'udp_proxy', 'icmp_proxy',
                'basic_auth', 'api_tokens', 'single_cluster'
            ]

        license_status = await self.get_license_status()
        if not license_status['valid']:
            return []

        features = license_status.get('features', {})
        available = [
            'basic_proxy', 'tcp_proxy', 'udp_proxy', 'icmp_proxy',
            'basic_auth', 'api_tokens', 'single_cluster'
        ]

        # Add enterprise features if enabled
        enterprise_features = [
            'unlimited_proxies', 'multi_cluster', 'saml_authentication',
            'oauth2_authentication', 'scim_provisioning', 'advanced_routing',
            'load_balancing', 'health_checks', 'metrics_advanced'
        ]

        for feature in enterprise_features:
            if features.get(feature, False):
                available.append(feature)

        return available

    async def check_feature_enabled(self, feature: str) -> bool:
        """Check if specific feature is enabled"""
        # Community features always available
        community_features = {
            'basic_proxy', 'tcp_proxy', 'udp_proxy', 'icmp_proxy',
            'basic_auth', 'api_tokens', 'single_cluster'
        }

        if feature in community_features:
            return True

        # Enterprise features require valid license
        if not self.license_key:
            return False

        license_status = await self.get_license_status()
        if not license_status['valid'] or not license_status['is_enterprise']:
            return False

        features = license_status.get('features', {})
        return features.get(feature, False)

    async def validate_license_key(self, license_key: str, force_refresh: bool = False) -> Dict[str, Any]:
        """Validate a specific license key"""
        return await self.validator.validate_license(self.db, license_key, force_refresh)

    async def check_feature_with_server(self, feature: str) -> Dict[str, Any]:
        """Check specific feature with license server"""
        if not self.license_key:
            return {'entitled': False, 'error': 'No license key configured'}

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.validator.license_server_url}/api/v2/features",
                    json={
                        'product': 'marchproxy',
                        'feature': feature
                    },
                    headers={
                        'Authorization': f'Bearer {self.license_key}',
                        'Content-Type': 'application/json',
                        'User-Agent': 'MarchProxy-Manager/1.0'
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    features = data.get('features', [])
                    if features:
                        feature_data = features[0]
                        return {
                            'entitled': feature_data.get('entitled', False),
                            'units': feature_data.get('units', 0),
                            'description': feature_data.get('description', ''),
                            'metadata': feature_data.get('metadata', {})
                        }

                return {'entitled': False, 'error': 'Feature not found in response'}

        except Exception as e:
            logger.error(f"Feature check failed: {e}")
            return {'entitled': False, 'error': str(e)}

    async def send_keepalive(self, hostname: str = None, version: str = "1.0.0",
                           usage_stats: Dict[str, Any] = None) -> bool:
        """Send keepalive to license server"""
        if not self.license_key:
            return True  # Community edition doesn't need keepalive

        # Get server_id if we don't have it
        if not self.server_id:
            license_status = await self.get_license_status()
            if not license_status.get('valid'):
                return False

        try:
            import time
            import socket

            if not hostname:
                hostname = socket.gethostname()

            uptime_seconds = int(time.time() - self._start_time)

            # Collect usage statistics
            if not usage_stats:
                usage_stats = self._collect_usage_stats()

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.validator.license_server_url}/api/v2/keepalive",
                    json={
                        'product': 'marchproxy',
                        'server_id': self.server_id,
                        'hostname': hostname,
                        'version': version,
                        'uptime_seconds': uptime_seconds,
                        'usage_stats': usage_stats
                    },
                    headers={
                        'Authorization': f'Bearer {self.license_key}',
                        'Content-Type': 'application/json',
                        'User-Agent': 'MarchProxy-Manager/1.0'
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    logger.info("License keepalive sent successfully")
                    logger.debug(f"Next keepalive suggested: {data.get('metadata', {}).get('next_keepalive_suggested')}")

                    # Update keepalive timestamp in cache
                    LicenseCacheModel.update_keepalive(self.db, self.license_key)

                    return True
                else:
                    logger.warning(f"License keepalive failed: {response.status_code}")
                    return False

        except Exception as e:
            logger.error(f"License keepalive failed: {e}")
            return False

    def _collect_usage_stats(self) -> Dict[str, Any]:
        """Collect usage statistics for keepalive"""
        try:
            # Count active users
            active_users = self.db(self.db.auth_user.id > 0).count()

            # Count active proxies
            active_proxies = self.db(
                (self.db.proxy_servers.status == 'active') &
                (self.db.proxy_servers.last_seen > datetime.utcnow() - timedelta(minutes=5))
            ).count()

            # Count clusters
            active_clusters = self.db(self.db.clusters.is_active == True).count()

            # Count services
            active_services = self.db(self.db.services.is_active == True).count()

            return {
                'active_users': active_users,
                'active_proxies': active_proxies,
                'active_clusters': active_clusters,
                'active_services': active_services,
                'feature_usage': {
                    'multi_cluster': active_clusters > 1,
                    'user_management': active_users > 1,
                    'proxy_management': active_proxies > 0
                }
            }
        except Exception as e:
            logger.error(f"Failed to collect usage stats: {e}")
            return {}

    def schedule_keepalive(self, interval_hours: int = 1):
        """Schedule periodic keepalive reports"""
        if not self.license_key:
            return  # Community edition doesn't need keepalive

        import threading
        import time

        def keepalive_worker():
            while True:
                try:
                    # Use asyncio.run for the async keepalive
                    import asyncio
                    asyncio.run(self.send_keepalive())
                except Exception as e:
                    logger.error(f"Scheduled keepalive failed: {e}")

                time.sleep(interval_hours * 3600)  # Convert hours to seconds

        thread = threading.Thread(target=keepalive_worker, daemon=True)
        thread.start()
        logger.info(f"Scheduled keepalive every {interval_hours} hour(s)")

    def get_keepalive_health(self) -> Dict[str, Any]:
        """Get keepalive health status"""
        if not self.license_key:
            return {'status': 'not_applicable', 'message': 'Community edition'}

        return LicenseCacheModel.check_keepalive_health(self.db, self.license_key)


# Pydantic models for request/response validation
class LicenseValidationRequest(BaseModel):
    license_key: str
    force_refresh: bool = False

    @validator('license_key')
    def validate_license_key(cls, v):
        if not v.startswith('PENG-'):
            raise ValueError('License key must start with PENG-')
        if len(v) != 29:  # PENG-XXXX-XXXX-XXXX-XXXX-ABCD
            raise ValueError('License key must be in format PENG-XXXX-XXXX-XXXX-XXXX-ABCD')
        return v.upper()


class LicenseResponse(BaseModel):
    is_valid: bool
    tier: str
    is_enterprise: bool
    max_proxies: int
    features: Dict[str, bool]
    expires_at: Optional[datetime]
    validated_at: datetime
    grace_period: bool = False


class LicenseStatusResponse(BaseModel):
    license_configured: bool
    tier: str
    is_valid: bool
    max_proxies: int
    active_proxies: int
    features_available: List[str]
    expires_at: Optional[datetime]
    last_validated: Optional[datetime]