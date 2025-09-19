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
                error_message=validation_data.get('error')
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
                error_message=validation_data.get('error')
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

        return {
            'is_valid': cache_entry.is_valid,
            'is_enterprise': cache_entry.is_enterprise,
            'max_proxies': cache_entry.max_proxies,
            'features': cache_entry.features,
            'validation_data': cache_entry.validation_data,
            'expires_at': cache_entry.expires_at,
            'cached_at': cache_entry.last_validated
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
        """Call license server for validation"""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.license_server_url}/api/v1/validate",
                json={
                    'license_key': license_key,
                    'product': 'marchproxy'
                },
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'MarchProxy-Manager/1.0'
                }
            )

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {'valid': False, 'error': 'License key not found'}
            elif response.status_code == 403:
                return {'valid': False, 'error': 'License key expired or invalid'}
            else:
                response.raise_for_status()

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

    async def initialize(self) -> Dict[str, Any]:
        """Initialize license system and validate key"""
        if not self.license_key:
            # Community edition
            return {
                'tier': 'community',
                'is_valid': True,
                'is_enterprise': False,
                'max_proxies': 3,
                'features': {}
            }

        # Validate enterprise license
        return await self.validator.validate_license(self.db, self.license_key)

    async def check_proxy_registration(self, cluster_id: int) -> bool:
        """Check if new proxy can be registered"""
        if not self.license_key:
            # Community edition - check cluster limit
            from .cluster import ClusterModel
            return ClusterModel.check_proxy_limit(self.db, cluster_id)

        # Enterprise edition - check global limit
        license_data = await self.validator.validate_license(self.db, self.license_key)
        return self.validator.enforce_proxy_limits(self.db, self.license_key)

    def get_available_features(self) -> List[str]:
        """Get list of available features based on license"""
        if not self.license_key:
            return [
                'basic_proxy', 'tcp_proxy', 'udp_proxy', 'icmp_proxy',
                'basic_auth', 'api_tokens', 'single_cluster'
            ]

        # Get cached license data
        license_data = LicenseCacheModel.get_cached_validation(self.db, self.license_key)
        if not license_data or not license_data['is_valid']:
            return []

        features = license_data.get('features', {})
        available = []

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