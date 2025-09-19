"""
Rate limiting models for MarchProxy Manager

Copyright (C) 2025 MarchProxy Contributors
Licensed under GNU Affero General Public License v3.0
"""

import time
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from pydal import DAL, Field
import logging

logger = logging.getLogger(__name__)


class RateLimitModel:
    """Rate limiting model for API endpoints"""

    @staticmethod
    def define_table(db: DAL):
        """Define rate limit table in database"""
        return db.define_table(
            'rate_limits',
            Field('client_id', type='string', required=True, length=255),  # IP or user ID
            Field('endpoint', type='string', required=True, length=255),
            Field('request_count', type='integer', default=0),
            Field('window_start', type='datetime', required=True),
            Field('last_request', type='datetime', default=datetime.utcnow),
            Field('is_blocked', type='boolean', default=False),
            Field('block_until', type='datetime'),
            Field('metadata', type='json'),
        )

    @staticmethod
    def check_rate_limit(db: DAL, client_id: str, endpoint: str,
                        max_requests: int = 100, window_minutes: int = 60,
                        block_duration_minutes: int = 15) -> Tuple[bool, Dict[str, Any]]:
        """Check if client is within rate limits"""
        now = datetime.utcnow()
        window_start = now - timedelta(minutes=window_minutes)

        # Get or create rate limit record
        existing = db(
            (db.rate_limits.client_id == client_id) &
            (db.rate_limits.endpoint == endpoint)
        ).select().first()

        if not existing:
            # Create new record
            db.rate_limits.insert(
                client_id=client_id,
                endpoint=endpoint,
                request_count=1,
                window_start=now,
                last_request=now
            )
            return True, {
                'allowed': True,
                'requests_remaining': max_requests - 1,
                'window_reset': (now + timedelta(minutes=window_minutes)).isoformat(),
                'retry_after': None
            }

        # Check if currently blocked
        if existing.is_blocked and existing.block_until and existing.block_until > now:
            return False, {
                'allowed': False,
                'error': 'Rate limit exceeded',
                'requests_remaining': 0,
                'retry_after': existing.block_until.isoformat(),
                'window_reset': existing.block_until.isoformat()
            }

        # Check if window has expired
        if existing.window_start < window_start:
            # Reset window
            existing.update_record(
                request_count=1,
                window_start=now,
                last_request=now,
                is_blocked=False,
                block_until=None
            )
            return True, {
                'allowed': True,
                'requests_remaining': max_requests - 1,
                'window_reset': (now + timedelta(minutes=window_minutes)).isoformat(),
                'retry_after': None
            }

        # Check rate limit
        if existing.request_count >= max_requests:
            # Block client
            block_until = now + timedelta(minutes=block_duration_minutes)
            existing.update_record(
                is_blocked=True,
                block_until=block_until,
                last_request=now
            )
            return False, {
                'allowed': False,
                'error': 'Rate limit exceeded',
                'requests_remaining': 0,
                'retry_after': block_until.isoformat(),
                'window_reset': block_until.isoformat()
            }

        # Increment counter
        existing.update_record(
            request_count=existing.request_count + 1,
            last_request=now
        )

        return True, {
            'allowed': True,
            'requests_remaining': max_requests - existing.request_count,
            'window_reset': (existing.window_start + timedelta(minutes=window_minutes)).isoformat(),
            'retry_after': None
        }

    @staticmethod
    def cleanup_old_records(db: DAL, cleanup_hours: int = 24):
        """Clean up old rate limit records"""
        cutoff = datetime.utcnow() - timedelta(hours=cleanup_hours)
        deleted = db(
            (db.rate_limits.last_request < cutoff) &
            ((db.rate_limits.is_blocked == False) |
             (db.rate_limits.block_until < datetime.utcnow()))
        ).delete()
        return deleted

    @staticmethod
    def get_client_stats(db: DAL, client_id: str) -> Dict[str, Any]:
        """Get rate limiting stats for a client"""
        records = db(db.rate_limits.client_id == client_id).select()

        stats = {
            'client_id': client_id,
            'endpoints': [],
            'total_requests': 0,
            'blocked_endpoints': 0
        }

        for record in records:
            endpoint_stats = {
                'endpoint': record.endpoint,
                'request_count': record.request_count,
                'window_start': record.window_start,
                'last_request': record.last_request,
                'is_blocked': record.is_blocked,
                'block_until': record.block_until
            }
            stats['endpoints'].append(endpoint_stats)
            stats['total_requests'] += record.request_count

            if record.is_blocked:
                stats['blocked_endpoints'] += 1

        return stats


class RateLimitManager:
    """Rate limiting manager with different policies"""

    def __init__(self, db: DAL):
        self.db = db
        self.policies = {
            # General API endpoints
            'api_general': {'max_requests': 1000, 'window_minutes': 60, 'block_minutes': 15},

            # Authentication endpoints (more restrictive)
            'api_auth': {'max_requests': 30, 'window_minutes': 15, 'block_minutes': 30},

            # Admin endpoints
            'api_admin': {'max_requests': 500, 'window_minutes': 60, 'block_minutes': 10},

            # Proxy endpoints (high volume)
            'api_proxy': {'max_requests': 10000, 'window_minutes': 60, 'block_minutes': 5},

            # License endpoints
            'api_license': {'max_requests': 100, 'window_minutes': 60, 'block_minutes': 30},
        }

    def check_limit(self, client_id: str, endpoint: str, endpoint_type: str = 'api_general') -> Tuple[bool, Dict[str, Any]]:
        """Check rate limit using predefined policies"""
        policy = self.policies.get(endpoint_type, self.policies['api_general'])

        return RateLimitModel.check_rate_limit(
            self.db,
            client_id,
            endpoint,
            max_requests=policy['max_requests'],
            window_minutes=policy['window_minutes'],
            block_duration_minutes=policy['block_minutes']
        )

    def get_client_identifier(self, request, user=None) -> str:
        """Get unique client identifier for rate limiting"""
        if user and user.get('id'):
            return f"user:{user['id']}"

        # Fall back to IP address
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return f"ip:{forwarded_for.split(',')[0].strip()}"

        remote_addr = request.headers.get('X-Real-IP') or request.environ.get('REMOTE_ADDR', 'unknown')
        return f"ip:{remote_addr}"

    def get_endpoint_type(self, path: str) -> str:
        """Determine endpoint type for rate limiting policy"""
        if '/api/auth/' in path:
            return 'api_auth'
        elif '/api/proxy/' in path:
            return 'api_proxy'
        elif '/api/license/' in path:
            return 'api_license'
        elif any(admin_path in path for admin_path in ['/api/clusters', '/api/users']):
            return 'api_admin'
        else:
            return 'api_general'


def rate_limit_fixture(endpoint_type: str = 'api_general'):
    """py4web fixture for rate limiting"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            from py4web import request, response

            # Get rate limit manager from globals
            if 'rate_limit_manager' not in globals():
                # Skip rate limiting if not configured
                return func(*args, **kwargs)

            rate_manager = globals()['rate_limit_manager']

            # Get client identifier
            user = None
            if hasattr(request, 'user') and request.user:
                user = request.user

            client_id = rate_manager.get_client_identifier(request, user)
            endpoint = request.path

            # Check rate limit
            allowed, limit_info = rate_manager.check_limit(client_id, endpoint, endpoint_type)

            # Add rate limit headers
            if limit_info.get('requests_remaining') is not None:
                response.headers['X-RateLimit-Remaining'] = str(limit_info['requests_remaining'])
            if limit_info.get('window_reset'):
                response.headers['X-RateLimit-Reset'] = limit_info['window_reset']

            if not allowed:
                response.status = 429
                if limit_info.get('retry_after'):
                    response.headers['Retry-After'] = limit_info['retry_after']

                return {
                    'error': 'Rate limit exceeded',
                    'message': limit_info.get('error', 'Too many requests'),
                    'retry_after': limit_info.get('retry_after')
                }

            return func(*args, **kwargs)

        return wrapper
    return decorator