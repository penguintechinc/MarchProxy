"""
MarchProxy Manager Application using py4web native features

Copyright (C) 2025 MarchProxy Contributors
Licensed under GNU Affero General Public License v3.0
"""

import os
import sys
from py4web import action, request, response, abort, redirect, URL
from py4web.utils.cors import CORS
from py4web.utils.auth import Auth
from pydal import DAL, Field
import logging
from datetime import datetime
import json

# Add the manager directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import native auth setup
from models.auth_native import (
    setup_auth, extend_auth_user_table, TOTPManager, APITokenManager,
    create_admin_user, setup_auth_groups, check_permission, require_admin, require_permission
)

# Import existing models (updated to work with py4web auth)
from models.cluster import ClusterModel, UserClusterAssignmentModel
from models.proxy import ProxyServerModel, ProxyMetricsModel
from models.license import LicenseCacheModel, LicenseManager
from models.service import ServiceModel, UserServiceAssignmentModel
from models.mapping import MappingModel
from models.certificate import CertificateModel
from models.rate_limiting import RateLimitModel, RateLimitManager
from models.syslog_client import ClusterSyslogManager
from models.structured_logging import structured_logger, get_structured_logger, log_api_request

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.environ.get(
    'DATABASE_URL',
    'postgres://marchproxy:password@localhost:5432/marchproxy'
)

# Initialize database
db = DAL(DATABASE_URL, pool_size=10, migrate=True, fake_migrate=False)

# Setup py4web native authentication
BASE_URL = os.environ.get('BASE_URL', 'http://localhost:8000')
auth = setup_auth(db, BASE_URL)

# Extend auth_user table with custom fields
extend_auth_user_table(auth)

# Define business logic tables (referencing auth_user)
ClusterModel.define_table(db)
UserClusterAssignmentModel.define_table(db)
ProxyServerModel.define_table(db)
ProxyMetricsModel.define_table(db)
LicenseCacheModel.define_table(db)
ServiceModel.define_table(db)
UserServiceAssignmentModel.define_table(db)
MappingModel.define_table(db)
CertificateModel.define_table(db)
RateLimitModel.define_table(db)

# Commit database changes
db.commit()

# Initialize managers
totp_manager = TOTPManager(auth)
token_manager = APITokenManager(auth)

# Initialize license manager
LICENSE_KEY = os.environ.get('LICENSE_KEY')
license_manager = LicenseManager(db, LICENSE_KEY)

# Initialize rate limit manager
rate_limit_manager = RateLimitManager(db)

# Initialize syslog manager
syslog_manager = ClusterSyslogManager(db)

# Setup auth groups and permissions
groups = setup_auth_groups(auth)


# Authentication endpoints using py4web native features
@action('/auth/<path:path>')
@action.uses(auth, CORS())
def auth_handler(path):
    """Handle py4web native auth endpoints"""
    return auth.navbar


@action('/api/auth/profile', methods=['GET', 'PUT'])
@action.uses(auth, auth.user, CORS())
def profile():
    """Get/update user profile"""
    user = auth.get_user()

    if request.method == 'GET':
        return {
            'id': user['id'],
            'email': user['email'],
            'first_name': user.get('first_name', ''),
            'last_name': user.get('last_name', ''),
            'is_admin': user.get('is_admin', False),
            'totp_enabled': user.get('totp_enabled', False),
            'auth_provider': user.get('auth_provider', 'local'),
            'last_login': user.get('last_login'),
            'created_on': user.get('created_on')
        }

    elif request.method == 'PUT':
        data = request.json
        update_data = {}

        # Allow updating profile fields
        if 'first_name' in data:
            update_data['first_name'] = data['first_name']
        if 'last_name' in data:
            update_data['last_name'] = data['last_name']

        # Handle password change
        if 'new_password' in data:
            current_password = data.get('current_password')
            if not current_password:
                response.status = 400
                return {'error': 'Current password required'}

            user_record = db.auth_user[user['id']]
            if not auth.verify_password(current_password, user_record.password):
                response.status = 401
                return {'error': 'Invalid current password'}

            # Use py4web's password hashing
            update_data['password'] = auth.get_or_create_user({'password': data['new_password']})['password']

        if update_data:
            db.auth_user[user['id']].update_record(**update_data)

        return {'message': 'Profile updated successfully'}


@action('/api/auth/2fa/enable', methods=['POST'])
@action.uses(auth, auth.user, CORS())

def enable_2fa():
    """Enable 2FA for current user"""
    user = auth.get_user()
    data = request.json

    result = totp_manager.enable_2fa(user['id'], data.get('password', ''))
    if not result:
        response.status = 401
        return {'error': 'Invalid password'}

    return {
        'secret': result['secret'],
        'qr_uri': result['qr_uri'],
        'qr_code': result['qr_code'],
        'message': 'Scan QR code and verify with TOTP code to complete setup'
    }


@action('/api/auth/2fa/verify', methods=['POST'])
@action.uses(auth, auth.user, CORS())

def verify_2fa():
    """Complete 2FA setup"""
    user = auth.get_user()
    data = request.json

    success = totp_manager.verify_and_complete_2fa(
        user['id'], data.get('secret', ''), data.get('totp_code', '')
    )

    if not success:
        response.status = 400
        return {'error': 'Invalid TOTP code or secret'}

    return {'message': '2FA enabled successfully'}


@action('/api/auth/2fa/disable', methods=['POST'])
@action.uses(auth, auth.user, CORS())

def disable_2fa():
    """Disable 2FA for current user"""
    user = auth.get_user()
    data = request.json

    success = totp_manager.disable_2fa(
        user['id'], data.get('password', ''), data.get('totp_code')
    )

    if not success:
        response.status = 400
        return {'error': 'Invalid password or TOTP code'}

    return {'message': '2FA disabled successfully'}


# API Token management
@action('/api/auth/tokens', methods=['GET', 'POST'])
@action.uses(auth, auth.user, CORS())

def api_tokens():
    """Manage API tokens"""
    user = auth.get_user()

    if request.method == 'GET':
        tokens = db(
            (db.api_tokens.user_id == user['id']) &
            (db.api_tokens.is_active == True)
        ).select()

        return {
            'tokens': [
                {
                    'id': token.id,
                    'token_id': token.token_id,
                    'name': token.name,
                    'created_at': token.created_at,
                    'expires_at': token.expires_at,
                    'last_used': token.last_used
                }
                for token in tokens
            ]
        }

    elif request.method == 'POST':
        data = request.json
        token, token_id = token_manager.create_token(
            user['id'],
            data.get('name', 'API Token'),
            data.get('permissions', {}),
            data.get('ttl_days')
        )

        return {
            'token': token,
            'token_id': token_id,
            'message': 'API token created successfully'
        }


# Cluster management using py4web auth
@action('/api/clusters', methods=['GET', 'POST'])
@action.uses(auth, auth.user, CORS())

def clusters():
    """Cluster management"""
    user = auth.get_user()

    if request.method == 'GET':
        if user.get('is_admin'):
            # Admin sees all clusters
            clusters = db(db.clusters.is_active == True).select(orderby=db.clusters.name)
        else:
            # Regular user sees only assigned clusters
            user_clusters = UserClusterAssignmentModel.get_user_clusters(db, user['id'])
            cluster_ids = [uc['cluster_id'] for uc in user_clusters]
            clusters = db(
                (db.clusters.id.belongs(cluster_ids)) &
                (db.clusters.is_active == True)
            ).select(orderby=db.clusters.name)

        result = []
        for cluster in clusters:
            active_proxies = ClusterModel.count_active_proxies(db, cluster.id)
            result.append({
                'id': cluster.id,
                'name': cluster.name,
                'description': cluster.description,
                'syslog_endpoint': cluster.syslog_endpoint,
                'log_auth': cluster.log_auth,
                'log_netflow': cluster.log_netflow,
                'log_debug': cluster.log_debug,
                'is_active': cluster.is_active,
                'is_default': cluster.is_default,
                'max_proxies': cluster.max_proxies,
                'active_proxies': active_proxies,
                'created_at': cluster.created_at,
                'updated_at': cluster.updated_at
            })

        return {'clusters': result}

    elif request.method == 'POST':
        # Only admins can create clusters
        if not check_permission(auth, 'create_clusters'):
            abort(403)

        data = request.json

        try:
            cluster_id, api_key = ClusterModel.create_cluster(
                db,
                name=data['name'],
                description=data.get('description'),
                created_by=user['id'],
                syslog_endpoint=data.get('syslog_endpoint'),
                log_auth=data.get('log_auth', True),
                log_netflow=data.get('log_netflow', True),
                log_debug=data.get('log_debug', False),
                max_proxies=data.get('max_proxies', 3)
            )

            cluster = db.clusters[cluster_id]
            return {
                'cluster': {
                    'id': cluster.id,
                    'name': cluster.name,
                    'description': cluster.description,
                    'is_active': cluster.is_active,
                    'created_at': cluster.created_at
                },
                'api_key': api_key,
                'message': 'Cluster created successfully'
            }

        except Exception as e:
            logger.error(f"Cluster creation failed: {e}")
            response.status = 500
            return {'error': 'Failed to create cluster'}


@action('/api/clusters/<cluster_id:int>', methods=['GET', 'PUT', 'DELETE'])
@action.uses(auth, auth.user, CORS())

def cluster_detail(cluster_id):
    """Individual cluster management"""
    user = auth.get_user()

    # Check access permissions
    if not user.get('is_admin'):
        user_role = UserClusterAssignmentModel.check_user_cluster_access(db, user['id'], cluster_id)
        if not user_role:
            abort(403)

    cluster = db.clusters[cluster_id]
    if not cluster:
        abort(404)

    if request.method == 'GET':
        active_proxies = ClusterModel.count_active_proxies(db, cluster_id)
        return {
            'cluster': {
                'id': cluster.id,
                'name': cluster.name,
                'description': cluster.description,
                'syslog_endpoint': cluster.syslog_endpoint,
                'log_auth': cluster.log_auth,
                'log_netflow': cluster.log_netflow,
                'log_debug': cluster.log_debug,
                'is_active': cluster.is_active,
                'is_default': cluster.is_default,
                'max_proxies': cluster.max_proxies,
                'active_proxies': active_proxies,
                'created_at': cluster.created_at,
                'updated_at': cluster.updated_at
            }
        }

    elif request.method == 'PUT':
        # Only admins can update clusters
        if not check_permission(auth, 'update_clusters'):
            abort(403)

        data = request.json
        update_data = {'updated_at': datetime.utcnow()}

        # Update allowed fields
        if 'name' in data:
            update_data['name'] = data['name']
        if 'description' in data:
            update_data['description'] = data['description']
        if 'syslog_endpoint' in data:
            update_data['syslog_endpoint'] = data['syslog_endpoint']
        if 'log_auth' in data:
            update_data['log_auth'] = data['log_auth']
        if 'log_netflow' in data:
            update_data['log_netflow'] = data['log_netflow']
        if 'log_debug' in data:
            update_data['log_debug'] = data['log_debug']
        if 'max_proxies' in data:
            update_data['max_proxies'] = data['max_proxies']

        cluster.update_record(**update_data)
        return {'message': 'Cluster updated successfully'}

    elif request.method == 'DELETE':
        # Only admins can delete clusters
        if not check_permission(auth, 'delete_clusters'):
            abort(403)

        # Don't allow deleting default cluster
        if cluster.is_default:
            response.status = 400
            return {'error': 'Cannot delete default cluster'}

        # Soft delete - deactivate cluster
        cluster.update_record(is_active=False, updated_at=datetime.utcnow())
        return {'message': 'Cluster deactivated successfully'}


@action('/api/clusters/<cluster_id:int>/rotate-key', methods=['POST'])
@action.uses(auth, auth.user, CORS())

def rotate_cluster_key(cluster_id):
    """Rotate cluster API key"""
    user = auth.get_user()

    # Only admins can rotate keys
    if not check_permission(auth, 'update_clusters'):
        abort(403)

    cluster = db.clusters[cluster_id]
    if not cluster:
        abort(404)

    try:
        new_api_key = ClusterModel.rotate_api_key(db, cluster_id)
        if new_api_key:
            return {
                'api_key': new_api_key,
                'message': 'API key rotated successfully'
            }
        else:
            response.status = 500
            return {'error': 'Failed to rotate API key'}
    except Exception as e:
        logger.error(f"API key rotation failed: {e}")
        response.status = 500
        return {'error': 'Failed to rotate API key'}


@action('/api/clusters/<cluster_id:int>/logging', methods=['PUT'])
@action.uses(auth, auth.user, CORS())

def update_cluster_logging(cluster_id):
    """Update cluster logging configuration"""
    user = auth.get_user()

    # Only admins can update logging config
    if not check_permission(auth, 'update_clusters'):
        abort(403)

    cluster = db.clusters[cluster_id]
    if not cluster:
        abort(404)

    data = request.json
    success = ClusterModel.update_logging_config(
        db, cluster_id,
        syslog_endpoint=data.get('syslog_endpoint'),
        log_auth=data.get('log_auth'),
        log_netflow=data.get('log_netflow'),
        log_debug=data.get('log_debug')
    )

    if success:
        return {'message': 'Logging configuration updated successfully'}
    else:
        response.status = 500
        return {'error': 'Failed to update logging configuration'}


@action('/api/clusters/<cluster_id:int>/users', methods=['GET', 'POST'])
@action.uses(auth, auth.user, CORS())

def cluster_users(cluster_id):
    """Manage cluster user assignments"""
    user = auth.get_user()

    # Only admins can manage cluster users
    if not check_permission(auth, 'update_clusters'):
        abort(403)

    cluster = db.clusters[cluster_id]
    if not cluster:
        abort(404)

    if request.method == 'GET':
        # Get all users assigned to this cluster
        assignments = db(
            (db.user_cluster_assignments.cluster_id == cluster_id) &
            (db.user_cluster_assignments.is_active == True) &
            (db.auth_user.id == db.user_cluster_assignments.user_id)
        ).select(
            db.user_cluster_assignments.ALL,
            db.auth_user.id,
            db.auth_user.email,
            db.auth_user.first_name,
            db.auth_user.last_name,
            left=db.auth_user.on(db.auth_user.id == db.user_cluster_assignments.user_id)
        )

        return {
            'users': [
                {
                    'user_id': assignment.auth_user.id,
                    'email': assignment.auth_user.email,
                    'first_name': assignment.auth_user.first_name,
                    'last_name': assignment.auth_user.last_name,
                    'role': assignment.user_cluster_assignments.role,
                    'assigned_at': assignment.user_cluster_assignments.assigned_at
                }
                for assignment in assignments
            ]
        }

    elif request.method == 'POST':
        # Assign user to cluster
        data = request.json
        target_user_id = data.get('user_id')
        role = data.get('role', 'service_owner')

        # Validate user exists
        target_user = db.auth_user[target_user_id]
        if not target_user:
            response.status = 400
            return {'error': 'User not found'}

        success = UserClusterAssignmentModel.assign_user_to_cluster(
            db, target_user_id, cluster_id, role, user['id']
        )

        if success:
            return {'message': 'User assigned to cluster successfully'}
        else:
            response.status = 500
            return {'error': 'Failed to assign user to cluster'}


@action('/api/clusters/<cluster_id:int>/config', methods=['GET'])

def cluster_config(cluster_id):
    """Get cluster configuration for proxy (API key authenticated)"""
    # This endpoint uses API key authentication, not user auth
    auth_header = request.headers.get('Authorization', '')
    api_key = auth_header.replace('Bearer ', '') if auth_header.startswith('Bearer ') else None

    if not api_key:
        response.status = 401
        return {'error': 'API key required'}

    # Validate API key and get cluster info
    cluster_info = ClusterModel.validate_api_key(db, api_key)
    if not cluster_info or cluster_info['cluster_id'] != cluster_id:
        response.status = 401
        return {'error': 'Invalid API key for cluster'}

    # Get complete cluster configuration
    config = ClusterModel.get_cluster_config(db, cluster_id)
    if not config:
        abort(404)

    return config


# User management using py4web auth
@action('/api/users', methods=['GET', 'POST'])
@action.uses(auth, CORS())

def users():
    """User management (admin only)"""
    if not auth.user_id:
        abort(401)

    user = auth.get_user()
    if not user.get('is_admin'):
        abort(403)

    if request.method == 'GET':
        users = db(db.auth_user).select(orderby=db.auth_user.email)

        return {
            'users': [
                {
                    'id': u.id,
                    'email': u.email,
                    'first_name': u.first_name,
                    'last_name': u.last_name,
                    'is_admin': u.get('is_admin', False),
                    'totp_enabled': u.get('totp_enabled', False),
                    'auth_provider': u.get('auth_provider', 'local'),
                    'created_on': u.created_on,
                    'last_login': u.get('last_login')
                }
                for u in users
            ]
        }

    elif request.method == 'POST':
        data = request.json

        # Use py4web's native user creation
        try:
            result = auth.register(
                email=data['email'],
                password=data['password'],
                first_name=data.get('first_name', ''),
                last_name=data.get('last_name', '')
            )

            user_id = result.get('id')
            if user_id:
                # Update with additional fields
                new_user = db.auth_user[user_id]
                new_user.update_record(
                    is_admin=data.get('is_admin', False),
                    registration_key='',  # Auto-approve
                    registration_id=''
                )

                return {
                    'user': {
                        'id': new_user.id,
                        'email': new_user.email,
                        'first_name': new_user.first_name,
                        'last_name': new_user.last_name,
                        'is_admin': new_user.is_admin
                    },
                    'message': 'User created successfully'
                }

        except Exception as e:
            logger.error(f"User creation failed: {e}")
            response.status = 500
            return {'error': 'Failed to create user'}


# Proxy registration and management using API key authentication
@action('/api/proxy/register', methods=['POST'])

def proxy_register():
    """Register proxy server with cluster API key"""
    data = request.json

    proxy_id = ProxyServerModel.register_proxy(
        db,
        name=data['name'],
        hostname=data['hostname'],
        cluster_api_key=data['cluster_api_key'],
        ip_address=data.get('ip_address'),
        port=data.get('port', 8080),
        version=data.get('version'),
        capabilities=data.get('capabilities')
    )

    if not proxy_id:
        response.status = 400
        return {'error': 'Registration failed - invalid API key or proxy limit exceeded'}

    proxy = db.proxy_servers[proxy_id]
    return {
        'proxy': {
            'id': proxy.id,
            'name': proxy.name,
            'hostname': proxy.hostname,
            'cluster_id': proxy.cluster_id,
            'status': proxy.status
        },
        'message': 'Proxy registered successfully'
    }


@action('/api/proxy/heartbeat', methods=['POST'])

def proxy_heartbeat():
    """Proxy heartbeat and status update"""
    data = request.json

    success = ProxyServerModel.update_heartbeat(
        db,
        proxy_name=data['proxy_name'],
        cluster_api_key=data['cluster_api_key'],
        status_data={
            'version': data.get('version'),
            'capabilities': data.get('capabilities'),
            'config_version': data.get('config_version')
        }
    )

    if not success:
        response.status = 401
        return {'error': 'Invalid API key or proxy not found'}

    # Record metrics if provided
    if 'metrics' in data and data['metrics']:
        try:
            proxy = db(
                (db.proxy_servers.name == data['proxy_name']) &
                (db.proxy_servers.cluster_id == ClusterModel.validate_api_key(db, data['cluster_api_key'])['cluster_id'])
            ).select().first()

            if proxy:
                ProxyMetricsModel.record_metrics(db, proxy.id, data['metrics'])
        except Exception as e:
            logger.warning(f"Failed to record metrics: {e}")

    return {'message': 'Heartbeat received successfully'}


@action('/api/proxy/config/<proxy_name>', methods=['GET'])

def proxy_config(proxy_name):
    """Get configuration for specific proxy"""
    auth_header = request.headers.get('Authorization', '')
    api_key = auth_header.replace('Bearer ', '') if auth_header.startswith('Bearer ') else None

    if not api_key:
        response.status = 401
        return {'error': 'API key required'}

    config = ProxyServerModel.get_proxy_config(db, proxy_name, api_key)
    if not config:
        response.status = 401
        return {'error': 'Invalid API key or proxy not found'}

    return config


@action('/api/proxy/stats/<cluster_id:int>', methods=['GET'])
@action.uses(auth, auth.user, CORS())

def proxy_stats(cluster_id):
    """Get proxy statistics for cluster"""
    user = auth.get_user()

    # Check access permissions
    if not user.get('is_admin'):
        user_role = UserClusterAssignmentModel.check_user_cluster_access(db, user['id'], cluster_id)
        if not user_role:
            abort(403)

    stats = ProxyServerModel.get_proxy_stats(db, cluster_id)
    return {'stats': stats}


@action('/api/proxy/<proxy_id:int>/metrics', methods=['GET'])
@action.uses(auth, auth.user, CORS())

def proxy_metrics(proxy_id):
    """Get metrics for specific proxy"""
    user = auth.get_user()

    # Get proxy to check cluster access
    proxy = db.proxy_servers[proxy_id]
    if not proxy:
        abort(404)

    # Check access permissions
    if not user.get('is_admin'):
        user_role = UserClusterAssignmentModel.check_user_cluster_access(db, user['id'], proxy.cluster_id)
        if not user_role:
            abort(403)

    hours = int(request.vars.get('hours', 24))
    metrics = ProxyMetricsModel.get_metrics(db, proxy_id, hours)

    return {
        'proxy_id': proxy_id,
        'metrics': metrics
    }


@action('/api/proxy/license-status', methods=['GET'])

def proxy_license_status():
    """Check license status for proxy count validation"""
    auth_header = request.headers.get('Authorization', '')
    api_key = auth_header.replace('Bearer ', '') if auth_header.startswith('Bearer ') else None

    if not api_key:
        response.status = 401
        return {'error': 'API key required'}

    # Validate API key and get cluster info
    cluster_info = ClusterModel.validate_api_key(db, api_key)
    if not cluster_info:
        response.status = 401
        return {'error': 'Invalid API key'}

    cluster_id = cluster_info['cluster_id']
    active_proxies = ClusterModel.count_active_proxies(db, cluster_id)
    max_proxies = cluster_info['max_proxies']

    # Get license information
    license_status = "community"
    features = []

    if hasattr(globals(), 'license_manager') and license_manager:
        try:
            license_info = license_manager.get_license_status_sync()
            if license_info.get('valid'):
                license_status = "enterprise"
                features = license_info.get('features', {})
        except Exception as e:
            logger.warning(f"License check failed: {e}")

    return {
        'license_status': license_status,
        'features': features,
        'cluster': {
            'id': cluster_id,
            'name': cluster_info['name'],
            'active_proxies': active_proxies,
            'max_proxies': max_proxies,
            'can_register_more': active_proxies < max_proxies
        }
    }


# License validation endpoints (async)
@action('/api/license/validate', methods=['POST'])
@action.uses(auth, auth.user, CORS())

async def validate_license():
    """Validate license key (admin only)"""
    user = auth.get_user()

    if not user.get('is_admin'):
        abort(403)

    data = request.json
    license_key = data.get('license_key')
    force_refresh = data.get('force_refresh', False)

    if not license_key:
        response.status = 400
        return {'error': 'License key required'}

    try:
        validation_result = await license_manager.validate_license_key(license_key, force_refresh)
        return {
            'license': validation_result,
            'message': 'License validated successfully'
        }
    except Exception as e:
        logger.error(f"License validation failed: {e}")
        response.status = 500
        return {'error': f'License validation failed: {str(e)}'}


@action('/api/license/status', methods=['GET'])
@action.uses(auth, auth.user, CORS())

async def license_status():
    """Get current license status (admin only)"""
    user = auth.get_user()

    if not user.get('is_admin'):
        abort(403)

    try:
        license_info = await license_manager.get_license_status()
        features = await license_manager.get_available_features()

        return {
            'license': license_info,
            'available_features': features
        }
    except Exception as e:
        logger.error(f"License status check failed: {e}")
        response.status = 500
        return {'error': f'License status check failed: {str(e)}'}


@action('/api/license/features', methods=['GET'])
@action.uses(auth, auth.user, CORS())

async def license_features():
    """Get available features for current user"""
    user = auth.get_user()

    try:
        features = await license_manager.get_available_features()

        # Filter features based on user permissions
        user_features = []

        # Basic features for all users
        basic_features = ['basic_proxy', 'tcp_proxy', 'udp_proxy', 'basic_auth', 'api_tokens']
        user_features.extend([f for f in features if f in basic_features])

        # Admin-only features
        if user.get('is_admin'):
            admin_features = ['multi_cluster', 'saml_authentication', 'oauth2_authentication', 'metrics_advanced']
            user_features.extend([f for f in features if f in admin_features])

        return {'features': user_features}
    except Exception as e:
        logger.error(f"Feature check failed: {e}")
        response.status = 500
        return {'error': f'Feature check failed: {str(e)}'}


@action('/api/license/check-feature/<feature>', methods=['GET'])
@action.uses(auth, auth.user, CORS())

async def check_feature(feature):
    """Check if specific feature is enabled"""
    user = auth.get_user()

    try:
        is_enabled = await license_manager.check_feature_enabled(feature)

        # Additional permission checks for admin features
        admin_features = {'multi_cluster', 'saml_authentication', 'oauth2_authentication', 'user_management'}
        if feature in admin_features and not user.get('is_admin'):
            is_enabled = False

        return {
            'feature': feature,
            'enabled': is_enabled
        }
    except Exception as e:
        logger.error(f"Feature check failed: {e}")
        response.status = 500
        return {'error': f'Feature check failed: {str(e)}'}


@action('/api/license/keepalive', methods=['POST'])
@action.uses(auth, auth.user, CORS())

async def send_license_keepalive():
    """Send keepalive to license server (admin only)"""
    user = auth.get_user()

    if not user.get('is_admin'):
        abort(403)

    if not license_manager or not license_manager.license_key:
        response.status = 400
        return {'error': 'No enterprise license configured'}

    try:
        success = await license_manager.send_keepalive()
        if success:
            return {'message': 'Keepalive sent successfully'}
        else:
            response.status = 500
            return {'error': 'Keepalive failed'}
    except Exception as e:
        logger.error(f"Manual keepalive failed: {e}")
        response.status = 500
        return {'error': f'Keepalive failed: {str(e)}'}


@action('/api/license/keepalive-health', methods=['GET'])
@action.uses(auth, auth.user, CORS())

def get_keepalive_health():
    """Get keepalive health status (admin only)"""
    user = auth.get_user()

    if not user.get('is_admin'):
        abort(403)

    if not license_manager:
        return {'status': 'not_applicable', 'message': 'No license manager configured'}

    try:
        health = license_manager.get_keepalive_health()
        return {'keepalive_health': health}
    except Exception as e:
        logger.error(f"Keepalive health check failed: {e}")
        response.status = 500
        return {'error': f'Keepalive health check failed: {str(e)}'}


# Service management endpoints
@action('/api/services', methods=['GET', 'POST'])
@action.uses(auth, auth.user, CORS())

def services():
    """Service management"""
    user = auth.get_user()

    if request.method == 'GET':
        cluster_id = request.vars.get('cluster_id')

        if cluster_id:
            # Get services for specific cluster
            if not user.get('is_admin'):
                # Check user has access to this cluster
                user_role = UserClusterAssignmentModel.check_user_cluster_access(db, user['id'], int(cluster_id))
                if not user_role:
                    abort(403)

            services = ServiceModel.get_cluster_services(db, int(cluster_id), None if user.get('is_admin') else user['id'])
        else:
            # Get all services user has access to
            if user.get('is_admin'):
                services = db(db.services.is_active == True).select(
                    db.services.ALL,
                    db.clusters.name,
                    left=db.clusters.on(db.clusters.id == db.services.cluster_id),
                    orderby=db.services.name
                )
                services = [
                    {
                        'id': service.services.id,
                        'name': service.services.name,
                        'ip_fqdn': service.services.ip_fqdn,
                        'port': service.services.port,
                        'protocol': service.services.protocol,
                        'collection': service.services.collection,
                        'cluster_id': service.services.cluster_id,
                        'cluster_name': service.clusters.name,
                        'auth_type': service.services.auth_type,
                        'tls_enabled': service.services.tls_enabled,
                        'health_check_enabled': service.services.health_check_enabled,
                        'created_at': service.services.created_at
                    }
                    for service in services
                ]
            else:
                # Get services assigned to user
                user_services = UserServiceAssignmentModel.get_user_services(db, user['id'])
                services = user_services

        return {'services': services}

    elif request.method == 'POST':
        # Create new service
        if not check_permission(auth, 'create_services'):
            abort(403)

        data = request.json

        # Validate cluster access
        cluster_id = data.get('cluster_id')
        if not user.get('is_admin'):
            user_role = UserClusterAssignmentModel.check_user_cluster_access(db, user['id'], cluster_id)
            if not user_role:
                abort(403)

        try:
            service_id = ServiceModel.create_service(
                db,
                name=data['name'],
                ip_fqdn=data['ip_fqdn'],
                port=data['port'],
                cluster_id=cluster_id,
                created_by=user['id'],
                protocol=data.get('protocol', 'tcp'),
                collection=data.get('collection'),
                auth_type=data.get('auth_type', 'none'),
                tls_enabled=data.get('tls_enabled', False),
                tls_verify=data.get('tls_verify', True)
            )

            service = db.services[service_id]
            return {
                'service': {
                    'id': service.id,
                    'name': service.name,
                    'ip_fqdn': service.ip_fqdn,
                    'port': service.port,
                    'protocol': service.protocol,
                    'cluster_id': service.cluster_id,
                    'auth_type': service.auth_type,
                    'created_at': service.created_at
                },
                'message': 'Service created successfully'
            }

        except Exception as e:
            logger.error(f"Service creation failed: {e}")
            response.status = 500
            return {'error': 'Failed to create service'}


@action('/api/services/<service_id:int>', methods=['GET', 'PUT', 'DELETE'])
@action.uses(auth, auth.user, CORS())

def service_detail(service_id):
    """Individual service management"""
    user = auth.get_user()

    service = db.services[service_id]
    if not service or not service.is_active:
        abort(404)

    # Check access permissions
    if not user.get('is_admin'):
        if not UserServiceAssignmentModel.check_user_service_access(db, user['id'], service_id):
            abort(403)

    if request.method == 'GET':
        return {
            'service': {
                'id': service.id,
                'name': service.name,
                'ip_fqdn': service.ip_fqdn,
                'port': service.port,
                'protocol': service.protocol,
                'collection': service.collection,
                'cluster_id': service.cluster_id,
                'auth_type': service.auth_type,
                'tls_enabled': service.tls_enabled,
                'tls_verify': service.tls_verify,
                'health_check_enabled': service.health_check_enabled,
                'health_check_path': service.health_check_path,
                'health_check_interval': service.health_check_interval,
                'created_at': service.created_at,
                'updated_at': service.updated_at
            }
        }

    elif request.method == 'PUT':
        # Only admins and service owners can update services
        if not check_permission(auth, 'update_services'):
            abort(403)

        data = request.json
        update_data = {'updated_at': datetime.utcnow()}

        # Update allowed fields
        if 'name' in data:
            update_data['name'] = data['name']
        if 'ip_fqdn' in data:
            update_data['ip_fqdn'] = data['ip_fqdn']
        if 'port' in data:
            update_data['port'] = data['port']
        if 'protocol' in data:
            update_data['protocol'] = data['protocol']
        if 'collection' in data:
            update_data['collection'] = data['collection']
        if 'tls_enabled' in data:
            update_data['tls_enabled'] = data['tls_enabled']
        if 'tls_verify' in data:
            update_data['tls_verify'] = data['tls_verify']
        if 'health_check_enabled' in data:
            update_data['health_check_enabled'] = data['health_check_enabled']
        if 'health_check_path' in data:
            update_data['health_check_path'] = data['health_check_path']
        if 'health_check_interval' in data:
            update_data['health_check_interval'] = data['health_check_interval']

        service.update_record(**update_data)
        return {'message': 'Service updated successfully'}

    elif request.method == 'DELETE':
        # Only admins can delete services
        if not check_permission(auth, 'delete_services'):
            abort(403)

        # Soft delete - deactivate service
        service.update_record(is_active=False, updated_at=datetime.utcnow())
        return {'message': 'Service deactivated successfully'}


@action('/api/services/<service_id:int>/auth', methods=['PUT'])
@action.uses(auth, auth.user, CORS())

def set_service_auth(service_id):
    """Set service authentication method"""
    user = auth.get_user()

    service = db.services[service_id]
    if not service or not service.is_active:
        abort(404)

    # Check access permissions
    if not user.get('is_admin'):
        if not UserServiceAssignmentModel.check_user_service_access(db, user['id'], service_id):
            abort(403)

    if not check_permission(auth, 'update_services'):
        abort(403)

    data = request.json
    auth_type = data.get('auth_type')

    try:
        if auth_type == 'base64':
            token = ServiceModel.set_base64_auth(db, service_id)
            return {
                'auth_type': 'base64',
                'token': token,
                'message': 'Base64 authentication configured'
            }

        elif auth_type == 'jwt':
            jwt_expiry = data.get('jwt_expiry', 3600)
            jwt_algorithm = data.get('jwt_algorithm', 'HS256')
            jwt_secret = ServiceModel.set_jwt_auth(db, service_id, jwt_expiry, jwt_algorithm)
            return {
                'auth_type': 'jwt',
                'jwt_secret': jwt_secret,
                'jwt_expiry': jwt_expiry,
                'jwt_algorithm': jwt_algorithm,
                'message': 'JWT authentication configured'
            }

        elif auth_type == 'none':
            service.update_record(
                auth_type='none',
                token_base64=None,
                jwt_secret=None,
                jwt_expiry=None,
                updated_at=datetime.utcnow()
            )
            return {
                'auth_type': 'none',
                'message': 'Authentication disabled'
            }

        else:
            response.status = 400
            return {'error': 'Invalid auth type. Must be: none, base64, or jwt'}

    except Exception as e:
        logger.error(f"Service auth configuration failed: {e}")
        response.status = 500
        return {'error': 'Failed to configure authentication'}


@action('/api/services/<service_id:int>/jwt/rotate', methods=['POST'])
@action.uses(auth, auth.user, CORS())

def rotate_service_jwt(service_id):
    """Rotate JWT secret for service"""
    user = auth.get_user()

    service = db.services[service_id]
    if not service or not service.is_active:
        abort(404)

    # Check access permissions
    if not user.get('is_admin'):
        if not UserServiceAssignmentModel.check_user_service_access(db, user['id'], service_id):
            abort(403)

    if not check_permission(auth, 'update_services'):
        abort(403)

    try:
        new_secret = ServiceModel.rotate_jwt_secret(db, service_id)
        if new_secret:
            return {
                'jwt_secret': new_secret,
                'message': 'JWT secret rotated successfully'
            }
        else:
            response.status = 400
            return {'error': 'Service is not configured for JWT authentication'}

    except Exception as e:
        logger.error(f"JWT rotation failed: {e}")
        response.status = 500
        return {'error': 'Failed to rotate JWT secret'}


@action('/api/services/<service_id:int>/jwt/token', methods=['POST'])
@action.uses(auth, auth.user, CORS())

def create_service_jwt_token(service_id):
    """Create JWT token for service"""
    user = auth.get_user()

    service = db.services[service_id]
    if not service or not service.is_active:
        abort(404)

    # Check access permissions
    if not user.get('is_admin'):
        if not UserServiceAssignmentModel.check_user_service_access(db, user['id'], service_id):
            abort(403)

    data = request.json
    additional_claims = data.get('additional_claims', {})

    try:
        token = ServiceModel.create_jwt_token(db, service_id, additional_claims)
        if token:
            return {
                'token': token,
                'service_id': service_id,
                'message': 'JWT token created successfully'
            }
        else:
            response.status = 400
            return {'error': 'Service is not configured for JWT authentication'}

    except Exception as e:
        logger.error(f"JWT token creation failed: {e}")
        response.status = 500
        return {'error': 'Failed to create JWT token'}


@action('/api/services/<service_id:int>/users', methods=['GET', 'POST'])
@action.uses(auth, auth.user, CORS())

def service_users(service_id):
    """Manage service user assignments"""
    user = auth.get_user()

    # Only admins can manage service users
    if not check_permission(auth, 'update_services'):
        abort(403)

    service = db.services[service_id]
    if not service or not service.is_active:
        abort(404)

    if request.method == 'GET':
        # Get all users assigned to this service
        assignments = db(
            (db.user_service_assignments.service_id == service_id) &
            (db.user_service_assignments.is_active == True) &
            (db.auth_user.id == db.user_service_assignments.user_id)
        ).select(
            db.user_service_assignments.ALL,
            db.auth_user.id,
            db.auth_user.email,
            db.auth_user.first_name,
            db.auth_user.last_name,
            left=db.auth_user.on(db.auth_user.id == db.user_service_assignments.user_id)
        )

        return {
            'users': [
                {
                    'user_id': assignment.auth_user.id,
                    'email': assignment.auth_user.email,
                    'first_name': assignment.auth_user.first_name,
                    'last_name': assignment.auth_user.last_name,
                    'assigned_at': assignment.user_service_assignments.assigned_at
                }
                for assignment in assignments
            ]
        }

    elif request.method == 'POST':
        # Assign user to service
        data = request.json
        target_user_id = data.get('user_id')

        # Validate user exists
        target_user = db.auth_user[target_user_id]
        if not target_user:
            response.status = 400
            return {'error': 'User not found'}

        success = UserServiceAssignmentModel.assign_user_to_service(
            db, target_user_id, service_id, user['id']
        )

        if success:
            return {'message': 'User assigned to service successfully'}
        else:
            response.status = 500
            return {'error': 'Failed to assign user to service'}


# Mapping Management API Endpoints
@action('/api/mappings', methods=['GET', 'POST'])
@action.uses(auth, auth.user, CORS())

def mappings():
    """List mappings or create new mapping"""
    user = auth.get_user()

    if request.method == 'GET':
        # Get cluster filter
        cluster_id = request.query.get('cluster_id')

        if not cluster_id:
            response.status = 400
            return {'error': 'cluster_id parameter required'}

        try:
            cluster_id = int(cluster_id)
        except (ValueError, TypeError):
            response.status = 400
            return {'error': 'Invalid cluster_id'}

        # Check user access to cluster
        if not user.get('is_admin', False):
            if not UserClusterAssignmentModel.check_user_cluster_access(db, user['id'], cluster_id):
                response.status = 403
                return {'error': 'Access denied to cluster'}

        # Get mappings for cluster
        mappings = MappingModel.get_cluster_mappings(
            db, cluster_id, user['id'] if not user.get('is_admin', False) else None
        )

        return {'mappings': mappings}

    elif request.method == 'POST':
        if not check_permission(auth, 'create_mappings'):
            response.status = 403
            return {'error': 'Permission denied'}

        data = request.json
        if not data:
            response.status = 400
            return {'error': 'JSON data required'}

        try:
            # Validate required fields
            required_fields = ['name', 'cluster_id', 'source_services', 'dest_services', 'ports']
            for field in required_fields:
                if field not in data:
                    response.status = 400
                    return {'error': f'Missing required field: {field}'}

            # Check user access to cluster
            cluster_id = data['cluster_id']
            if not user.get('is_admin', False):
                if not UserClusterAssignmentModel.check_user_cluster_access(db, user['id'], cluster_id):
                    response.status = 403
                    return {'error': 'Access denied to cluster'}

            # Create mapping
            mapping_id = MappingModel.create_mapping(
                db=db,
                name=data['name'],
                source_services=data['source_services'],
                dest_services=data['dest_services'],
                ports=data['ports'],
                cluster_id=cluster_id,
                created_by=user['id'],
                protocols=data.get('protocols', ['tcp']),
                auth_required=data.get('auth_required', True),
                priority=data.get('priority', 100),
                description=data.get('description'),
                comments=data.get('comments')
            )

            return {
                'message': 'Mapping created successfully',
                'mapping_id': mapping_id
            }

        except ValueError as e:
            response.status = 400
            return {'error': str(e)}
        except Exception as e:
            logger.error(f"Mapping creation failed: {e}")
            response.status = 500
            return {'error': 'Internal server error'}


@action('/api/mappings/<mapping_id:int>', methods=['GET', 'PUT', 'DELETE'])
@action.uses(auth, auth.user, CORS())

def mapping_detail(mapping_id):
    """Get, update, or delete specific mapping"""
    user = auth.get_user()

    # Get mapping
    mapping = db.mappings[mapping_id]
    if not mapping or not mapping.is_active:
        response.status = 404
        return {'error': 'Mapping not found'}

    # Check user access
    if not user.get('is_admin', False):
        if not UserClusterAssignmentModel.check_user_cluster_access(db, user['id'], mapping.cluster_id):
            response.status = 403
            return {'error': 'Access denied'}

    if request.method == 'GET':
        # Return full mapping details
        config = MappingModel.resolve_mapping_services(db, mapping_id)
        if not config:
            response.status = 404
            return {'error': 'Mapping not found'}

        return {'mapping': config}

    elif request.method == 'PUT':
        if not check_permission(auth, 'update_mappings'):
            response.status = 403
            return {'error': 'Permission denied'}

        data = request.json
        if not data:
            response.status = 400
            return {'error': 'JSON data required'}

        try:
            update_data = {}

            # Update allowed fields
            if 'name' in data:
                update_data['name'] = data['name']
            if 'description' in data:
                update_data['description'] = data['description']
            if 'source_services' in data:
                normalized_sources = MappingModel._normalize_service_list(
                    db, data['source_services'], mapping.cluster_id
                )
                if normalized_sources:
                    update_data['source_services'] = normalized_sources
            if 'dest_services' in data:
                normalized_dests = MappingModel._normalize_service_list(
                    db, data['dest_services'], mapping.cluster_id
                )
                if normalized_dests:
                    update_data['dest_services'] = normalized_dests
            if 'ports' in data:
                normalized_ports = MappingModel._normalize_port_list(data['ports'])
                if normalized_ports:
                    update_data['ports'] = normalized_ports
            if 'protocols' in data:
                update_data['protocols'] = data['protocols']
            if 'auth_required' in data:
                update_data['auth_required'] = data['auth_required']
            if 'priority' in data:
                update_data['priority'] = data['priority']
            if 'comments' in data:
                update_data['comments'] = data['comments']

            if update_data:
                update_data['updated_at'] = datetime.utcnow()
                mapping.update_record(**update_data)

            return {'message': 'Mapping updated successfully'}

        except ValueError as e:
            response.status = 400
            return {'error': str(e)}
        except Exception as e:
            logger.error(f"Mapping update failed: {e}")
            response.status = 500
            return {'error': 'Internal server error'}

    elif request.method == 'DELETE':
        if not check_permission(auth, 'delete_mappings'):
            response.status = 403
            return {'error': 'Permission denied'}

        try:
            # Soft delete
            mapping.update_record(
                is_active=False,
                updated_at=datetime.utcnow()
            )

            return {'message': 'Mapping deleted successfully'}

        except Exception as e:
            logger.error(f"Mapping deletion failed: {e}")
            response.status = 500
            return {'error': 'Internal server error'}


@action('/api/mappings/<mapping_id:int>/resolve')
@action.uses(auth, auth.user, CORS())

def resolve_mapping(mapping_id):
    """Resolve mapping to concrete service configurations for proxy"""
    user = auth.get_user()

    # Get mapping
    mapping = db.mappings[mapping_id]
    if not mapping or not mapping.is_active:
        response.status = 404
        return {'error': 'Mapping not found'}

    # Check user access
    if not user.get('is_admin', False):
        if not UserClusterAssignmentModel.check_user_cluster_access(db, user['id'], mapping.cluster_id):
            response.status = 403
            return {'error': 'Access denied'}

    try:
        resolved = MappingModel.resolve_mapping_services(db, mapping_id)
        if not resolved:
            response.status = 404
            return {'error': 'Mapping not found'}

        return {'resolved_mapping': resolved}

    except Exception as e:
        logger.error(f"Mapping resolution failed: {e}")
        response.status = 500
        return {'error': 'Internal server error'}


@action('/api/mappings/find', methods=['POST'])
@action.uses(auth, auth.user, CORS())

def find_mappings():
    """Find mappings that match specific criteria"""
    user = auth.get_user()
    data = request.json

    if not data:
        response.status = 400
        return {'error': 'JSON data required'}

    # Validate required fields
    required_fields = ['source_service_id', 'dest_service_id', 'protocol', 'port']
    for field in required_fields:
        if field not in data:
            response.status = 400
            return {'error': f'Missing required field: {field}'}

    try:
        source_service_id = data['source_service_id']
        dest_service_id = data['dest_service_id']
        protocol = data['protocol']
        port = data['port']

        # Check user access to services
        source_service = db.services[source_service_id]
        if not source_service:
            response.status = 404
            return {'error': 'Source service not found'}

        if not user.get('is_admin', False):
            if not UserClusterAssignmentModel.check_user_cluster_access(db, user['id'], source_service.cluster_id):
                response.status = 403
                return {'error': 'Access denied'}

        # Find matching mappings
        matching = MappingModel.find_matching_mappings(
            db, source_service_id, dest_service_id, protocol, port
        )

        return {'matching_mappings': matching}

    except Exception as e:
        logger.error(f"Mapping search failed: {e}")
        response.status = 500
        return {'error': 'Internal server error'}


# Certificate Management API Endpoints
@action('/api/certificates', methods=['GET', 'POST'])
@action.uses(auth, auth.user, CORS())
def certificates():
    """Certificate management"""
    user = auth.get_user()

    if request.method == 'GET':
        if not check_permission(auth, 'read_certificates'):
            response.status = 403
            return {'error': 'Permission denied'}

        # Get all active certificates
        certificates = db(
            db.certificates.is_active == True
        ).select(orderby=db.certificates.name)

        cert_list = []
        for cert in certificates:
            days_until_expiry = (cert.expires_at - datetime.utcnow()).days if cert.expires_at else 0
            cert_list.append({
                'id': cert.id,
                'name': cert.name,
                'description': cert.description,
                'domain_names': cert.domain_names,
                'issuer': cert.issuer,
                'source_type': cert.source_type,
                'auto_renew': cert.auto_renew,
                'issued_at': cert.issued_at,
                'expires_at': cert.expires_at,
                'days_until_expiry': days_until_expiry,
                'is_active': cert.is_active,
                'created_at': cert.created_at
            })

        return {'certificates': cert_list}

    elif request.method == 'POST':
        if not check_permission(auth, 'create_certificates'):
            response.status = 403
            return {'error': 'Permission denied'}

        data = request.json
        if not data:
            response.status = 400
            return {'error': 'JSON data required'}

        try:
            # Validate required fields
            if 'name' not in data or 'source_type' not in data:
                response.status = 400
                return {'error': 'Missing required fields: name, source_type'}

            source_type = data['source_type']

            if source_type == 'upload':
                # Direct certificate upload
                if not all(field in data for field in ['cert_data', 'key_data']):
                    response.status = 400
                    return {'error': 'Missing required fields for upload: cert_data, key_data'}

                cert_id = CertificateModel.create_certificate(
                    db=db,
                    name=data['name'],
                    cert_data=data['cert_data'],
                    key_data=data['key_data'],
                    source_type='upload',
                    created_by=user['id'],
                    description=data.get('description'),
                    ca_bundle=data.get('ca_bundle'),
                    auto_renew=False
                )

            elif source_type == 'infisical':
                # Infisical integration
                if 'source_config' not in data:
                    response.status = 400
                    return {'error': 'Missing source_config for Infisical'}

                config = data['source_config']
                required_fields = ['api_url', 'token', 'project_id', 'secret_path']
                if not all(field in config for field in required_fields):
                    response.status = 400
                    return {'error': f'Missing required Infisical config fields: {required_fields}'}

                cert_id = CertificateModel.create_certificate(
                    db=db,
                    name=data['name'],
                    cert_data="",  # Will be fetched during renewal
                    key_data="",
                    source_type='infisical',
                    created_by=user['id'],
                    description=data.get('description'),
                    source_config=config,
                    auto_renew=data.get('auto_renew', True),
                    renewal_threshold_days=data.get('renewal_threshold_days', 30)
                )

            elif source_type == 'vault':
                # HashiCorp Vault integration
                if 'source_config' not in data:
                    response.status = 400
                    return {'error': 'Missing source_config for Vault'}

                config = data['source_config']
                required_fields = ['vault_url', 'token', 'role', 'common_name']
                if not all(field in config for field in required_fields):
                    response.status = 400
                    return {'error': f'Missing required Vault config fields: {required_fields}'}

                cert_id = CertificateModel.create_certificate(
                    db=db,
                    name=data['name'],
                    cert_data="",  # Will be issued during renewal
                    key_data="",
                    source_type='vault',
                    created_by=user['id'],
                    description=data.get('description'),
                    source_config=config,
                    auto_renew=data.get('auto_renew', True),
                    renewal_threshold_days=data.get('renewal_threshold_days', 30)
                )

            else:
                response.status = 400
                return {'error': 'Invalid source_type. Must be: upload, infisical, vault'}

            return {
                'message': 'Certificate created successfully',
                'certificate_id': cert_id
            }

        except ValueError as e:
            response.status = 400
            return {'error': str(e)}
        except Exception as e:
            logger.error(f"Certificate creation failed: {e}")
            response.status = 500
            return {'error': 'Failed to create certificate'}


@action('/api/certificates/<cert_id:int>', methods=['GET', 'PUT', 'DELETE'])
@action.uses(auth, auth.user, CORS())
def certificate_detail(cert_id):
    """Individual certificate management"""
    user = auth.get_user()

    # Get certificate
    cert = db.certificates[cert_id]
    if not cert or not cert.is_active:
        response.status = 404
        return {'error': 'Certificate not found'}

    if request.method == 'GET':
        if not check_permission(auth, 'read_certificates'):
            response.status = 403
            return {'error': 'Permission denied'}

        days_until_expiry = (cert.expires_at - datetime.utcnow()).days if cert.expires_at else 0

        cert_data = {
            'id': cert.id,
            'name': cert.name,
            'description': cert.description,
            'domain_names': cert.domain_names,
            'issuer': cert.issuer,
            'serial_number': cert.serial_number,
            'fingerprint_sha256': cert.fingerprint_sha256,
            'source_type': cert.source_type,
            'auto_renew': cert.auto_renew,
            'renewal_threshold_days': cert.renewal_threshold_days,
            'issued_at': cert.issued_at,
            'expires_at': cert.expires_at,
            'days_until_expiry': days_until_expiry,
            'next_renewal_check': cert.next_renewal_check,
            'renewal_attempts': cert.renewal_attempts,
            'last_renewal_attempt': cert.last_renewal_attempt,
            'renewal_error': cert.renewal_error,
            'is_active': cert.is_active,
            'created_at': cert.created_at,
            'updated_at': cert.updated_at
        }

        # Include source config for admins (without sensitive data)
        if user.get('is_admin'):
            config = dict(cert.source_config or {})
            # Mask sensitive fields
            if 'token' in config:
                config['token'] = '***masked***'
            cert_data['source_config'] = config

        return {'certificate': cert_data}

    elif request.method == 'PUT':
        if not check_permission(auth, 'update_certificates'):
            response.status = 403
            return {'error': 'Permission denied'}

        data = request.json
        if not data:
            response.status = 400
            return {'error': 'JSON data required'}

        try:
            update_data = {}

            # Update allowed fields
            if 'name' in data:
                update_data['name'] = data['name']
            if 'description' in data:
                update_data['description'] = data['description']
            if 'auto_renew' in data:
                update_data['auto_renew'] = data['auto_renew']
            if 'renewal_threshold_days' in data:
                if 1 <= data['renewal_threshold_days'] <= 90:
                    update_data['renewal_threshold_days'] = data['renewal_threshold_days']
                else:
                    response.status = 400
                    return {'error': 'Renewal threshold must be between 1 and 90 days'}

            # Update certificate data for upload type
            if cert.source_type == 'upload' and 'cert_data' in data and 'key_data' in data:
                # Parse and validate new certificate
                cert_info = CertificateModel._parse_certificate(data['cert_data'])
                if not cert_info:
                    response.status = 400
                    return {'error': 'Invalid certificate data'}

                if not CertificateModel._validate_key_pair(data['cert_data'], data['key_data']):
                    response.status = 400
                    return {'error': 'Private key does not match certificate'}

                update_data.update({
                    'cert_data': data['cert_data'],
                    'key_data': data['key_data'],
                    'domain_names': cert_info['domain_names'],
                    'issuer': cert_info['issuer'],
                    'serial_number': cert_info['serial_number'],
                    'fingerprint_sha256': cert_info['fingerprint_sha256'],
                    'issued_at': cert_info['issued_at'],
                    'expires_at': cert_info['expires_at']
                })

                if 'ca_bundle' in data:
                    update_data['ca_bundle'] = data['ca_bundle']

            if update_data:
                update_data['updated_at'] = datetime.utcnow()
                cert.update_record(**update_data)

            return {'message': 'Certificate updated successfully'}

        except ValueError as e:
            response.status = 400
            return {'error': str(e)}
        except Exception as e:
            logger.error(f"Certificate update failed: {e}")
            response.status = 500
            return {'error': 'Failed to update certificate'}

    elif request.method == 'DELETE':
        if not check_permission(auth, 'delete_certificates'):
            response.status = 403
            return {'error': 'Permission denied'}

        try:
            # Soft delete
            cert.update_record(
                is_active=False,
                updated_at=datetime.utcnow()
            )

            return {'message': 'Certificate deleted successfully'}

        except Exception as e:
            logger.error(f"Certificate deletion failed: {e}")
            response.status = 500
            return {'error': 'Failed to delete certificate'}


@action('/api/certificates/<cert_id:int>/renew', methods=['POST'])
@action.uses(auth, auth.user, CORS())
async def renew_certificate(cert_id):
    """Manually trigger certificate renewal"""
    user = auth.get_user()

    if not check_permission(auth, 'update_certificates'):
        response.status = 403
        return {'error': 'Permission denied'}

    cert = db.certificates[cert_id]
    if not cert or not cert.is_active:
        response.status = 404
        return {'error': 'Certificate not found'}

    if cert.source_type == 'upload':
        response.status = 400
        return {'error': 'Manual certificates cannot be auto-renewed'}

    try:
        from models.certificate import CertificateManager
        cert_manager = CertificateManager(db)
        success = await cert_manager.renew_certificate(cert_id)

        if success:
            return {'message': 'Certificate renewal initiated successfully'}
        else:
            response.status = 500
            return {'error': 'Certificate renewal failed'}

    except Exception as e:
        logger.error(f"Certificate renewal failed: {e}")
        response.status = 500
        return {'error': f'Certificate renewal failed: {str(e)}'}


@action('/api/certificates/expiring', methods=['GET'])
@action.uses(auth, auth.user, CORS())
def expiring_certificates():
    """Get certificates expiring soon"""
    user = auth.get_user()

    if not check_permission(auth, 'read_certificates'):
        response.status = 403
        return {'error': 'Permission denied'}

    days = int(request.query.get('days', 30))
    if not (1 <= days <= 365):
        response.status = 400
        return {'error': 'Days parameter must be between 1 and 365'}

    try:
        expiring = CertificateModel.get_expiring_certificates(db, days)
        return {'expiring_certificates': expiring}

    except Exception as e:
        logger.error(f"Failed to get expiring certificates: {e}")
        response.status = 500
        return {'error': 'Failed to get expiring certificates'}


@action('/api/certificates/renewal-status', methods=['GET'])
@action.uses(auth, auth.user, CORS())
def certificate_renewal_status():
    """Get certificate renewal status"""
    user = auth.get_user()

    if not user.get('is_admin'):
        response.status = 403
        return {'error': 'Admin access required'}

    try:
        # Get certificates that need renewal
        pending_renewals = CertificateModel.get_certificates_for_renewal(db)

        # Get recent renewal attempts
        recent_attempts = db(
            (db.certificates.last_renewal_attempt >= datetime.utcnow() - timedelta(days=7)) &
            (db.certificates.is_active == True)
        ).select(
            db.certificates.id,
            db.certificates.name,
            db.certificates.last_renewal_attempt,
            db.certificates.renewal_attempts,
            db.certificates.renewal_error,
            orderby=~db.certificates.last_renewal_attempt
        )

        return {
            'pending_renewals': pending_renewals,
            'recent_attempts': [
                {
                    'id': attempt.id,
                    'name': attempt.name,
                    'last_attempt': attempt.last_renewal_attempt,
                    'attempts': attempt.renewal_attempts,
                    'error': attempt.renewal_error
                }
                for attempt in recent_attempts
            ]
        }

    except Exception as e:
        logger.error(f"Failed to get renewal status: {e}")
        response.status = 500
        return {'error': 'Failed to get renewal status'}


# Health endpoints
@action('/healthz')
@action.uses(CORS())
def health_check():
    """Health check endpoint"""
    try:
        # Test database connectivity
        db.executesql('SELECT 1')

        # Check license status
        license_status = "community"
        if license_manager and license_manager.license_key:
            try:
                license_info = license_manager.get_license_status_sync()
                if license_info.get('valid') and license_info.get('is_enterprise'):
                    license_status = "enterprise"
            except Exception as e:
                logger.warning(f"License check in health endpoint failed: {e}")
                license_status = "community"

        return {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': 'connected',
            'license': license_status
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        response.status = 503
        return {
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }


@action('/metrics')
@action.uses(CORS())
def metrics():
    """Prometheus metrics endpoint"""
    try:
        # Basic metrics
        total_users = db(db.auth_user).count()
        total_clusters = db(db.clusters.is_active == True).count()
        total_proxies = db(db.proxy_servers).count()
        active_proxies = db(db.proxy_servers.status == 'active').count()

        metrics_text = f"""# HELP marchproxy_users_total Total number of users
# TYPE marchproxy_users_total gauge
marchproxy_users_total {total_users}

# HELP marchproxy_clusters_total Total number of clusters
# TYPE marchproxy_clusters_total gauge
marchproxy_clusters_total {total_clusters}

# HELP marchproxy_proxies_total Total number of proxy servers
# TYPE marchproxy_proxies_total gauge
marchproxy_proxies_total {total_proxies}

# HELP marchproxy_proxies_active Number of active proxy servers
# TYPE marchproxy_proxies_active gauge
marchproxy_proxies_active {active_proxies}
"""

        response.headers['Content-Type'] = 'text/plain'
        return metrics_text

    except Exception as e:
        logger.error(f"Metrics collection failed: {e}")
        response.status = 500
        return f"# Error collecting metrics: {e}"


@action('/')
@action.uses(CORS())
def index():
    """Root endpoint"""
    return {
        'name': 'MarchProxy Manager',
        'version': '1.0.0',
        'api_version': 'v1',
        'authentication': 'py4web-native',
        'endpoints': {
            'health': '/healthz',
            'metrics': '/metrics',
            'auth': '/auth/*',
            'api': '/api/*'
        }
    }


# Initialize default data
def initialize_default_data():
    """Initialize default admin user and cluster"""
    try:
        # Create admin user using py4web auth
        admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
        admin_id = create_admin_user(auth, 'admin', 'admin@localhost', admin_password)

        # Create default cluster for Community edition
        existing_cluster = db(db.clusters.is_default == True).select().first()
        if not existing_cluster:
            cluster_id, api_key = ClusterModel.create_default_cluster(db, admin_id)
            logger.info(f"Created default cluster (ID: {cluster_id}, API Key: {api_key})")

        db.commit()

    except Exception as e:
        logger.error(f"Failed to initialize default data: {e}")


# Background task for proxy cleanup
def cleanup_stale_proxies():
    """Background task to clean up stale proxies"""
    try:
        cleaned = ProxyServerModel.cleanup_stale_proxies(db, timeout_minutes=10)
        if cleaned > 0:
            logger.info(f"Marked {cleaned} stale proxies as inactive")
    except Exception as e:
        logger.error(f"Proxy cleanup failed: {e}")


# Schedule proxy cleanup task
import threading
import time

def run_background_tasks():
    """Run background tasks periodically"""
    while True:
        try:
            cleanup_stale_proxies()
            # Also clean up old metrics
            ProxyMetricsModel.cleanup_old_metrics(db, days=30)
        except Exception as e:
            logger.error(f"Background task failed: {e}")
        time.sleep(300)  # Run every 5 minutes


# Start background thread
background_thread = threading.Thread(target=run_background_tasks, daemon=True)
background_thread.start()

# Initialize on startup
initialize_default_data()

# Schedule license keepalive if enterprise license is configured
if license_manager and license_manager.license_key:
    license_manager.schedule_keepalive(interval_hours=1)
    logger.info("License keepalive scheduled")

logger.info("MarchProxy Manager with py4web native auth started successfully")