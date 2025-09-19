"""
MarchProxy Manager Application using py4web native features

Copyright (C) 2025 MarchProxy Contributors
Licensed under GNU Affero General Public License v3.0
"""

import os
import sys
from py4web import action, request, response, abort, redirect, URL
from py4web.utils.cors import enable_cors
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

# Commit database changes
db.commit()

# Initialize managers
totp_manager = TOTPManager(auth)
token_manager = APITokenManager(auth)

# Initialize license manager
LICENSE_KEY = os.environ.get('LICENSE_KEY')
license_manager = LicenseManager(db, LICENSE_KEY)

# Setup auth groups and permissions
groups = setup_auth_groups(auth)


# Authentication endpoints using py4web native features
@action('/auth/<path:path>')
@action.uses(auth)
def auth_handler(path):
    """Handle py4web native auth endpoints"""
    return auth.navbar


@action('/api/auth/profile', methods=['GET', 'PUT'])
@action.uses(auth, auth.user)
@enable_cors()
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
@action.uses(auth, auth.user)
@enable_cors()
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
@action.uses(auth, auth.user)
@enable_cors()
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
@action.uses(auth, auth.user)
@enable_cors()
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
@action.uses(auth, auth.user)
@enable_cors()
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
@action.uses(auth, auth.user)
@enable_cors()
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
@action.uses(auth, auth.user)
@enable_cors()
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
@action.uses(auth, auth.user)
@enable_cors()
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
@action.uses(auth, auth.user)
@enable_cors()
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
@action.uses(auth, auth.user)
@enable_cors()
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
@enable_cors()
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
@action.uses(auth)
@enable_cors()
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
@enable_cors()
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
@enable_cors()
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
@enable_cors()
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
@action.uses(auth, auth.user)
@enable_cors()
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
@action.uses(auth, auth.user)
@enable_cors()
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
@enable_cors()
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
@action.uses(auth, auth.user)
@enable_cors()
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
@action.uses(auth, auth.user)
@enable_cors()
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
@action.uses(auth, auth.user)
@enable_cors()
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
@action.uses(auth, auth.user)
@enable_cors()
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
@action.uses(auth, auth.user)
@enable_cors()
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
@action.uses(auth, auth.user)
@enable_cors()
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


# Health endpoints
@action('/healthz')
@enable_cors()
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
@enable_cors()
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
@enable_cors()
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