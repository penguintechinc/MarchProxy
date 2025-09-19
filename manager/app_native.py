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


# Proxy registration using API key authentication
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
        if LICENSE_KEY:
            license_status = "enterprise"

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


# Initialize on startup
initialize_default_data()
logger.info("MarchProxy Manager with py4web native auth started successfully")