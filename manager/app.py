"""
Main MarchProxy Manager Application

Copyright (C) 2025 MarchProxy Contributors
Licensed under GNU Affero General Public License v3.0
"""

import os
import sys
from py4web import application, URL, request, response, abort
from pydal import DAL, Field
from py4web.utils.cors import enable_cors
import logging
from datetime import datetime

# Add the manager directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models.auth import UserModel, SessionModel, APITokenModel, JWTManager
from models.cluster import ClusterModel, UserClusterAssignmentModel
from models.proxy import ProxyServerModel, ProxyMetricsModel
from models.license import LicenseCacheModel, LicenseManager
from models.service import ServiceModel, UserServiceAssignmentModel
from models.mapping import MappingModel
from models.certificate import CertificateModel

from api.auth import auth_api
from api.clusters import clusters_api
from api.proxy import proxy_api

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

# Define all database tables
UserModel.define_table(db)
SessionModel.define_table(db)
APITokenModel.define_table(db)
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

# Initialize JWT manager
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-super-secret-jwt-key-change-in-production')
jwt_manager = JWTManager(JWT_SECRET)

# Initialize license manager
LICENSE_KEY = os.environ.get('LICENSE_KEY')
license_manager = LicenseManager(db, LICENSE_KEY)

# Initialize API endpoints
auth_endpoints = auth_api(db, jwt_manager)
cluster_endpoints = clusters_api(db, jwt_manager)
proxy_endpoints = proxy_api(db, jwt_manager)

# Register API routes
def _call_endpoint(endpoint_func):
    """Helper to call API endpoints"""
    try:
        return endpoint_func()
    except Exception as e:
        logger.error(f"API endpoint error: {e}")
        response.status = 500
        return {"error": "Internal server error"}

# Authentication routes
@application.route('/api/auth/login', methods=['POST'])
def login():
    return _call_endpoint(auth_endpoints['login'])

@application.route('/api/auth/logout', methods=['POST'])
def logout():
    return _call_endpoint(auth_endpoints['logout'])

@application.route('/api/auth/register', methods=['POST'])
def register():
    return _call_endpoint(auth_endpoints['register'])

@application.route('/api/auth/refresh', methods=['POST'])
def refresh_token():
    return _call_endpoint(auth_endpoints['refresh_token'])

@application.route('/api/auth/2fa/enable', methods=['POST'])
def enable_2fa():
    return _call_endpoint(auth_endpoints['enable_2fa'])

@application.route('/api/auth/2fa/verify', methods=['POST'])
def verify_2fa():
    return _call_endpoint(auth_endpoints['verify_2fa'])

@application.route('/api/auth/2fa/disable', methods=['POST'])
def disable_2fa():
    return _call_endpoint(auth_endpoints['disable_2fa'])

@application.route('/api/auth/profile', methods=['GET', 'PUT'])
def profile():
    return _call_endpoint(auth_endpoints['profile'])

# Cluster routes
@application.route('/api/clusters', methods=['GET', 'POST'])
def clusters():
    if request.method == 'GET':
        return _call_endpoint(cluster_endpoints['list_clusters'])
    else:
        return _call_endpoint(cluster_endpoints['create_cluster'])

@application.route('/api/clusters/<int:cluster_id>', methods=['GET', 'PUT'])
def cluster_detail(cluster_id):
    if request.method == 'GET':
        return _call_endpoint(lambda: cluster_endpoints['get_cluster'](cluster_id))
    else:
        return _call_endpoint(lambda: cluster_endpoints['update_cluster'](cluster_id))

@application.route('/api/clusters/<int:cluster_id>/rotate-key', methods=['POST'])
def rotate_cluster_key(cluster_id):
    return _call_endpoint(lambda: cluster_endpoints['rotate_api_key'](cluster_id))

@application.route('/api/clusters/<int:cluster_id>/logging', methods=['PUT'])
def update_cluster_logging(cluster_id):
    return _call_endpoint(lambda: cluster_endpoints['update_logging_config'](cluster_id))

@application.route('/api/clusters/<int:cluster_id>/assign-user', methods=['POST'])
def assign_user_to_cluster(cluster_id):
    return _call_endpoint(lambda: cluster_endpoints['assign_user'](cluster_id))

@application.route('/api/config/<int:cluster_id>', methods=['GET'])
def get_cluster_config(cluster_id):
    return _call_endpoint(lambda: cluster_endpoints['get_config'](cluster_id))

# Proxy routes
@application.route('/api/proxy/register', methods=['POST'])
def proxy_register():
    return _call_endpoint(proxy_endpoints['register'])

@application.route('/api/proxy/heartbeat', methods=['POST'])
def proxy_heartbeat():
    return _call_endpoint(proxy_endpoints['heartbeat'])

@application.route('/api/proxy/config', methods=['POST'])
def proxy_get_config():
    return _call_endpoint(proxy_endpoints['get_config'])

@application.route('/api/proxies', methods=['GET'])
def list_proxies():
    return _call_endpoint(proxy_endpoints['list_proxies'])

@application.route('/api/proxies/<int:proxy_id>', methods=['GET'])
def get_proxy_detail(proxy_id):
    return _call_endpoint(lambda: proxy_endpoints['get_proxy'](proxy_id))

@application.route('/api/proxies/stats', methods=['GET'])
def get_proxy_stats():
    return _call_endpoint(proxy_endpoints['get_stats'])

@application.route('/api/proxies/<int:proxy_id>/metrics', methods=['GET'])
def get_proxy_metrics(proxy_id):
    return _call_endpoint(lambda: proxy_endpoints['get_metrics'](proxy_id))

@application.route('/api/proxies/cleanup', methods=['POST'])
def cleanup_stale_proxies():
    return _call_endpoint(proxy_endpoints['cleanup_stale'])

# Health and status endpoints
@application.route('/healthz', methods=['GET'])
@enable_cors()
def health_check():
    """Health check endpoint"""
    try:
        # Test database connectivity
        db.executesql('SELECT 1')

        # Check license status if configured
        license_status = "community"
        if LICENSE_KEY:
            license_status = "enterprise"

        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "database": "connected",
            "license": license_status
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        response.status = 503
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

@application.route('/metrics', methods=['GET'])
@enable_cors()
def metrics():
    """Prometheus metrics endpoint"""
    try:
        # Basic metrics
        total_users = db(db.users).count()
        active_users = db(db.users.is_active == True).count()
        total_clusters = db(db.clusters.is_active == True).count()
        total_proxies = db(db.proxy_servers).count()
        active_proxies = db(db.proxy_servers.status == 'active').count()
        total_services = db(db.services.is_active == True).count()
        total_mappings = db(db.mappings.is_active == True).count()

        metrics_text = f"""# HELP marchproxy_users_total Total number of users
# TYPE marchproxy_users_total gauge
marchproxy_users_total {total_users}

# HELP marchproxy_users_active Number of active users
# TYPE marchproxy_users_active gauge
marchproxy_users_active {active_users}

# HELP marchproxy_clusters_total Total number of clusters
# TYPE marchproxy_clusters_total gauge
marchproxy_clusters_total {total_clusters}

# HELP marchproxy_proxies_total Total number of proxy servers
# TYPE marchproxy_proxies_total gauge
marchproxy_proxies_total {total_proxies}

# HELP marchproxy_proxies_active Number of active proxy servers
# TYPE marchproxy_proxies_active gauge
marchproxy_proxies_active {active_proxies}

# HELP marchproxy_services_total Total number of services
# TYPE marchproxy_services_total gauge
marchproxy_services_total {total_services}

# HELP marchproxy_mappings_total Total number of mappings
# TYPE marchproxy_mappings_total gauge
marchproxy_mappings_total {total_mappings}
"""

        response.headers['Content-Type'] = 'text/plain'
        return metrics_text

    except Exception as e:
        logger.error(f"Metrics collection failed: {e}")
        response.status = 500
        return f"# Error collecting metrics: {e}"

@application.route('/license-status', methods=['GET'])
@enable_cors()
def license_status():
    """License status endpoint for proxy validation"""
    try:
        if not LICENSE_KEY:
            return {
                "tier": "community",
                "is_valid": True,
                "max_proxies": 3,
                "active_proxies": db(db.proxy_servers.status == 'active').count()
            }

        # Get cached license data
        from models.license import LicenseCacheModel
        license_data = LicenseCacheModel.get_cached_validation(db, LICENSE_KEY)

        if not license_data:
            return {
                "tier": "enterprise",
                "is_valid": False,
                "error": "License validation required"
            }

        return {
            "tier": "enterprise" if license_data['is_enterprise'] else "community",
            "is_valid": license_data['is_valid'],
            "max_proxies": license_data['max_proxies'],
            "active_proxies": db(db.proxy_servers.status == 'active').count(),
            "expires_at": license_data['expires_at'].isoformat() if license_data['expires_at'] else None
        }

    except Exception as e:
        logger.error(f"License status check failed: {e}")
        response.status = 500
        return {"error": str(e)}

# Root endpoint
@application.route('/', methods=['GET'])
@enable_cors()
def index():
    """Root endpoint with API information"""
    return {
        "name": "MarchProxy Manager",
        "version": "1.0.0",
        "api_version": "v1",
        "endpoints": {
            "health": "/healthz",
            "metrics": "/metrics",
            "license_status": "/license-status",
            "auth": "/api/auth/*",
            "clusters": "/api/clusters/*",
            "proxies": "/api/proxies/*",
            "proxy_api": "/api/proxy/*"
        }
    }

# Initialize default data
def initialize_default_data():
    """Initialize default admin user and cluster"""
    try:
        # Create default admin user if not exists
        admin_user = db(db.users.username == 'admin').select().first()
        if not admin_user:
            admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
            password_hash = UserModel.hash_password(admin_password)

            admin_id = db.users.insert(
                username='admin',
                email='admin@localhost',
                password_hash=password_hash,
                is_admin=True
            )

            logger.info(f"Created default admin user (ID: {admin_id})")

            # Create default cluster for Community edition
            cluster_id, api_key = ClusterModel.create_default_cluster(db, admin_id)
            logger.info(f"Created default cluster (ID: {cluster_id}, API Key: {api_key})")

            # Store the API key in environment for easy access
            if api_key:
                logger.info(f"Default cluster API key: {api_key}")

        db.commit()

    except Exception as e:
        logger.error(f"Failed to initialize default data: {e}")

# Initialize on startup
if __name__ == '__main__':
    initialize_default_data()
    logger.info("MarchProxy Manager started successfully")
else:
    # Initialize when imported by py4web
    initialize_default_data()