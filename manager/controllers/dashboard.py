"""
Dashboard controller for MarchProxy Manager Web UI

Copyright (C) 2025 MarchProxy Contributors
Licensed under GNU Affero General Public License v3.0
"""

from py4web import action, request, response, redirect, URL
from py4web.utils.auth import Auth
from ..models.cluster import ClusterModel, UserClusterAssignmentModel
from ..models.proxy import ProxyServerModel
from ..models.license import LicenseManager
from ..models.auth_native import check_permission
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


@action('dashboard')
@action.uses('dashboard.html', auth, auth.user)
def dashboard():
    """Main dashboard view"""
    user = auth.get_user()

    # Get clusters based on user permissions
    if user.get('is_admin'):
        clusters = db(db.clusters.is_active == True).select(orderby=db.clusters.name)
    else:
        user_clusters = UserClusterAssignmentModel.get_user_clusters(db, user['id'])
        cluster_ids = [uc['cluster_id'] for uc in user_clusters]
        clusters = db(
            (db.clusters.id.belongs(cluster_ids)) &
            (db.clusters.is_active == True)
        ).select(orderby=db.clusters.name)

    # Calculate proxy statistics per cluster
    proxy_stats = {}
    for cluster in clusters:
        active_proxies = ClusterModel.count_active_proxies(db, cluster.id)
        max_proxies = cluster.max_proxies
        utilization = (active_proxies / max_proxies * 100) if max_proxies > 0 else 0

        proxy_stats[cluster.id] = {
            'active': active_proxies,
            'max': max_proxies,
            'utilization': utilization
        }

    # Get license information
    license_info = None
    if hasattr(globals(), 'license_manager') and license_manager:
        try:
            license_info = license_manager.get_license_status_sync()
        except Exception as e:
            logger.warning(f"License check failed: {e}")
            license_info = {'valid': False, 'edition': 'Community'}
    else:
        license_info = {'valid': False, 'edition': 'Community'}

    return dict(
        title="Dashboard",
        user=user,
        clusters=clusters,
        proxy_stats=proxy_stats,
        license_info=license_info
    )


@action('clusters')
@action.uses('clusters.html', auth, auth.user)
def clusters():
    """Clusters management view"""
    user = auth.get_user()

    # Get clusters based on user permissions
    if user.get('is_admin'):
        clusters = db(db.clusters.is_active == True).select(orderby=db.clusters.name)
    else:
        user_clusters = UserClusterAssignmentModel.get_user_clusters(db, user['id'])
        cluster_ids = [uc['cluster_id'] for uc in user_clusters]
        clusters = db(
            (db.clusters.id.belongs(cluster_ids)) &
            (db.clusters.is_active == True)
        ).select(orderby=db.clusters.name)

    # Add proxy count to each cluster
    for cluster in clusters:
        cluster.active_proxies = ClusterModel.count_active_proxies(db, cluster.id)

    return dict(
        title="Clusters",
        user=user,
        clusters=clusters,
        can_create=check_permission(auth, 'create_clusters')
    )


@action('clusters/create')
@action.uses('cluster_form.html', auth, auth.user)
def create_cluster():
    """Create cluster form"""
    user = auth.get_user()

    if not check_permission(auth, 'create_clusters'):
        redirect(URL('clusters'))

    if request.method == 'POST':
        data = request.forms

        try:
            cluster_id, api_key = ClusterModel.create_cluster(
                db,
                name=data.name,
                description=data.description,
                created_by=user['id'],
                syslog_endpoint=data.syslog_endpoint if data.syslog_endpoint else None,
                log_auth=bool(data.log_auth),
                log_netflow=bool(data.log_netflow),
                log_debug=bool(data.log_debug),
                max_proxies=int(data.max_proxies) if data.max_proxies else 3
            )

            # Store API key in flash message for display
            session.flash = f"Cluster created successfully. API Key: {api_key}"
            redirect(URL('clusters'))

        except Exception as e:
            logger.error(f"Cluster creation failed: {e}")
            session.flash = f"Failed to create cluster: {str(e)}"

    return dict(
        title="Create Cluster",
        user=user,
        form_action=URL('clusters/create'),
        cluster=None
    )


@action('clusters/<cluster_id:int>/edit')
@action.uses('cluster_form.html', auth, auth.user)
def edit_cluster(cluster_id):
    """Edit cluster form"""
    user = auth.get_user()

    if not check_permission(auth, 'update_clusters'):
        redirect(URL('clusters'))

    cluster = db.clusters[cluster_id]
    if not cluster:
        redirect(URL('clusters'))

    if request.method == 'POST':
        data = request.forms

        try:
            update_data = {
                'name': data.name,
                'description': data.description,
                'syslog_endpoint': data.syslog_endpoint if data.syslog_endpoint else None,
                'log_auth': bool(data.log_auth),
                'log_netflow': bool(data.log_netflow),
                'log_debug': bool(data.log_debug),
                'max_proxies': int(data.max_proxies) if data.max_proxies else 3,
                'updated_at': datetime.utcnow()
            }

            cluster.update_record(**update_data)
            session.flash = "Cluster updated successfully"
            redirect(URL('clusters'))

        except Exception as e:
            logger.error(f"Cluster update failed: {e}")
            session.flash = f"Failed to update cluster: {str(e)}"

    return dict(
        title="Edit Cluster",
        user=user,
        form_action=URL('clusters', cluster_id, 'edit'),
        cluster=cluster
    )


@action('proxies')
@action.uses('proxies.html', auth, auth.user)
def proxies():
    """Proxies management view"""
    user = auth.get_user()

    # Get proxies based on user permissions
    if user.get('is_admin'):
        proxies = db(
            db.proxy_servers.id > 0
        ).select(
            db.proxy_servers.ALL,
            db.clusters.name,
            left=db.clusters.on(db.clusters.id == db.proxy_servers.cluster_id),
            orderby=db.proxy_servers.name
        )
    else:
        user_clusters = UserClusterAssignmentModel.get_user_clusters(db, user['id'])
        cluster_ids = [uc['cluster_id'] for uc in user_clusters]
        proxies = db(
            db.proxy_servers.cluster_id.belongs(cluster_ids)
        ).select(
            db.proxy_servers.ALL,
            db.clusters.name,
            left=db.clusters.on(db.clusters.id == db.proxy_servers.cluster_id),
            orderby=db.proxy_servers.name
        )

    return dict(
        title="Proxies",
        user=user,
        proxies=proxies
    )


@action('services')
@action.uses('services.html', auth, auth.user)
def services():
    """Services management view"""
    user = auth.get_user()

    # Get services based on user permissions
    if user.get('is_admin'):
        services = db(
            db.services.is_active == True
        ).select(
            db.services.ALL,
            db.clusters.name,
            left=db.clusters.on(db.clusters.id == db.services.cluster_id),
            orderby=db.services.name
        )
    else:
        user_clusters = UserClusterAssignmentModel.get_user_clusters(db, user['id'])
        cluster_ids = [uc['cluster_id'] for uc in user_clusters]
        services = db(
            (db.services.cluster_id.belongs(cluster_ids)) &
            (db.services.is_active == True)
        ).select(
            db.services.ALL,
            db.clusters.name,
            left=db.clusters.on(db.clusters.id == db.services.cluster_id),
            orderby=db.services.name
        )

    return dict(
        title="Services",
        user=user,
        services=services,
        can_create=check_permission(auth, 'create_services')
    )


@action('mappings')
@action.uses('mappings.html', auth, auth.user)
def mappings():
    """Mappings management view"""
    user = auth.get_user()

    # Get mappings based on user permissions
    if user.get('is_admin'):
        mappings = db(
            db.mappings.is_active == True
        ).select(
            db.mappings.ALL,
            db.clusters.name,
            left=db.clusters.on(db.clusters.id == db.mappings.cluster_id),
            orderby=db.mappings.id
        )
    else:
        user_clusters = UserClusterAssignmentModel.get_user_clusters(db, user['id'])
        cluster_ids = [uc['cluster_id'] for uc in user_clusters]
        mappings = db(
            (db.mappings.cluster_id.belongs(cluster_ids)) &
            (db.mappings.is_active == True)
        ).select(
            db.mappings.ALL,
            db.clusters.name,
            left=db.clusters.on(db.clusters.id == db.mappings.cluster_id),
            orderby=db.mappings.id
        )

    return dict(
        title="Mappings",
        user=user,
        mappings=mappings,
        can_create=check_permission(auth, 'create_mappings')
    )


@action('certificates')
@action.uses('certificates.html', auth, auth.user)
def certificates():
    """Certificates management view"""
    user = auth.get_user()

    if not check_permission(auth, 'read_certificates'):
        redirect(URL('dashboard'))

    certificates = db(
        db.certificates.is_active == True
    ).select(orderby=db.certificates.name)

    return dict(
        title="Certificates",
        user=user,
        certificates=certificates,
        can_create=check_permission(auth, 'create_certificates')
    )


@action('users')
@action.uses('users.html', auth, auth.user)
def users():
    """Users management view (admin only)"""
    user = auth.get_user()

    if not user.get('is_admin'):
        redirect(URL('dashboard'))

    users = db(db.auth_user).select(orderby=db.auth_user.email)

    return dict(
        title="Users",
        user=user,
        users=users
    )


@action('license')
@action.uses('license.html', auth, auth.user)
def license():
    """License management view (admin only)"""
    user = auth.get_user()

    if not user.get('is_admin'):
        redirect(URL('dashboard'))

    # Get license information
    license_info = None
    if hasattr(globals(), 'license_manager') and license_manager:
        try:
            license_info = license_manager.get_license_status_sync()
        except Exception as e:
            logger.warning(f"License check failed: {e}")
            license_info = {'valid': False, 'edition': 'Community', 'error': str(e)}
    else:
        license_info = {'valid': False, 'edition': 'Community'}

    return dict(
        title="License",
        user=user,
        license_info=license_info
    )


@action('profile')
@action.uses('profile.html', auth, auth.user)
def profile():
    """User profile view"""
    user = auth.get_user()

    return dict(
        title="Profile",
        user=user
    )


@action('api_tokens')
@action.uses('api_tokens.html', auth, auth.user)
def api_tokens():
    """API tokens management view"""
    user = auth.get_user()

    # Get user's API tokens
    tokens = db(
        (db.api_tokens.user_id == user['id']) &
        (db.api_tokens.is_active == True)
    ).select(orderby=db.api_tokens.created_at)

    return dict(
        title="API Tokens",
        user=user,
        tokens=tokens
    )