"""
Ingress Routes API endpoints for MarchProxy Manager

Provides API endpoints for managing ingress route configuration for
reverse proxy functionality including host/path-based routing, load balancing,
and backend service management.
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional

from py4web import action, request, response, abort, HTTP
from py4web.utils.cors import CORS
from pydal.validators import *

from ..common import (
    auth, db, require_auth, require_admin, require_license_feature,
    create_audit_log, check_permission
)

cors = CORS()


@action('api/ingress-routes', method=['GET'])
@action.uses(cors, auth, require_auth)
def list_ingress_routes():
    """Get all ingress routes for the user's accessible clusters"""

    # Get user's accessible clusters
    user_id = auth.get_user()['id']
    is_admin = auth.get_user().get('is_admin', False)

    if is_admin:
        # Admin can see all routes
        routes = db(db.ingress_routes.is_active == True).select(
            db.ingress_routes.ALL,
            db.clusters.name.with_alias('cluster_name'),
            left=db.clusters.on(db.clusters.id == db.ingress_routes.cluster_id),
            orderby=~db.ingress_routes.priority
        )
    else:
        # Non-admin users see only routes in their assigned clusters
        user_clusters = db(db.user_cluster_assignments.user_id == user_id).select(
            db.user_cluster_assignments.cluster_id
        )
        cluster_ids = [row.cluster_id for row in user_clusters]

        if not cluster_ids:
            return {"routes": []}

        routes = db(
            (db.ingress_routes.cluster_id.belongs(cluster_ids)) &
            (db.ingress_routes.is_active == True)
        ).select(
            db.ingress_routes.ALL,
            db.clusters.name.with_alias('cluster_name'),
            left=db.clusters.on(db.clusters.id == db.ingress_routes.cluster_id),
            orderby=~db.ingress_routes.priority
        )

    route_list = []
    for route in routes:
        route_dict = route.ingress_routes.as_dict()
        route_dict['cluster_name'] = route.cluster_name

        # Include backend service names
        if route_dict.get('backend_services'):
            service_ids = route_dict['backend_services']
            services = db(db.services.id.belongs(service_ids)).select(
                db.services.id, db.services.name
            )
            route_dict['backend_service_names'] = [
                {"id": s.id, "name": s.name} for s in services
            ]

        route_list.append(route_dict)

    return {"routes": route_list}


@action('api/ingress-routes/<route_id:int>', method=['GET'])
@action.uses(cors, auth, require_auth)
def get_ingress_route(route_id):
    """Get a specific ingress route by ID"""

    user_id = auth.get_user()['id']
    is_admin = auth.get_user().get('is_admin', False)

    # Check if route exists and user has access
    if is_admin:
        route = db(
            (db.ingress_routes.id == route_id) &
            (db.ingress_routes.is_active == True)
        ).select().first()
    else:
        user_clusters = db(db.user_cluster_assignments.user_id == user_id).select(
            db.user_cluster_assignments.cluster_id
        )
        cluster_ids = [row.cluster_id for row in user_clusters]

        route = db(
            (db.ingress_routes.id == route_id) &
            (db.ingress_routes.cluster_id.belongs(cluster_ids)) &
            (db.ingress_routes.is_active == True)
        ).select().first()

    if not route:
        abort(404, "Ingress route not found")

    route_dict = route.as_dict()

    # Include backend service details
    if route_dict.get('backend_services'):
        service_ids = route_dict['backend_services']
        services = db(db.services.id.belongs(service_ids)).select()
        route_dict['backend_service_details'] = [s.as_dict() for s in services]

    return {"route": route_dict}


@action('api/ingress-routes', method=['POST'])
@action.uses(cors, auth, require_auth)
def create_ingress_route():
    """Create a new ingress route"""

    user_id = auth.get_user()['id']
    is_admin = auth.get_user().get('is_admin', False)

    data = request.json
    if not data:
        abort(400, "Invalid JSON data")

    # Validate required fields
    required_fields = ['name', 'cluster_id', 'backend_services']
    for field in required_fields:
        if field not in data:
            abort(400, f"Missing required field: {field}")

    cluster_id = data['cluster_id']

    # Check cluster access
    if not is_admin:
        user_cluster = db(
            (db.user_cluster_assignments.user_id == user_id) &
            (db.user_cluster_assignments.cluster_id == cluster_id)
        ).select().first()
        if not user_cluster:
            abort(403, "Access denied to cluster")

    # Validate cluster exists
    cluster = db(db.clusters.id == cluster_id).select().first()
    if not cluster:
        abort(400, "Invalid cluster ID")

    # Validate backend services exist and belong to the cluster
    backend_service_ids = data['backend_services']
    if not isinstance(backend_service_ids, list) or not backend_service_ids:
        abort(400, "backend_services must be a non-empty array")

    services = db(
        (db.services.id.belongs(backend_service_ids)) &
        (db.services.cluster_id == cluster_id)
    ).select()

    if len(services) != len(backend_service_ids):
        abort(400, "One or more backend services not found in the specified cluster")

    # Validate routing patterns
    host_pattern = data.get('host_pattern', '')
    path_pattern = data.get('path_pattern', '')

    if not host_pattern and not path_pattern:
        abort(400, "At least one of host_pattern or path_pattern must be specified")

    # Check for conflicting routes
    conflicts = db(
        (db.ingress_routes.cluster_id == cluster_id) &
        (db.ingress_routes.host_pattern == host_pattern) &
        (db.ingress_routes.path_pattern == path_pattern) &
        (db.ingress_routes.is_active == True)
    ).select()

    if conflicts:
        abort(400, "A route with the same host and path patterns already exists")

    # Create the route
    route_data = {
        'name': data['name'],
        'description': data.get('description', ''),
        'cluster_id': cluster_id,
        'host_pattern': host_pattern,
        'path_pattern': path_pattern,
        'priority': data.get('priority', 100),
        'backend_services': backend_service_ids,
        'load_balancer_algorithm': data.get('load_balancer_algorithm', 'round_robin'),
        'service_weights': data.get('service_weights'),
        'require_mtls': data.get('require_mtls', False),
        'allowed_client_cns': data.get('allowed_client_cns'),
        'tls_server_name': data.get('tls_server_name'),
        'health_check_enabled': data.get('health_check_enabled', True),
        'health_check_path': data.get('health_check_path', '/healthz'),
        'health_check_interval': data.get('health_check_interval', 30),
        'health_check_timeout': data.get('health_check_timeout', 5),
        'health_check_threshold': data.get('health_check_threshold', 3),
        'rate_limit_enabled': data.get('rate_limit_enabled', False),
        'rate_limit_rps': data.get('rate_limit_rps', 1000),
        'ddos_protection_enabled': data.get('ddos_protection_enabled', False),
        'ddos_threshold_pps': data.get('ddos_threshold_pps', 10000),
        'request_headers': data.get('request_headers'),
        'response_headers': data.get('response_headers'),
        'strip_prefix': data.get('strip_prefix'),
        'add_prefix': data.get('add_prefix'),
        'created_by': user_id
    }

    route_id = db.ingress_routes.insert(**route_data)

    # Create audit log
    create_audit_log(
        user_id=user_id,
        event_type="ingress_route_created",
        resource_type="ingress_route",
        resource_id=route_id,
        details={
            "route_name": data['name'],
            "cluster_id": cluster_id,
            "host_pattern": host_pattern,
            "path_pattern": path_pattern
        }
    )

    # Invalidate configuration cache for the cluster
    db(db.config_cache.cluster_id == cluster_id).delete()

    return {
        "message": "Ingress route created successfully",
        "route_id": route_id
    }


@action('api/ingress-routes/<route_id:int>', method=['PUT'])
@action.uses(cors, auth, require_auth)
def update_ingress_route(route_id):
    """Update an existing ingress route"""

    user_id = auth.get_user()['id']
    is_admin = auth.get_user().get('is_admin', False)

    data = request.json
    if not data:
        abort(400, "Invalid JSON data")

    # Get existing route
    if is_admin:
        route = db(
            (db.ingress_routes.id == route_id) &
            (db.ingress_routes.is_active == True)
        ).select().first()
    else:
        user_clusters = db(db.user_cluster_assignments.user_id == user_id).select(
            db.user_cluster_assignments.cluster_id
        )
        cluster_ids = [row.cluster_id for row in user_clusters]

        route = db(
            (db.ingress_routes.id == route_id) &
            (db.ingress_routes.cluster_id.belongs(cluster_ids)) &
            (db.ingress_routes.is_active == True)
        ).select().first()

    if not route:
        abort(404, "Ingress route not found")

    # Validate backend services if provided
    if 'backend_services' in data:
        backend_service_ids = data['backend_services']
        if not isinstance(backend_service_ids, list) or not backend_service_ids:
            abort(400, "backend_services must be a non-empty array")

        services = db(
            (db.services.id.belongs(backend_service_ids)) &
            (db.services.cluster_id == route.cluster_id)
        ).select()

        if len(services) != len(backend_service_ids):
            abort(400, "One or more backend services not found in the route's cluster")

    # Check for conflicts if routing patterns are changing
    if 'host_pattern' in data or 'path_pattern' in data:
        new_host = data.get('host_pattern', route.host_pattern)
        new_path = data.get('path_pattern', route.path_pattern)

        conflicts = db(
            (db.ingress_routes.cluster_id == route.cluster_id) &
            (db.ingress_routes.host_pattern == new_host) &
            (db.ingress_routes.path_pattern == new_path) &
            (db.ingress_routes.id != route_id) &
            (db.ingress_routes.is_active == True)
        ).select()

        if conflicts:
            abort(400, "A route with the same host and path patterns already exists")

    # Update the route
    update_data = {}
    updateable_fields = [
        'name', 'description', 'host_pattern', 'path_pattern', 'priority',
        'backend_services', 'load_balancer_algorithm', 'service_weights',
        'require_mtls', 'allowed_client_cns', 'tls_server_name',
        'health_check_enabled', 'health_check_path', 'health_check_interval',
        'health_check_timeout', 'health_check_threshold', 'rate_limit_enabled',
        'rate_limit_rps', 'ddos_protection_enabled', 'ddos_threshold_pps',
        'request_headers', 'response_headers', 'strip_prefix', 'add_prefix'
    ]

    for field in updateable_fields:
        if field in data:
            update_data[field] = data[field]

    if update_data:
        db(db.ingress_routes.id == route_id).update(**update_data)

        # Create audit log
        create_audit_log(
            user_id=user_id,
            event_type="ingress_route_updated",
            resource_type="ingress_route",
            resource_id=route_id,
            details={
                "route_name": route.name,
                "updated_fields": list(update_data.keys())
            }
        )

        # Invalidate configuration cache for the cluster
        db(db.config_cache.cluster_id == route.cluster_id).delete()

    return {"message": "Ingress route updated successfully"}


@action('api/ingress-routes/<route_id:int>', method=['DELETE'])
@action.uses(cors, auth, require_auth)
def delete_ingress_route(route_id):
    """Delete (deactivate) an ingress route"""

    user_id = auth.get_user()['id']
    is_admin = auth.get_user().get('is_admin', False)

    # Get existing route
    if is_admin:
        route = db(
            (db.ingress_routes.id == route_id) &
            (db.ingress_routes.is_active == True)
        ).select().first()
    else:
        user_clusters = db(db.user_cluster_assignments.user_id == user_id).select(
            db.user_cluster_assignments.cluster_id
        )
        cluster_ids = [row.cluster_id for row in user_clusters]

        route = db(
            (db.ingress_routes.id == route_id) &
            (db.ingress_routes.cluster_id.belongs(cluster_ids)) &
            (db.ingress_routes.is_active == True)
        ).select().first()

    if not route:
        abort(404, "Ingress route not found")

    # Soft delete (deactivate)
    db(db.ingress_routes.id == route_id).update(is_active=False)

    # Create audit log
    create_audit_log(
        user_id=user_id,
        event_type="ingress_route_deleted",
        resource_type="ingress_route",
        resource_id=route_id,
        details={
            "route_name": route.name,
            "cluster_id": route.cluster_id
        }
    )

    # Invalidate configuration cache for the cluster
    db(db.config_cache.cluster_id == route.cluster_id).delete()

    return {"message": "Ingress route deleted successfully"}


@action('api/clusters/<cluster_id:int>/ingress-routes', method=['GET'])
@action.uses(cors, auth, require_auth)
def get_cluster_ingress_routes(cluster_id):
    """Get all ingress routes for a specific cluster"""

    user_id = auth.get_user()['id']
    is_admin = auth.get_user().get('is_admin', False)

    # Check cluster access
    if not is_admin:
        user_cluster = db(
            (db.user_cluster_assignments.user_id == user_id) &
            (db.user_cluster_assignments.cluster_id == cluster_id)
        ).select().first()
        if not user_cluster:
            abort(403, "Access denied to cluster")

    # Validate cluster exists
    cluster = db(db.clusters.id == cluster_id).select().first()
    if not cluster:
        abort(404, "Cluster not found")

    routes = db(
        (db.ingress_routes.cluster_id == cluster_id) &
        (db.ingress_routes.is_active == True)
    ).select(orderby=~db.ingress_routes.priority)

    route_list = []
    for route in routes:
        route_dict = route.as_dict()

        # Include backend service names
        if route_dict.get('backend_services'):
            service_ids = route_dict['backend_services']
            services = db(db.services.id.belongs(service_ids)).select(
                db.services.id, db.services.name
            )
            route_dict['backend_service_names'] = [
                {"id": s.id, "name": s.name} for s in services
            ]

        route_list.append(route_dict)

    return {
        "cluster_id": cluster_id,
        "cluster_name": cluster.name,
        "routes": route_list
    }