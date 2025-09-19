"""
Cluster management API endpoints for MarchProxy Manager

Copyright (C) 2025 MarchProxy Contributors
Licensed under GNU Affero General Public License v3.0
"""

from py4web import request, response
from py4web.utils.cors import enable_cors
from pydantic import ValidationError
import logging
from datetime import datetime
from ..models.cluster import (
    ClusterModel, UserClusterAssignmentModel,
    CreateClusterRequest, UpdateClusterRequest, ClusterResponse,
    AssignUserToClusterRequest
)
from .auth import _check_auth

logger = logging.getLogger(__name__)


def clusters_api(db, jwt_manager):
    """Cluster management API endpoints"""

    @enable_cors()
    def list_clusters():
        """List all clusters"""
        if request.method == 'GET':
            # Check authentication
            auth_result = _check_auth(db, jwt_manager)
            if 'error' in auth_result:
                response.status = auth_result['status']
                return auth_result

            user = auth_result['user']

            if user['is_admin']:
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
                result.append(ClusterResponse(
                    id=cluster.id,
                    name=cluster.name,
                    description=cluster.description,
                    syslog_endpoint=cluster.syslog_endpoint,
                    log_auth=cluster.log_auth,
                    log_netflow=cluster.log_netflow,
                    log_debug=cluster.log_debug,
                    is_active=cluster.is_active,
                    is_default=cluster.is_default,
                    max_proxies=cluster.max_proxies,
                    active_proxies=active_proxies,
                    created_at=cluster.created_at,
                    updated_at=cluster.updated_at
                ).dict())

            return {"clusters": result}

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def create_cluster():
        """Create new cluster (Enterprise only)"""
        if request.method == 'POST':
            # Check authentication - admin required
            auth_result = _check_auth(db, jwt_manager, admin_required=True)
            if 'error' in auth_result:
                response.status = auth_result['status']
                return auth_result

            try:
                data = CreateClusterRequest(**request.json)
            except ValidationError as e:
                response.status = 400
                return {"error": "Validation error", "details": str(e)}

            # Check if cluster name already exists
            existing = db(db.clusters.name == data.name).select().first()
            if existing:
                response.status = 409
                return {"error": "Cluster name already exists"}

            # Create cluster
            try:
                cluster_id, api_key = ClusterModel.create_cluster(
                    db,
                    name=data.name,
                    description=data.description,
                    created_by=auth_result['user']['id'],
                    syslog_endpoint=data.syslog_endpoint,
                    log_auth=data.log_auth,
                    log_netflow=data.log_netflow,
                    log_debug=data.log_debug,
                    max_proxies=data.max_proxies
                )

                cluster = db.clusters[cluster_id]
                return {
                    "cluster": ClusterResponse(
                        id=cluster.id,
                        name=cluster.name,
                        description=cluster.description,
                        syslog_endpoint=cluster.syslog_endpoint,
                        log_auth=cluster.log_auth,
                        log_netflow=cluster.log_netflow,
                        log_debug=cluster.log_debug,
                        is_active=cluster.is_active,
                        is_default=cluster.is_default,
                        max_proxies=cluster.max_proxies,
                        active_proxies=0,
                        created_at=cluster.created_at,
                        updated_at=cluster.updated_at
                    ).dict(),
                    "api_key": api_key,
                    "message": "Cluster created successfully"
                }

            except Exception as e:
                logger.error(f"Cluster creation failed: {e}")
                response.status = 500
                return {"error": "Failed to create cluster"}

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def get_cluster(cluster_id):
        """Get cluster details"""
        if request.method == 'GET':
            # Check authentication
            auth_result = _check_auth(db, jwt_manager)
            if 'error' in auth_result:
                response.status = auth_result['status']
                return auth_result

            user = auth_result['user']

            # Check access to cluster
            if not user['is_admin']:
                user_role = UserClusterAssignmentModel.check_user_cluster_access(db, user['id'], cluster_id)
                if not user_role:
                    response.status = 403
                    return {"error": "Access denied to cluster"}

            cluster = db((db.clusters.id == cluster_id) & (db.clusters.is_active == True)).select().first()
            if not cluster:
                response.status = 404
                return {"error": "Cluster not found"}

            active_proxies = ClusterModel.count_active_proxies(db, cluster.id)

            return ClusterResponse(
                id=cluster.id,
                name=cluster.name,
                description=cluster.description,
                syslog_endpoint=cluster.syslog_endpoint,
                log_auth=cluster.log_auth,
                log_netflow=cluster.log_netflow,
                log_debug=cluster.log_debug,
                is_active=cluster.is_active,
                is_default=cluster.is_default,
                max_proxies=cluster.max_proxies,
                active_proxies=active_proxies,
                created_at=cluster.created_at,
                updated_at=cluster.updated_at
            ).dict()

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def update_cluster(cluster_id):
        """Update cluster configuration"""
        if request.method == 'PUT':
            # Check authentication - admin required
            auth_result = _check_auth(db, jwt_manager, admin_required=True)
            if 'error' in auth_result:
                response.status = auth_result['status']
                return auth_result

            try:
                data = UpdateClusterRequest(**request.json)
            except ValidationError as e:
                response.status = 400
                return {"error": "Validation error", "details": str(e)}

            cluster = db.clusters[cluster_id]
            if not cluster:
                response.status = 404
                return {"error": "Cluster not found"}

            # Update cluster
            update_data = {'updated_at': datetime.utcnow()}

            if data.name is not None:
                # Check name uniqueness
                existing = db((db.clusters.name == data.name) & (db.clusters.id != cluster_id)).select().first()
                if existing:
                    response.status = 409
                    return {"error": "Cluster name already exists"}
                update_data['name'] = data.name

            if data.description is not None:
                update_data['description'] = data.description
            if data.syslog_endpoint is not None:
                update_data['syslog_endpoint'] = data.syslog_endpoint
            if data.log_auth is not None:
                update_data['log_auth'] = data.log_auth
            if data.log_netflow is not None:
                update_data['log_netflow'] = data.log_netflow
            if data.log_debug is not None:
                update_data['log_debug'] = data.log_debug
            if data.max_proxies is not None:
                update_data['max_proxies'] = data.max_proxies

            cluster.update_record(**update_data)

            active_proxies = ClusterModel.count_active_proxies(db, cluster.id)

            return ClusterResponse(
                id=cluster.id,
                name=cluster.name,
                description=cluster.description,
                syslog_endpoint=cluster.syslog_endpoint,
                log_auth=cluster.log_auth,
                log_netflow=cluster.log_netflow,
                log_debug=cluster.log_debug,
                is_active=cluster.is_active,
                is_default=cluster.is_default,
                max_proxies=cluster.max_proxies,
                active_proxies=active_proxies,
                created_at=cluster.created_at,
                updated_at=cluster.updated_at
            ).dict()

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def rotate_api_key(cluster_id):
        """Rotate cluster API key"""
        if request.method == 'POST':
            # Check authentication - admin required
            auth_result = _check_auth(db, jwt_manager, admin_required=True)
            if 'error' in auth_result:
                response.status = auth_result['status']
                return auth_result

            cluster = db.clusters[cluster_id]
            if not cluster:
                response.status = 404
                return {"error": "Cluster not found"}

            new_api_key = ClusterModel.rotate_api_key(db, cluster_id)
            if not new_api_key:
                response.status = 500
                return {"error": "Failed to rotate API key"}

            return {
                "api_key": new_api_key,
                "message": "API key rotated successfully"
            }

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def update_logging_config(cluster_id):
        """Update cluster logging configuration"""
        if request.method == 'PUT':
            # Check authentication - admin required
            auth_result = _check_auth(db, jwt_manager, admin_required=True)
            if 'error' in auth_result:
                response.status = auth_result['status']
                return auth_result

            data = request.json

            success = ClusterModel.update_logging_config(
                db, cluster_id,
                syslog_endpoint=data.get('syslog_endpoint'),
                log_auth=data.get('log_auth'),
                log_netflow=data.get('log_netflow'),
                log_debug=data.get('log_debug')
            )

            if not success:
                response.status = 404
                return {"error": "Cluster not found"}

            return {"message": "Logging configuration updated successfully"}

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def assign_user(cluster_id):
        """Assign user to cluster"""
        if request.method == 'POST':
            # Check authentication - admin required
            auth_result = _check_auth(db, jwt_manager, admin_required=True)
            if 'error' in auth_result:
                response.status = auth_result['status']
                return auth_result

            try:
                data = AssignUserToClusterRequest(**request.json)
            except ValidationError as e:
                response.status = 400
                return {"error": "Validation error", "details": str(e)}

            # Check if cluster exists
            cluster = db.clusters[cluster_id]
            if not cluster:
                response.status = 404
                return {"error": "Cluster not found"}

            # Check if user exists
            user = db.users[data.user_id]
            if not user:
                response.status = 404
                return {"error": "User not found"}

            # Assign user to cluster
            success = UserClusterAssignmentModel.assign_user_to_cluster(
                db, data.user_id, cluster_id, data.role, auth_result['user']['id']
            )

            if success:
                return {"message": "User assigned to cluster successfully"}
            else:
                response.status = 500
                return {"error": "Failed to assign user to cluster"}

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def get_config(cluster_id):
        """Get cluster configuration for proxy (API key authenticated)"""
        if request.method == 'GET':
            # This endpoint uses API key authentication instead of JWT
            api_key = request.environ.get('HTTP_X_API_KEY') or request.query.get('api_key')
            if not api_key:
                response.status = 401
                return {"error": "API key required"}

            # Validate cluster API key
            cluster_info = ClusterModel.validate_api_key(db, api_key)
            if not cluster_info or cluster_info['cluster_id'] != int(cluster_id):
                response.status = 401
                return {"error": "Invalid API key for cluster"}

            # Get cluster configuration
            config = ClusterModel.get_cluster_config(db, cluster_id)
            if not config:
                response.status = 404
                return {"error": "Cluster configuration not found"}

            return config

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    # Return API endpoints
    return {
        'list_clusters': list_clusters,
        'create_cluster': create_cluster,
        'get_cluster': get_cluster,
        'update_cluster': update_cluster,
        'rotate_api_key': rotate_api_key,
        'update_logging_config': update_logging_config,
        'assign_user': assign_user,
        'get_config': get_config
    }