"""
Proxy registration and management API endpoints for MarchProxy Manager

Copyright (C) 2025 MarchProxy Contributors
Licensed under GNU Affero General Public License v3.0
"""

from py4web import request, response
from py4web.utils.cors import enable_cors
from pydantic import ValidationError
import logging
from ..models.proxy import (
    ProxyServerModel, ProxyMetricsModel,
    ProxyRegistrationRequest, ProxyHeartbeatRequest, ProxyConfigRequest,
    ProxyResponse, ProxyStatsResponse, ProxyMetricsResponse
)
from ..models.cluster import ClusterModel
from .auth import _check_auth

logger = logging.getLogger(__name__)


def proxy_api(db, jwt_manager):
    """Proxy registration and management API endpoints"""

    @enable_cors()
    def register():
        """Register new proxy server"""
        if request.method == 'POST':
            try:
                data = ProxyRegistrationRequest(**request.json)
            except ValidationError as e:
                response.status = 400
                return {"error": "Validation error", "details": str(e)}

            # Register proxy with cluster API key validation
            proxy_id = ProxyServerModel.register_proxy(
                db,
                name=data.name,
                hostname=data.hostname,
                cluster_api_key=data.cluster_api_key,
                proxy_type=data.proxy_type,
                ip_address=data.ip_address,
                port=data.port,
                version=data.version,
                capabilities=data.capabilities
            )

            if not proxy_id:
                response.status = 400
                return {"error": "Registration failed - invalid API key or proxy limit exceeded"}

            proxy = db.proxy_servers[proxy_id]
            return {
                "proxy": ProxyResponse(
                    id=proxy.id,
                    name=proxy.name,
                    hostname=proxy.hostname,
                    ip_address=proxy.ip_address,
                    port=proxy.port,
                    cluster_id=proxy.cluster_id,
                    status=proxy.status,
                    version=proxy.version,
                    license_validated=proxy.license_validated,
                    last_seen=proxy.last_seen,
                    registered_at=proxy.registered_at
                ).dict(),
                "message": "Proxy registered successfully"
            }

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def heartbeat():
        """Proxy heartbeat endpoint"""
        if request.method == 'POST':
            try:
                data = ProxyHeartbeatRequest(**request.json)
            except ValidationError as e:
                response.status = 400
                return {"error": "Validation error", "details": str(e)}

            # Update heartbeat
            status_data = {}
            if data.version:
                status_data['version'] = data.version
            if data.capabilities:
                status_data['capabilities'] = data.capabilities
            if data.config_version:
                status_data['config_version'] = data.config_version

            success = ProxyServerModel.update_heartbeat(
                db, data.proxy_name, data.cluster_api_key, status_data
            )

            if not success:
                response.status = 400
                return {"error": "Heartbeat failed - invalid API key or proxy not found"}

            # Record metrics if provided
            if data.metrics:
                proxy = db(db.proxy_servers.name == data.proxy_name).select().first()
                if proxy:
                    ProxyMetricsModel.record_metrics(db, proxy.id, data.metrics)

            return {"message": "Heartbeat recorded successfully"}

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def get_config():
        """Get proxy configuration"""
        if request.method == 'POST':
            try:
                data = ProxyConfigRequest(**request.json)
            except ValidationError as e:
                response.status = 400
                return {"error": "Validation error", "details": str(e)}

            config = ProxyServerModel.get_proxy_config(
                db, data.proxy_name, data.cluster_api_key
            )

            if not config:
                response.status = 400
                return {"error": "Configuration retrieval failed - invalid API key or proxy not found"}

            return config

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def list_proxies():
        """List all proxies (authenticated endpoint)"""
        if request.method == 'GET':
            # Check authentication
            auth_result = _check_auth(db, jwt_manager)
            if 'error' in auth_result:
                response.status = auth_result['status']
                return auth_result

            user = auth_result['user']
            cluster_id = request.query.get('cluster_id')

            if user['is_admin']:
                # Admin can see all proxies
                if cluster_id:
                    proxies = ProxyServerModel.get_cluster_proxies(db, int(cluster_id))
                else:
                    # Get all proxies across clusters
                    all_proxies = db(db.proxy_servers).select()
                    proxies = [
                        {
                            'id': proxy.id,
                            'name': proxy.name,
                            'hostname': proxy.hostname,
                            'ip_address': proxy.ip_address,
                            'port': proxy.port,
                            'cluster_id': proxy.cluster_id,
                            'status': proxy.status,
                            'version': proxy.version,
                            'license_validated': proxy.license_validated,
                            'last_seen': proxy.last_seen,
                            'registered_at': proxy.registered_at
                        }
                        for proxy in all_proxies
                    ]
            else:
                # Regular user can only see proxies in their assigned clusters
                from ..models.cluster import UserClusterAssignmentModel
                user_clusters = UserClusterAssignmentModel.get_user_clusters(db, user['id'])
                cluster_ids = [uc['cluster_id'] for uc in user_clusters]

                if cluster_id and int(cluster_id) in cluster_ids:
                    proxies = ProxyServerModel.get_cluster_proxies(db, int(cluster_id))
                else:
                    # Get proxies from all user's clusters
                    proxies = []
                    for cid in cluster_ids:
                        proxies.extend(ProxyServerModel.get_cluster_proxies(db, cid))

            return {"proxies": proxies}

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def get_proxy(proxy_id):
        """Get proxy details"""
        if request.method == 'GET':
            # Check authentication
            auth_result = _check_auth(db, jwt_manager)
            if 'error' in auth_result:
                response.status = auth_result['status']
                return auth_result

            user = auth_result['user']

            proxy = db.proxy_servers[proxy_id]
            if not proxy:
                response.status = 404
                return {"error": "Proxy not found"}

            # Check access to proxy cluster
            if not user['is_admin']:
                from ..models.cluster import UserClusterAssignmentModel
                user_role = UserClusterAssignmentModel.check_user_cluster_access(db, user['id'], proxy.cluster_id)
                if not user_role:
                    response.status = 403
                    return {"error": "Access denied to proxy"}

            return ProxyResponse(
                id=proxy.id,
                name=proxy.name,
                hostname=proxy.hostname,
                ip_address=proxy.ip_address,
                port=proxy.port,
                cluster_id=proxy.cluster_id,
                status=proxy.status,
                version=proxy.version,
                license_validated=proxy.license_validated,
                last_seen=proxy.last_seen,
                registered_at=proxy.registered_at
            ).dict()

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def get_stats():
        """Get proxy statistics"""
        if request.method == 'GET':
            # Check authentication
            auth_result = _check_auth(db, jwt_manager)
            if 'error' in auth_result:
                response.status = auth_result['status']
                return auth_result

            user = auth_result['user']
            cluster_id = request.query.get('cluster_id')

            if cluster_id:
                cluster_id = int(cluster_id)
                # Check access to cluster
                if not user['is_admin']:
                    from ..models.cluster import UserClusterAssignmentModel
                    user_role = UserClusterAssignmentModel.check_user_cluster_access(db, user['id'], cluster_id)
                    if not user_role:
                        response.status = 403
                        return {"error": "Access denied to cluster"}

            stats = ProxyServerModel.get_proxy_stats(db, cluster_id)
            return ProxyStatsResponse(**stats).dict()

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def get_metrics(proxy_id):
        """Get proxy metrics"""
        if request.method == 'GET':
            # Check authentication
            auth_result = _check_auth(db, jwt_manager)
            if 'error' in auth_result:
                response.status = auth_result['status']
                return auth_result

            user = auth_result['user']

            proxy = db.proxy_servers[proxy_id]
            if not proxy:
                response.status = 404
                return {"error": "Proxy not found"}

            # Check access to proxy cluster
            if not user['is_admin']:
                from ..models.cluster import UserClusterAssignmentModel
                user_role = UserClusterAssignmentModel.check_user_cluster_access(db, user['id'], proxy.cluster_id)
                if not user_role:
                    response.status = 403
                    return {"error": "Access denied to proxy"}

            hours = int(request.query.get('hours', 24))
            metrics = ProxyMetricsModel.get_metrics(db, proxy_id, hours)

            return {
                "proxy_id": proxy_id,
                "metrics": [
                    ProxyMetricsResponse(
                        proxy_id=metric['proxy_id'],
                        timestamp=metric['timestamp'],
                        cpu_usage=metric['cpu_usage'],
                        memory_usage=metric['memory_usage'],
                        connections_active=metric['connections_active'],
                        connections_total=metric['connections_total'],
                        bytes_sent=metric['bytes_sent'],
                        bytes_received=metric['bytes_received'],
                        requests_per_second=metric['requests_per_second'],
                        latency_avg=metric['latency_avg'],
                        latency_p95=metric['latency_p95'],
                        errors_per_second=metric['errors_per_second']
                    ).dict() for metric in metrics
                ]
            }

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def cleanup_stale():
        """Cleanup stale proxy registrations (admin only)"""
        if request.method == 'POST':
            # Check authentication - admin required
            auth_result = _check_auth(db, jwt_manager, admin_required=True)
            if 'error' in auth_result:
                response.status = auth_result['status']
                return auth_result

            timeout_minutes = int(request.json.get('timeout_minutes', 10))
            cleaned_count = ProxyServerModel.cleanup_stale_proxies(db, timeout_minutes)

            return {
                "message": f"Cleaned up {cleaned_count} stale proxy registrations",
                "cleaned_count": cleaned_count
            }

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    # Return API endpoints
    return {
        'register': register,
        'heartbeat': heartbeat,
        'get_config': get_config,
        'list_proxies': list_proxies,
        'get_proxy': get_proxy,
        'get_stats': get_stats,
        'get_metrics': get_metrics,
        'cleanup_stale': cleanup_stale
    }