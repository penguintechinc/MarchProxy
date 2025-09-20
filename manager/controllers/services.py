"""
Service Management Controller for MarchProxy
Handles service CRUD operations, authentication management, and user assignments
"""

import json
import logging
from typing import Dict, Optional

from py4web import Field, HTTP, URL, abort, action, redirect, request, response, session
from py4web.utils.auth import Auth
from py4web.utils.form import Form, FormStyleBulma

from ..models import get_db
from ..services.license_service import LicenseService
from ..services.service_management import ServiceManagementService

logger = logging.getLogger(__name__)

# Initialize services
db = get_db()
auth = Auth(db)
license_service = LicenseService()
service_mgmt = ServiceManagementService(license_service, auth)


@action('services')
@action.uses('services/list.html', db, auth, session)
def services_list():
    """List services for current user"""
    if not auth.current_user:
        redirect(URL('auth/login'))

    cluster_id = request.query.get('cluster_id', type=int)
    page = request.query.get('page', 1, type=int)

    result = service_mgmt.list_services(
        user_id=auth.current_user.id,
        cluster_id=cluster_id,
        page=page
    )

    # Get available clusters for filter
    if auth.current_user.is_admin:
        clusters = db(db.clusters.is_active == True).select(orderby=db.clusters.name)
    else:
        clusters = db(
            (db.user_cluster_assignments.user_id == auth.current_user.id) &
            (db.user_cluster_assignments.cluster_id == db.clusters.id) &
            (db.clusters.is_active == True)
        ).select(db.clusters.ALL, orderby=db.clusters.name)

    return {
        'services': result['services'],
        'pagination': result['pagination'],
        'clusters': clusters,
        'current_cluster_id': cluster_id,
        'user': auth.current_user
    }


@action('services/create')
@action('services/create/<cluster_id:int>')
@action.uses('services/create.html', db, auth, session)
def services_create(cluster_id: Optional[int] = None):
    """Create new service"""
    if not auth.current_user:
        redirect(URL('auth/login'))

    # Get available clusters
    if auth.current_user.is_admin:
        clusters = db(db.clusters.is_active == True).select(orderby=db.clusters.name)
    else:
        clusters = db(
            (db.user_cluster_assignments.user_id == auth.current_user.id) &
            (db.user_cluster_assignments.cluster_id == db.clusters.id) &
            (db.clusters.is_active == True)
        ).select(db.clusters.ALL, orderby=db.clusters.name)

    if not clusters:
        abort(403, "No accessible clusters found")

    # Create form
    form = Form([
        Field('name', 'string', length=255, required=True,
              label='Service Name',
              comment='Unique name for the service'),
        Field('ip_fqdn', 'string', length=255, required=True,
              label='IP Address or FQDN',
              comment='Target IP address or fully qualified domain name'),
        Field('collection', 'string', length=100, default='default',
              label='Collection',
              comment='Service collection for grouping'),
        Field('cluster_id', 'reference clusters', required=True,
              label='Cluster',
              requires=IS_IN_SET([(c.id, c.name) for c in clusters])),
        Field('auth_type', 'string', default='none',
              label='Authentication Type',
              requires=IS_IN_SET([
                  ('none', 'No Authentication'),
                  ('token', 'Base64 Token'),
                  ('jwt', 'JWT Token')
              ], zero=None)),
        Field('description', 'text',
              label='Description',
              comment='Optional service description')
    ], formstyle=FormStyleBulma)

    # Set default cluster if provided
    if cluster_id and not form.vars.cluster_id:
        form.vars.cluster_id = cluster_id

    if form.accepted:
        try:
            service = service_mgmt.create_service(
                service_data=form.vars,
                user_id=auth.current_user.id
            )

            session.flash = f"Service '{service['name']}' created successfully"
            redirect(URL('services', 'view', service['id']))

        except Exception as e:
            logger.error(f"Service creation failed: {e}")
            form.errors['_general'] = str(e)

    return {
        'form': form,
        'clusters': clusters,
        'title': 'Create Service'
    }


@action('services/view/<service_id:int>')
@action.uses('services/view.html', db, auth, session)
def services_view(service_id: int):
    """View service details"""
    if not auth.current_user:
        redirect(URL('auth/login'))

    try:
        service = service_mgmt.get_service(
            service_id=service_id,
            user_id=auth.current_user.id,
            include_secrets=True
        )

        # Get service assignments
        assignments = db(
            db.user_service_assignments.service_id == service_id
        ).select(
            db.user_service_assignments.ALL,
            db.auth_user.username,
            db.auth_user.email,
            left=db.auth_user.on(db.auth_user.id == db.user_service_assignments.user_id)
        )

        # Get cluster info
        cluster = db.clusters[service['cluster_id']]

        # Check write access
        has_write_access = service_mgmt._user_has_service_write_access(
            auth.current_user.id, service_id
        )

        return {
            'service': service,
            'cluster': cluster,
            'assignments': assignments,
            'has_write_access': has_write_access,
            'user': auth.current_user
        }

    except Exception as e:
        logger.error(f"Service view failed: {e}")
        abort(404 if 'not found' in str(e).lower() else 403, str(e))


@action('services/edit/<service_id:int>')
@action.uses('services/edit.html', db, auth, session)
def services_edit(service_id: int):
    """Edit service"""
    if not auth.current_user:
        redirect(URL('auth/login'))

    try:
        service = service_mgmt.get_service(
            service_id=service_id,
            user_id=auth.current_user.id,
            include_secrets=True
        )

        # Check write access
        if not service_mgmt._user_has_service_write_access(auth.current_user.id, service_id):
            abort(403, "Write access denied")

        # Get available clusters
        if auth.current_user.is_admin:
            clusters = db(db.clusters.is_active == True).select(orderby=db.clusters.name)
        else:
            clusters = db(
                (db.user_cluster_assignments.user_id == auth.current_user.id) &
                (db.user_cluster_assignments.cluster_id == db.clusters.id) &
                (db.clusters.is_active == True)
            ).select(db.clusters.ALL, orderby=db.clusters.name)

        # Create form with current values
        form = Form([
            Field('name', 'string', length=255, required=True,
                  label='Service Name', default=service['name']),
            Field('ip_fqdn', 'string', length=255, required=True,
                  label='IP Address or FQDN', default=service['ip_fqdn']),
            Field('collection', 'string', length=100,
                  label='Collection', default=service['collection']),
            Field('cluster_id', 'reference clusters', required=True,
                  label='Cluster', default=service['cluster_id'],
                  requires=IS_IN_SET([(c.id, c.name) for c in clusters])),
            Field('auth_type', 'string', required=True,
                  label='Authentication Type', default=service['auth_type'],
                  requires=IS_IN_SET([
                      ('none', 'No Authentication'),
                      ('token', 'Base64 Token'),
                      ('jwt', 'JWT Token')
                  ], zero=None)),
            Field('description', 'text',
                  label='Description', default=service['description'])
        ], formstyle=FormStyleBulma)

        if form.accepted:
            try:
                updated_service = service_mgmt.update_service(
                    service_id=service_id,
                    service_data=form.vars,
                    user_id=auth.current_user.id
                )

                session.flash = f"Service '{updated_service['name']}' updated successfully"
                redirect(URL('services', 'view', service_id))

            except Exception as e:
                logger.error(f"Service update failed: {e}")
                form.errors['_general'] = str(e)

        return {
            'form': form,
            'service': service,
            'clusters': clusters,
            'title': f'Edit Service: {service["name"]}'
        }

    except Exception as e:
        logger.error(f"Service edit failed: {e}")
        abort(404 if 'not found' in str(e).lower() else 403, str(e))


@action('services/delete/<service_id:int>', method=['POST'])
@action.uses(db, auth, session)
def services_delete(service_id: int):
    """Delete service"""
    if not auth.current_user:
        abort(401, "Authentication required")

    try:
        service_mgmt.delete_service(
            service_id=service_id,
            user_id=auth.current_user.id
        )

        session.flash = "Service deleted successfully"
        redirect(URL('services'))

    except Exception as e:
        logger.error(f"Service deletion failed: {e}")
        session.flash = f"Error deleting service: {str(e)}"
        redirect(URL('services', 'view', service_id))


# API Endpoints

@action('api/services', method=['GET'])
@action.uses(db, auth)
def api_services_list():
    """API: List services"""
    if not auth.current_user:
        abort(401, "Authentication required")

    cluster_id = request.query.get('cluster_id', type=int)
    page = request.query.get('page', 1, type=int)
    per_page = min(request.query.get('per_page', 50, type=int), 100)

    try:
        result = service_mgmt.list_services(
            user_id=auth.current_user.id,
            cluster_id=cluster_id,
            page=page,
            per_page=per_page
        )

        return {"status": "success", "data": result}

    except Exception as e:
        logger.error(f"API services list failed: {e}")
        abort(500, "Internal server error")


@action('api/services', method=['POST'])
@action.uses(db, auth)
def api_services_create():
    """API: Create service"""
    if not auth.current_user:
        abort(401, "Authentication required")

    try:
        service_data = json.loads(request.body.read())
        service = service_mgmt.create_service(
            service_data=service_data,
            user_id=auth.current_user.id
        )

        return {"status": "success", "data": service}

    except json.JSONDecodeError:
        abort(400, "Invalid JSON")
    except Exception as e:
        logger.error(f"API service creation failed: {e}")
        abort(400, str(e))


@action('api/services/<service_id:int>', method=['GET'])
@action.uses(db, auth)
def api_services_get(service_id: int):
    """API: Get service"""
    if not auth.current_user:
        abort(401, "Authentication required")

    try:
        include_secrets = request.query.get('include_secrets') == 'true'
        service = service_mgmt.get_service(
            service_id=service_id,
            user_id=auth.current_user.id,
            include_secrets=include_secrets
        )

        return {"status": "success", "data": service}

    except Exception as e:
        logger.error(f"API service get failed: {e}")
        abort(404 if 'not found' in str(e).lower() else 403, str(e))


@action('api/services/<service_id:int>', method=['PUT'])
@action.uses(db, auth)
def api_services_update(service_id: int):
    """API: Update service"""
    if not auth.current_user:
        abort(401, "Authentication required")

    try:
        service_data = json.loads(request.body.read())
        service = service_mgmt.update_service(
            service_id=service_id,
            service_data=service_data,
            user_id=auth.current_user.id
        )

        return {"status": "success", "data": service}

    except json.JSONDecodeError:
        abort(400, "Invalid JSON")
    except Exception as e:
        logger.error(f"API service update failed: {e}")
        abort(400, str(e))


@action('api/services/<service_id:int>', method=['DELETE'])
@action.uses(db, auth)
def api_services_delete(service_id: int):
    """API: Delete service"""
    if not auth.current_user:
        abort(401, "Authentication required")

    try:
        service_mgmt.delete_service(
            service_id=service_id,
            user_id=auth.current_user.id
        )

        return {"status": "success", "message": "Service deleted"}

    except Exception as e:
        logger.error(f"API service deletion failed: {e}")
        abort(403 if 'access denied' in str(e).lower() else 404, str(e))


# Authentication Management Endpoints

@action('api/services/<service_id:int>/rotate-jwt', method=['POST'])
@action.uses(db, auth)
def api_rotate_jwt(service_id: int):
    """API: Rotate JWT secret"""
    if not auth.current_user:
        abort(401, "Authentication required")

    try:
        result = service_mgmt.rotate_jwt_secret(
            service_id=service_id,
            user_id=auth.current_user.id
        )

        return {"status": "success", "data": result}

    except Exception as e:
        logger.error(f"JWT rotation failed: {e}")
        abort(400, str(e))


@action('api/services/<service_id:int>/finalize-jwt-rotation', method=['POST'])
@action.uses(db, auth)
def api_finalize_jwt_rotation(service_id: int):
    """API: Finalize JWT rotation"""
    if not auth.current_user:
        abort(401, "Authentication required")

    try:
        service_mgmt.finalize_jwt_rotation(
            service_id=service_id,
            user_id=auth.current_user.id
        )

        return {"status": "success", "message": "JWT rotation finalized"}

    except Exception as e:
        logger.error(f"JWT rotation finalization failed: {e}")
        abort(400, str(e))


@action('api/services/<service_id:int>/regenerate-token', method=['POST'])
@action.uses(db, auth)
def api_regenerate_token(service_id: int):
    """API: Regenerate Base64 token"""
    if not auth.current_user:
        abort(401, "Authentication required")

    try:
        result = service_mgmt.regenerate_token(
            service_id=service_id,
            user_id=auth.current_user.id
        )

        return {"status": "success", "data": result}

    except Exception as e:
        logger.error(f"Token regeneration failed: {e}")
        abort(400, str(e))


# User Assignment Endpoints

@action('api/services/<service_id:int>/assign-user', method=['POST'])
@action.uses(db, auth)
def api_assign_user(service_id: int):
    """API: Assign user to service"""
    if not auth.current_user:
        abort(401, "Authentication required")

    try:
        data = json.loads(request.body.read())
        service_mgmt.assign_user_to_service(
            service_id=service_id,
            target_user_id=data['user_id'],
            role=data['role'],
            assigner_user_id=auth.current_user.id
        )

        return {"status": "success", "message": "User assigned"}

    except json.JSONDecodeError:
        abort(400, "Invalid JSON")
    except Exception as e:
        logger.error(f"User assignment failed: {e}")
        abort(400, str(e))


@action('api/services/<service_id:int>/remove-user', method=['POST'])
@action.uses(db, auth)
def api_remove_user(service_id: int):
    """API: Remove user from service"""
    if not auth.current_user:
        abort(401, "Authentication required")

    try:
        data = json.loads(request.body.read())
        service_mgmt.remove_user_from_service(
            service_id=service_id,
            target_user_id=data['user_id'],
            remover_user_id=auth.current_user.id
        )

        return {"status": "success", "message": "User removed"}

    except json.JSONDecodeError:
        abort(400, "Invalid JSON")
    except Exception as e:
        logger.error(f"User removal failed: {e}")
        abort(400, str(e))


# Configuration endpoint for proxy
@action('api/services/auth-config')
@action.uses(db)
def api_services_auth_config():
    """API: Get service authentication configuration for proxy"""
    # This endpoint is called by proxy servers, authenticate via API key
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        abort(401, "API key required")

    # Validate API key and get cluster
    cluster = db(db.clusters.api_key == api_key).select().first()
    if not cluster:
        abort(401, "Invalid API key")

    # Get all services for this cluster
    services = db(
        (db.services.cluster_id == cluster.id) &
        (db.services.is_active == True)
    ).select()

    auth_configs = {}
    for service in services:
        config = service_mgmt.get_service_auth_config(service.id)
        if config:
            auth_configs[f"{service.ip_fqdn}:{service.collection}"] = config

    return {"status": "success", "data": auth_configs}