"""
Enterprise Authentication Controller for MarchProxy
Handles SAML, OAuth2, and SCIM endpoints
"""

import json
import logging
from datetime import datetime
from typing import Dict, Optional

from py4web import Field, HTTP, URL, abort, action, redirect, request, response, session
from py4web.utils.auth import Auth

from ..models import get_db
from ..services.auth.oauth2_service import OAuth2Service
from ..services.auth.saml_service import SAMLService
from ..services.auth.scim_service import SCIMService
from ..services.license_service import LicenseService

logger = logging.getLogger(__name__)

# Initialize services
db = get_db()
auth = Auth(db)
license_service = LicenseService()
saml_service = SAMLService(auth, license_service)
oauth2_service = OAuth2Service(auth, license_service)
scim_service = SCIMService(auth, license_service)


@action('auth/enterprise')
@action.uses('enterprise_auth.html', db, auth, session)
def enterprise_auth():
    """Enterprise authentication selection page"""
    if not license_service.is_enterprise():
        abort(403, "Enterprise features not available")

    available_providers = []

    # Add SAML if configured
    if saml_service.is_enabled():
        available_providers.append({
            'type': 'saml',
            'name': 'SAML SSO',
            'url': URL('auth/saml/login'),
            'icon': 'fas fa-building'
        })

    # Add OAuth2 providers
    oauth2_providers = oauth2_service.get_available_providers()
    for provider in oauth2_providers:
        provider['type'] = 'oauth2'
        provider['icon'] = _get_provider_icon(provider['key'])
    available_providers.extend(oauth2_providers)

    return {
        'providers': available_providers,
        'license_info': license_service.get_license_info()
    }


def _get_provider_icon(provider_key: str) -> str:
    """Get icon class for OAuth2 provider"""
    icons = {
        'google': 'fab fa-google',
        'microsoft': 'fab fa-microsoft',
        'github': 'fab fa-github',
        'azure': 'fab fa-microsoft'
    }
    return icons.get(provider_key, 'fas fa-key')


# SAML Authentication Endpoints

@action('auth/saml/login')
@action.uses(db, session)
def saml_login():
    """Initiate SAML SSO login"""
    if not saml_service.is_enabled():
        abort(403, "SAML authentication not available")

    relay_state = request.query.get('RelayState')
    sso_url = saml_service.initiate_sso(relay_state)

    logger.info("Redirecting to SAML IdP for authentication")
    redirect(sso_url)


@action('auth/saml/acs', method=['POST'])
@action.uses(db, auth, session)
def saml_acs():
    """SAML Assertion Consumer Service"""
    if not saml_service.is_enabled():
        abort(403, "SAML authentication not available")

    saml_response = request.forms.get('SAMLResponse')
    relay_state = request.forms.get('RelayState')

    if not saml_response:
        abort(400, "Missing SAML response")

    try:
        user = saml_service.process_saml_response(saml_response, relay_state)

        # Authenticate user in py4web
        auth.login_user(user['id'])

        logger.info(f"SAML user {user['email']} authenticated successfully")

        # Redirect to original destination or dashboard
        redirect_url = relay_state or URL('dashboard')
        redirect(redirect_url)

    except Exception as e:
        logger.error(f"SAML authentication failed: {e}")
        abort(401, f"SAML authentication failed: {str(e)}")


@action('auth/saml/sls')
@action.uses(db, auth, session)
def saml_sls():
    """SAML Single Logout Service"""
    if not saml_service.is_enabled():
        abort(403, "SAML authentication not available")

    # Log out current user
    if auth.current_user:
        logger.info(f"SAML logout for user: {auth.current_user.email}")
        auth.logout()

    # Redirect to login page
    redirect(URL('auth/login'))


@action('auth/saml/metadata')
@action.uses()
def saml_metadata():
    """SAML Service Provider metadata"""
    if not saml_service.is_enabled():
        abort(403, "SAML authentication not available")

    metadata_xml = saml_service.generate_metadata()

    response.headers['Content-Type'] = 'application/xml'
    return metadata_xml


# OAuth2 Authentication Endpoints

@action('auth/oauth2/login')
@action.uses(db, session)
def oauth2_login():
    """Initiate OAuth2 authentication"""
    provider = request.query.get('provider')
    redirect_uri = request.query.get('redirect_uri')

    if not provider:
        abort(400, "Provider parameter required")

    if not oauth2_service.is_enabled(provider):
        abort(403, f"OAuth2 provider '{provider}' not available")

    oauth_url = oauth2_service.initiate_oauth2_flow(provider, redirect_uri)

    logger.info(f"Redirecting to {provider} OAuth2 for authentication")
    redirect(oauth_url)


@action('auth/oauth2/callback')
@action.uses(db, auth, session)
def oauth2_callback():
    """OAuth2 authorization callback"""
    provider = request.query.get('provider')
    code = request.query.get('code')
    state = request.query.get('state')
    error = request.query.get('error')

    if not provider:
        abort(400, "Provider parameter required")

    if error:
        logger.error(f"OAuth2 error from {provider}: {error}")
        abort(401, f"OAuth2 authentication failed: {error}")

    if not code or not state:
        abort(400, "Missing authorization code or state")

    try:
        user = oauth2_service.handle_oauth2_callback(provider, code, state)

        # Authenticate user in py4web
        auth.login_user(user['id'])

        logger.info(f"OAuth2 user {user['email']} authenticated successfully via {provider}")

        # Redirect to original destination or dashboard
        redirect_uri = session.get(f'oauth2_redirect_{provider}') or URL('dashboard')
        redirect(redirect_uri)

    except Exception as e:
        logger.error(f"OAuth2 authentication failed for {provider}: {e}")
        abort(401, f"OAuth2 authentication failed: {str(e)}")


# SCIM Provisioning Endpoints

@action('api/scim/v2/ServiceProviderConfig')
@action.uses()
def scim_service_provider_config():
    """SCIM Service Provider Configuration"""
    if not scim_service.is_enabled():
        abort(403, "SCIM provisioning not available")

    response.headers['Content-Type'] = 'application/scim+json'
    return json.dumps(scim_service.get_service_provider_config())


@action('api/scim/v2/ResourceTypes')
@action.uses()
def scim_resource_types():
    """SCIM Resource Types"""
    if not scim_service.is_enabled():
        abort(403, "SCIM provisioning not available")

    response.headers['Content-Type'] = 'application/scim+json'
    return json.dumps({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 2,
        "Resources": scim_service.get_resource_types()
    })


@action('api/scim/v2/Schemas')
@action.uses()
def scim_schemas():
    """SCIM Schemas"""
    if not scim_service.is_enabled():
        abort(403, "SCIM provisioning not available")

    response.headers['Content-Type'] = 'application/scim+json'
    return json.dumps({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 1,
        "Resources": scim_service.get_schemas()
    })


@action('api/scim/v2/Users', method=['GET'])
@action.uses(db)
def scim_list_users():
    """SCIM List Users"""
    if not scim_service.is_enabled():
        abort(403, "SCIM provisioning not available")

    # Parse query parameters
    start_index = int(request.query.get('startIndex', 1))
    count = int(request.query.get('count', 100))
    filter_expr = request.query.get('filter')

    result = scim_service.list_users(start_index, count, filter_expr)

    response.headers['Content-Type'] = 'application/scim+json'
    return json.dumps(result)


@action('api/scim/v2/Users', method=['POST'])
@action.uses(db)
def scim_create_user():
    """SCIM Create User"""
    if not scim_service.is_enabled():
        abort(403, "SCIM provisioning not available")

    try:
        user_data = json.loads(request.body.read())
        user = scim_service.create_user(user_data)

        response.status = 201
        response.headers['Content-Type'] = 'application/scim+json'
        response.headers['Location'] = f"/api/scim/v2/Users/{user['id']}"
        return json.dumps(user)

    except json.JSONDecodeError:
        abort(400, "Invalid JSON in request body")
    except Exception as e:
        logger.error(f"SCIM user creation failed: {e}")
        abort(400, str(e))


@action('api/scim/v2/Users/<user_id>', method=['GET'])
@action.uses(db)
def scim_get_user(user_id):
    """SCIM Get User"""
    if not scim_service.is_enabled():
        abort(403, "SCIM provisioning not available")

    user = scim_service.get_user(user_id)

    response.headers['Content-Type'] = 'application/scim+json'
    return json.dumps(user)


@action('api/scim/v2/Users/<user_id>', method=['PUT'])
@action.uses(db)
def scim_update_user(user_id):
    """SCIM Update User"""
    if not scim_service.is_enabled():
        abort(403, "SCIM provisioning not available")

    try:
        user_data = json.loads(request.body.read())
        user = scim_service.update_user(user_id, user_data)

        response.headers['Content-Type'] = 'application/scim+json'
        return json.dumps(user)

    except json.JSONDecodeError:
        abort(400, "Invalid JSON in request body")
    except Exception as e:
        logger.error(f"SCIM user update failed: {e}")
        abort(400, str(e))


@action('api/scim/v2/Users/<user_id>', method=['PATCH'])
@action.uses(db)
def scim_patch_user(user_id):
    """SCIM Patch User"""
    if not scim_service.is_enabled():
        abort(403, "SCIM provisioning not available")

    try:
        patch_data = json.loads(request.body.read())
        user = scim_service.patch_user(user_id, patch_data)

        response.headers['Content-Type'] = 'application/scim+json'
        return json.dumps(user)

    except json.JSONDecodeError:
        abort(400, "Invalid JSON in request body")
    except Exception as e:
        logger.error(f"SCIM user patch failed: {e}")
        abort(400, str(e))


@action('api/scim/v2/Users/<user_id>', method=['DELETE'])
@action.uses(db)
def scim_delete_user(user_id):
    """SCIM Delete User"""
    if not scim_service.is_enabled():
        abort(403, "SCIM provisioning not available")

    scim_service.delete_user(user_id)
    response.status = 204
    return ""


@action('api/scim/v2/Groups', method=['GET'])
@action.uses(db)
def scim_list_groups():
    """SCIM List Groups"""
    if not scim_service.is_enabled():
        abort(403, "SCIM provisioning not available")

    result = scim_service.get_groups()

    response.headers['Content-Type'] = 'application/scim+json'
    return json.dumps(result)


# Authentication utilities

def require_enterprise():
    """Decorator to require enterprise license"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not license_service.is_enterprise():
                abort(403, "Enterprise license required")
            return func(*args, **kwargs)
        return wrapper
    return decorator


def get_current_auth_provider():
    """Get current user's authentication provider"""
    if auth.current_user:
        return auth.current_user.auth_provider
    return None


def is_external_user():
    """Check if current user is from external provider"""
    provider = get_current_auth_provider()
    return provider and provider != 'local'