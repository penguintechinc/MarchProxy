"""
Enterprise authentication API endpoints for MarchProxy Manager

Copyright (C) 2025 MarchProxy Contributors
Licensed under GNU Affero General Public License v3.0
"""

from py4web import request, response, redirect
from py4web.utils.cors import enable_cors
from pydantic import ValidationError
import json
import secrets
import logging
from urllib.parse import quote
from ..models.enterprise_auth import (
    EnterpriseAuthProviderModel, EnterpriseAuthManager, SCIMUserModel,
    CreateSAMLProviderRequest, CreateOAuth2ProviderRequest, SCIMUserRequest,
    EnterpriseAuthProviderResponse
)
from ..models.auth import JWTManager, SessionModel
from .auth import _check_auth

logger = logging.getLogger(__name__)


def enterprise_auth_api(db, jwt_manager: JWTManager, base_url: str):
    """Enterprise authentication API endpoints"""

    auth_manager = EnterpriseAuthManager(db, base_url)

    @enable_cors()
    def list_providers():
        """List enterprise auth providers"""
        if request.method == 'GET':
            # Check authentication - admin required
            auth_result = _check_auth(db, jwt_manager, admin_required=True)
            if 'error' in auth_result:
                response.status = auth_result['status']
                return auth_result

            providers = db(
                db.enterprise_auth_providers.is_active == True
            ).select(orderby=db.enterprise_auth_providers.name)

            result = []
            for provider in providers:
                result.append(EnterpriseAuthProviderResponse(
                    id=provider.id,
                    name=provider.name,
                    provider_type=provider.provider_type,
                    is_active=provider.is_active,
                    auto_provision=provider.auto_provision,
                    default_role=provider.default_role,
                    created_at=provider.created_at
                ).dict())

            return {"providers": result}

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def create_saml_provider():
        """Create SAML authentication provider"""
        if request.method == 'POST':
            # Check authentication - admin required
            auth_result = _check_auth(db, jwt_manager, admin_required=True)
            if 'error' in auth_result:
                response.status = auth_result['status']
                return auth_result

            try:
                data = CreateSAMLProviderRequest(**request.json)
            except ValidationError as e:
                response.status = 400
                return {"error": "Validation error", "details": str(e)}

            # Check if provider name already exists
            existing = db(db.enterprise_auth_providers.name == data.name).select().first()
            if existing:
                response.status = 409
                return {"error": "Provider name already exists"}

            # Create SAML configuration
            saml_config = {
                'idp_sso_url': data.idp_sso_url,
                'idp_x509_cert': data.idp_x509_cert,
                'sp_entity_id': data.sp_entity_id,
                'idp_entity_id': data.idp_entity_id or data.sp_entity_id,
                'idp_slo_url': data.idp_slo_url,
                'sp_private_key': data.sp_private_key,
                'sp_x509_cert': data.sp_x509_cert
            }

            try:
                provider_id = EnterpriseAuthProviderModel.create_saml_provider(
                    db, data.name, saml_config, auth_result['user']['id'],
                    data.auto_provision, data.default_role
                )

                provider = db.enterprise_auth_providers[provider_id]
                return {
                    "provider": EnterpriseAuthProviderResponse(
                        id=provider.id,
                        name=provider.name,
                        provider_type=provider.provider_type,
                        is_active=provider.is_active,
                        auto_provision=provider.auto_provision,
                        default_role=provider.default_role,
                        created_at=provider.created_at
                    ).dict(),
                    "saml_metadata_url": f"{base_url}/api/auth/saml/{data.name}/metadata",
                    "saml_acs_url": f"{base_url}/api/auth/saml/{data.name}/acs",
                    "message": "SAML provider created successfully"
                }

            except Exception as e:
                logger.error(f"SAML provider creation failed: {e}")
                response.status = 500
                return {"error": "Failed to create SAML provider"}

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def create_oauth2_provider():
        """Create OAuth2 authentication provider"""
        if request.method == 'POST':
            # Check authentication - admin required
            auth_result = _check_auth(db, jwt_manager, admin_required=True)
            if 'error' in auth_result:
                response.status = auth_result['status']
                return auth_result

            try:
                data = CreateOAuth2ProviderRequest(**request.json)
            except ValidationError as e:
                response.status = 400
                return {"error": "Validation error", "details": str(e)}

            # Check if provider name already exists
            existing = db(db.enterprise_auth_providers.name == data.name).select().first()
            if existing:
                response.status = 409
                return {"error": "Provider name already exists"}

            # Create OAuth2 configuration
            oauth2_config = {
                'client_id': data.client_id,
                'client_secret': data.client_secret,
                'auth_url': data.auth_url,
                'token_url': data.token_url,
                'user_info_url': data.user_info_url,
                'scope': data.scope
            }

            try:
                provider_id = EnterpriseAuthProviderModel.create_oauth2_provider(
                    db, data.name, oauth2_config, auth_result['user']['id'],
                    data.auto_provision, data.default_role
                )

                provider = db.enterprise_auth_providers[provider_id]
                return {
                    "provider": EnterpriseAuthProviderResponse(
                        id=provider.id,
                        name=provider.name,
                        provider_type=provider.provider_type,
                        is_active=provider.is_active,
                        auto_provision=provider.auto_provision,
                        default_role=provider.default_role,
                        created_at=provider.created_at
                    ).dict(),
                    "oauth2_redirect_url": f"{base_url}/api/auth/oauth2/{data.name}/callback",
                    "oauth2_login_url": f"{base_url}/api/auth/oauth2/{data.name}/login",
                    "message": "OAuth2 provider created successfully"
                }

            except Exception as e:
                logger.error(f"OAuth2 provider creation failed: {e}")
                response.status = 500
                return {"error": "Failed to create OAuth2 provider"}

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def saml_metadata(provider_name):
        """Get SAML metadata for provider"""
        if request.method == 'GET':
            saml_auth = auth_manager.get_saml_authenticator(provider_name)
            if not saml_auth:
                response.status = 404
                return {"error": "SAML provider not found"}

            try:
                metadata = saml_auth.saml_client.config.metadata.to_string()
                response.headers['Content-Type'] = 'application/xml'
                return metadata
            except Exception as e:
                logger.error(f"SAML metadata generation failed: {e}")
                response.status = 500
                return {"error": "Failed to generate SAML metadata"}

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def saml_login(provider_name):
        """Initiate SAML login"""
        if request.method == 'GET':
            saml_auth = auth_manager.get_saml_authenticator(provider_name)
            if not saml_auth:
                response.status = 404
                return {"error": "SAML provider not found"}

            try:
                relay_state = request.query.get('relay_state', '/')
                req_id, redirect_url = saml_auth.create_auth_request(relay_state)

                # Store request ID in session for validation
                # In a real implementation, you'd use a proper session store

                return redirect(redirect_url)

            except Exception as e:
                logger.error(f"SAML login initiation failed: {e}")
                response.status = 500
                return {"error": "Failed to initiate SAML login"}

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def saml_acs(provider_name):
        """SAML Assertion Consumer Service"""
        if request.method == 'POST':
            saml_auth = auth_manager.get_saml_authenticator(provider_name)
            if not saml_auth:
                response.status = 404
                return {"error": "SAML provider not found"}

            try:
                saml_response = request.forms.get('SAMLResponse')
                relay_state = request.forms.get('RelayState', '/')

                if not saml_response:
                    response.status = 400
                    return {"error": "Missing SAML response"}

                # Process SAML response
                user_data = saml_auth.process_response(saml_response)
                if not user_data:
                    response.status = 400
                    return {"error": "Invalid SAML response"}

                # Provision or update user
                user_id = auth_manager.provision_user_from_external(provider_name, user_data)
                if not user_id:
                    response.status = 400
                    return {"error": "User provisioning failed"}

                # Create session and JWT tokens
                user = db.users[user_id]
                session_id = SessionModel.create_session(
                    db, user.id,
                    ip_address=request.environ.get('REMOTE_ADDR'),
                    user_agent=request.environ.get('HTTP_USER_AGENT')
                )

                access_payload = {
                    'user_id': user.id,
                    'username': user.username,
                    'is_admin': user.is_admin,
                    'session_id': session_id,
                    'type': 'access'
                }
                access_token = jwt_manager.create_token(access_payload)

                # Redirect to frontend with token
                redirect_url = f"{relay_state}?token={quote(access_token)}"
                return redirect(redirect_url)

            except Exception as e:
                logger.error(f"SAML ACS processing failed: {e}")
                response.status = 500
                return {"error": "Failed to process SAML response"}

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def oauth2_login(provider_name):
        """Initiate OAuth2 login"""
        if request.method == 'GET':
            oauth2_auth = auth_manager.get_oauth2_authenticator(provider_name)
            if not oauth2_auth:
                response.status = 404
                return {"error": "OAuth2 provider not found"}

            try:
                # Generate state parameter for CSRF protection
                state = secrets.token_urlsafe(32)

                # Store state in session (in production, use proper session store)
                # For now, we'll include return URL in state
                relay_state = request.query.get('relay_state', '/')

                auth_url = oauth2_auth.create_auth_url(state)
                return redirect(auth_url)

            except Exception as e:
                logger.error(f"OAuth2 login initiation failed: {e}")
                response.status = 500
                return {"error": "Failed to initiate OAuth2 login"}

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def oauth2_callback(provider_name):
        """OAuth2 callback handler"""
        if request.method == 'GET':
            oauth2_auth = auth_manager.get_oauth2_authenticator(provider_name)
            if not oauth2_auth:
                response.status = 404
                return {"error": "OAuth2 provider not found"}

            try:
                code = request.query.get('code')
                state = request.query.get('state')
                error = request.query.get('error')

                if error:
                    response.status = 400
                    return {"error": f"OAuth2 error: {error}"}

                if not code or not state:
                    response.status = 400
                    return {"error": "Missing authorization code or state"}

                # Exchange code for token and user info
                user_data = oauth2_auth.exchange_code(code, state)
                if not user_data:
                    response.status = 400
                    return {"error": "Failed to exchange authorization code"}

                # Provision or update user
                user_id = auth_manager.provision_user_from_external(provider_name, user_data)
                if not user_id:
                    response.status = 400
                    return {"error": "User provisioning failed"}

                # Create session and JWT tokens
                user = db.users[user_id]
                session_id = SessionModel.create_session(
                    db, user.id,
                    ip_address=request.environ.get('REMOTE_ADDR'),
                    user_agent=request.environ.get('HTTP_USER_AGENT')
                )

                access_payload = {
                    'user_id': user.id,
                    'username': user.username,
                    'is_admin': user.is_admin,
                    'session_id': session_id,
                    'type': 'access'
                }
                access_token = jwt_manager.create_token(access_payload)

                # Redirect to frontend with token
                redirect_url = f"/?token={quote(access_token)}"
                return redirect(redirect_url)

            except Exception as e:
                logger.error(f"OAuth2 callback processing failed: {e}")
                response.status = 500
                return {"error": "Failed to process OAuth2 callback"}

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def scim_users():
        """SCIM user provisioning endpoint"""
        if request.method == 'GET':
            # List SCIM users
            provider_name = request.query.get('provider')
            if not provider_name:
                response.status = 400
                return {"error": "Provider name required"}

            scim_users = db(
                db.scim_users.provider_name == provider_name
            ).select(orderby=db.scim_users.created_at)

            users = []
            for scim_user in scim_users:
                user_data = scim_user.scim_data
                users.append({
                    "id": scim_user.scim_id,
                    "userName": user_data.get('userName'),
                    "emails": user_data.get('emails', []),
                    "active": scim_user.is_active,
                    "externalId": scim_user.external_id,
                    "meta": {
                        "created": scim_user.created_at.isoformat(),
                        "lastModified": scim_user.last_sync.isoformat()
                    }
                })

            return {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": len(users),
                "startIndex": 1,
                "itemsPerPage": len(users),
                "Resources": users
            }

        elif request.method == 'POST':
            # Create SCIM user
            provider_name = request.headers.get('X-Provider-Name')
            if not provider_name:
                response.status = 400
                return {"error": "Provider name required in X-Provider-Name header"}

            try:
                data = SCIMUserRequest(**request.json)
            except ValidationError as e:
                response.status = 400
                return {"error": "Validation error", "details": str(e)}

            try:
                user_id = SCIMUserModel.process_scim_user(db, request.json, provider_name)
                if user_id:
                    # Return SCIM user resource
                    scim_user = db(db.scim_users.scim_id == data.id).select().first()
                    user_data = scim_user.scim_data

                    return {
                        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                        "id": scim_user.scim_id,
                        "userName": user_data.get('userName'),
                        "emails": user_data.get('emails', []),
                        "active": scim_user.is_active,
                        "externalId": scim_user.external_id,
                        "meta": {
                            "created": scim_user.created_at.isoformat(),
                            "lastModified": scim_user.last_sync.isoformat(),
                            "location": f"{base_url}/api/scim/Users/{scim_user.scim_id}",
                            "resourceType": "User"
                        }
                    }
                else:
                    response.status = 400
                    return {"error": "User provisioning failed"}

            except Exception as e:
                logger.error(f"SCIM user creation failed: {e}")
                response.status = 500
                return {"error": "Failed to create SCIM user"}

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    # Return API endpoints
    return {
        'list_providers': list_providers,
        'create_saml_provider': create_saml_provider,
        'create_oauth2_provider': create_oauth2_provider,
        'saml_metadata': saml_metadata,
        'saml_login': saml_login,
        'saml_acs': saml_acs,
        'oauth2_login': oauth2_login,
        'oauth2_callback': oauth2_callback,
        'scim_users': scim_users
    }