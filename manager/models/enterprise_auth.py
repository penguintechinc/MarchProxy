"""
Enterprise authentication models for MarchProxy Manager
Includes SAML, SCIM, and OAuth2 support

Copyright (C) 2025 MarchProxy Contributors
Licensed under GNU Affero General Public License v3.0
"""

import json
import uuid
import secrets
import base64
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from urllib.parse import urlencode, parse_qs
import httpx
from pydal import DAL, Field
from pydantic import BaseModel, validator, EmailStr
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
import logging

logger = logging.getLogger(__name__)


class EnterpriseAuthProviderModel:
    """Enterprise authentication provider configuration"""

    @staticmethod
    def define_table(db: DAL):
        """Define enterprise auth provider table"""
        return db.define_table(
            'enterprise_auth_providers',
            Field('name', type='string', unique=True, required=True, length=100),
            Field('provider_type', type='string', required=True, length=20),
            Field('config', type='json', required=True),
            Field('is_active', type='boolean', default=True),
            Field('auto_provision', type='boolean', default=True),
            Field('default_role', type='string', default='service_owner', length=50),
            Field('attribute_mapping', type='json'),
            Field('created_by', type='reference users', required=True),
            Field('created_at', type='datetime', default=datetime.utcnow),
            Field('updated_at', type='datetime', update=datetime.utcnow),
            Field('metadata', type='json'),
        )

    @staticmethod
    def create_saml_provider(db: DAL, name: str, saml_config: Dict[str, Any],
                           created_by: int, auto_provision: bool = True,
                           default_role: str = 'service_owner') -> int:
        """Create SAML authentication provider"""

        # Validate SAML configuration
        required_fields = ['idp_sso_url', 'idp_x509_cert', 'sp_entity_id']
        if not all(field in saml_config for field in required_fields):
            raise ValueError("Missing required SAML configuration fields")

        # Default attribute mapping for SAML
        default_mapping = {
            'email': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
            'username': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
            'first_name': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
            'last_name': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
            'groups': 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups'
        }

        provider_id = db.enterprise_auth_providers.insert(
            name=name,
            provider_type='saml',
            config=saml_config,
            auto_provision=auto_provision,
            default_role=default_role,
            attribute_mapping=default_mapping,
            created_by=created_by
        )

        return provider_id

    @staticmethod
    def create_oauth2_provider(db: DAL, name: str, oauth2_config: Dict[str, Any],
                             created_by: int, auto_provision: bool = True,
                             default_role: str = 'service_owner') -> int:
        """Create OAuth2 authentication provider"""

        # Validate OAuth2 configuration
        required_fields = ['client_id', 'client_secret', 'auth_url', 'token_url', 'user_info_url']
        if not all(field in oauth2_config for field in required_fields):
            raise ValueError("Missing required OAuth2 configuration fields")

        # Default attribute mapping for OAuth2
        default_mapping = {
            'email': 'email',
            'username': 'preferred_username',
            'first_name': 'given_name',
            'last_name': 'family_name',
            'groups': 'groups'
        }

        provider_id = db.enterprise_auth_providers.insert(
            name=name,
            provider_type='oauth2',
            config=oauth2_config,
            auto_provision=auto_provision,
            default_role=default_role,
            attribute_mapping=default_mapping,
            created_by=created_by
        )

        return provider_id


class SAMLAuthenticator:
    """SAML authentication handler"""

    def __init__(self, provider_config: Dict[str, Any], base_url: str):
        self.config = provider_config
        self.base_url = base_url.rstrip('/')
        self.saml_client = self._create_saml_client()

    def _create_saml_client(self) -> Saml2Client:
        """Create SAML client configuration"""
        saml_settings = {
            'entityid': self.config['sp_entity_id'],
            'assertion_consumer_service': {
                'url': f"{self.base_url}/api/auth/saml/acs",
                'binding': BINDING_HTTP_POST
            },
            'single_logout_service': {
                'url': f"{self.base_url}/api/auth/saml/sls",
                'binding': BINDING_HTTP_REDIRECT
            },
            'name_id_format': ['urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress'],
            'key_file': self.config.get('sp_private_key'),
            'cert_file': self.config.get('sp_x509_cert'),
        }

        idp_settings = {
            'single_sign_on_service': {
                'url': self.config['idp_sso_url'],
                'binding': BINDING_HTTP_REDIRECT
            },
            'single_logout_service': {
                'url': self.config.get('idp_slo_url', ''),
                'binding': BINDING_HTTP_REDIRECT
            },
            'x509cert': self.config['idp_x509_cert']
        }

        config = Saml2Config()
        config.load({
            'sp': saml_settings,
            'idp': {self.config['idp_entity_id']: idp_settings}
        })

        return Saml2Client(config=config)

    def create_auth_request(self, relay_state: str = None) -> tuple[str, str]:
        """Create SAML authentication request"""
        req_id, info = self.saml_client.prepare_for_authenticate(
            relay_state=relay_state,
            binding=BINDING_HTTP_REDIRECT
        )

        redirect_url = None
        for header_name, header_value in info['headers']:
            if header_name == 'Location':
                redirect_url = header_value
                break

        return req_id, redirect_url

    def process_response(self, saml_response: str, request_id: str = None) -> Optional[Dict[str, Any]]:
        """Process SAML response and extract user information"""
        try:
            authn_response = self.saml_client.parse_authn_request_response(
                saml_response, BINDING_HTTP_POST, request_id=request_id
            )

            if not authn_response:
                return None

            # Extract user attributes
            user_info = authn_response.get_identity()
            if not user_info:
                return None

            # Map attributes to user fields
            mapped_user = {}
            for local_attr, saml_attr in self.config.get('attribute_mapping', {}).items():
                if saml_attr in user_info:
                    value = user_info[saml_attr]
                    mapped_user[local_attr] = value[0] if isinstance(value, list) and value else value

            return {
                'provider': 'saml',
                'external_id': authn_response.name_id,
                'attributes': mapped_user,
                'session_index': authn_response.session_index()
            }

        except Exception as e:
            logger.error(f"SAML response processing failed: {e}")
            return None

    def create_logout_request(self, name_id: str, session_index: str) -> str:
        """Create SAML logout request"""
        req_id, info = self.saml_client.global_logout(
            name_id=name_id,
            session_index=session_index,
            binding=BINDING_HTTP_REDIRECT
        )

        for header_name, header_value in info['headers']:
            if header_name == 'Location':
                return header_value

        return None


class OAuth2Authenticator:
    """OAuth2 authentication handler"""

    def __init__(self, provider_config: Dict[str, Any], base_url: str):
        self.config = provider_config
        self.base_url = base_url.rstrip('/')
        self.redirect_uri = f"{self.base_url}/api/auth/oauth2/callback"

    def create_auth_url(self, state: str) -> str:
        """Create OAuth2 authorization URL"""
        params = {
            'client_id': self.config['client_id'],
            'response_type': 'code',
            'redirect_uri': self.redirect_uri,
            'scope': self.config.get('scope', 'openid email profile'),
            'state': state
        }

        return f"{self.config['auth_url']}?{urlencode(params)}"

    async def exchange_code(self, code: str, state: str) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for access token"""
        try:
            async with httpx.AsyncClient() as client:
                token_data = {
                    'grant_type': 'authorization_code',
                    'client_id': self.config['client_id'],
                    'client_secret': self.config['client_secret'],
                    'code': code,
                    'redirect_uri': self.redirect_uri
                }

                response = await client.post(
                    self.config['token_url'],
                    data=token_data,
                    headers={'Accept': 'application/json'}
                )

                if response.status_code == 200:
                    token_response = response.json()
                    access_token = token_response.get('access_token')

                    if access_token:
                        user_info = await self._get_user_info(client, access_token)
                        if user_info:
                            return {
                                'provider': 'oauth2',
                                'external_id': user_info.get('sub') or user_info.get('id'),
                                'attributes': self._map_attributes(user_info),
                                'access_token': access_token,
                                'refresh_token': token_response.get('refresh_token')
                            }

        except Exception as e:
            logger.error(f"OAuth2 code exchange failed: {e}")

        return None

    async def _get_user_info(self, client: httpx.AsyncClient, access_token: str) -> Optional[Dict[str, Any]]:
        """Get user information from OAuth2 provider"""
        try:
            response = await client.get(
                self.config['user_info_url'],
                headers={'Authorization': f'Bearer {access_token}'}
            )

            if response.status_code == 200:
                return response.json()

        except Exception as e:
            logger.error(f"OAuth2 user info request failed: {e}")

        return None

    def _map_attributes(self, user_info: Dict[str, Any]) -> Dict[str, Any]:
        """Map OAuth2 user attributes to local attributes"""
        mapped_user = {}
        for local_attr, oauth_attr in self.config.get('attribute_mapping', {}).items():
            if oauth_attr in user_info:
                mapped_user[local_attr] = user_info[oauth_attr]

        return mapped_user


class SCIMUserModel:
    """SCIM user provisioning model"""

    @staticmethod
    def define_table(db: DAL):
        """Define SCIM user provisioning table"""
        return db.define_table(
            'scim_users',
            Field('scim_id', type='string', unique=True, required=True, length=255),
            Field('user_id', type='reference users'),
            Field('provider_name', type='string', required=True, length=100),
            Field('external_id', type='string', length=255),
            Field('scim_data', type='json'),
            Field('is_active', type='boolean', default=True),
            Field('last_sync', type='datetime', default=datetime.utcnow),
            Field('created_at', type='datetime', default=datetime.utcnow),
        )

    @staticmethod
    def process_scim_user(db: DAL, scim_data: Dict[str, Any], provider_name: str) -> Optional[int]:
        """Process SCIM user creation/update"""
        scim_id = scim_data.get('id')
        if not scim_id:
            return None

        # Check if SCIM user exists
        scim_user = db(db.scim_users.scim_id == scim_id).select().first()

        # Extract user attributes
        user_name = scim_data.get('userName')
        emails = scim_data.get('emails', [])
        primary_email = None
        for email in emails:
            if email.get('primary', False):
                primary_email = email.get('value')
                break
        if not primary_email and emails:
            primary_email = emails[0].get('value')

        name = scim_data.get('name', {})
        first_name = name.get('givenName', '')
        last_name = name.get('familyName', '')

        is_active = scim_data.get('active', True)

        if scim_user:
            # Update existing user
            if scim_user.user_id:
                user = db.users[scim_user.user_id]
                if user:
                    user.update_record(
                        email=primary_email,
                        is_active=is_active,
                        external_id=scim_data.get('externalId')
                    )

            scim_user.update_record(
                scim_data=scim_data,
                is_active=is_active,
                last_sync=datetime.utcnow()
            )

            return scim_user.user_id

        else:
            # Create new user if auto-provisioning is enabled
            provider = db(db.enterprise_auth_providers.name == provider_name).select().first()
            if not provider or not provider.auto_provision:
                return None

            # Create user account
            from .auth import UserModel
            user_id = db.users.insert(
                username=user_name or primary_email,
                email=primary_email,
                password_hash=UserModel.hash_password(secrets.token_urlsafe(32)),  # Random password
                is_active=is_active,
                auth_provider=provider_name,
                external_id=scim_data.get('externalId')
            )

            # Create SCIM user record
            db.scim_users.insert(
                scim_id=scim_id,
                user_id=user_id,
                provider_name=provider_name,
                external_id=scim_data.get('externalId'),
                scim_data=scim_data
            )

            return user_id


class EnterpriseAuthManager:
    """Enterprise authentication manager"""

    def __init__(self, db: DAL, base_url: str):
        self.db = db
        self.base_url = base_url

    def get_saml_authenticator(self, provider_name: str) -> Optional[SAMLAuthenticator]:
        """Get SAML authenticator for provider"""
        provider = self.db(
            (self.db.enterprise_auth_providers.name == provider_name) &
            (self.db.enterprise_auth_providers.provider_type == 'saml') &
            (self.db.enterprise_auth_providers.is_active == True)
        ).select().first()

        if provider:
            return SAMLAuthenticator(provider.config, self.base_url)

        return None

    def get_oauth2_authenticator(self, provider_name: str) -> Optional[OAuth2Authenticator]:
        """Get OAuth2 authenticator for provider"""
        provider = self.db(
            (self.db.enterprise_auth_providers.name == provider_name) &
            (self.db.enterprise_auth_providers.provider_type == 'oauth2') &
            (self.db.enterprise_auth_providers.is_active == True)
        ).select().first()

        if provider:
            return OAuth2Authenticator(provider.config, self.base_url)

        return None

    def provision_user_from_external(self, provider_name: str, external_data: Dict[str, Any]) -> Optional[int]:
        """Provision user from external authentication provider"""
        provider = self.db(
            (self.db.enterprise_auth_providers.name == provider_name) &
            (self.db.enterprise_auth_providers.is_active == True)
        ).select().first()

        if not provider or not provider.auto_provision:
            return None

        external_id = external_data.get('external_id')
        attributes = external_data.get('attributes', {})

        # Check if user already exists
        existing_user = self.db(
            (self.db.users.external_id == external_id) &
            (self.db.users.auth_provider == provider_name)
        ).select().first()

        if existing_user:
            # Update existing user
            update_data = {}
            if 'email' in attributes:
                update_data['email'] = attributes['email']
            if update_data:
                existing_user.update_record(**update_data)
            return existing_user.id

        # Create new user
        from .auth import UserModel
        username = attributes.get('username') or attributes.get('email')
        email = attributes.get('email')

        if not username or not email:
            logger.error("Cannot provision user without username/email")
            return None

        user_id = self.db.users.insert(
            username=username,
            email=email,
            password_hash=UserModel.hash_password(secrets.token_urlsafe(32)),  # Random password
            auth_provider=provider_name,
            external_id=external_id,
            metadata=attributes
        )

        # Assign to default cluster if specified
        if provider.default_role and user_id:
            from .cluster import UserClusterAssignmentModel
            # Get default cluster
            default_cluster = self.db(self.db.clusters.is_default == True).select().first()
            if default_cluster:
                UserClusterAssignmentModel.assign_user_to_cluster(
                    self.db, user_id, default_cluster.id, provider.default_role, 1  # System user
                )

        return user_id


# Pydantic models for Enterprise authentication
class CreateSAMLProviderRequest(BaseModel):
    name: str
    idp_sso_url: str
    idp_x509_cert: str
    sp_entity_id: str
    idp_entity_id: Optional[str] = None
    idp_slo_url: Optional[str] = None
    sp_private_key: Optional[str] = None
    sp_x509_cert: Optional[str] = None
    auto_provision: bool = True
    default_role: str = 'service_owner'

    @validator('name')
    def validate_name(cls, v):
        if len(v) < 3:
            raise ValueError('Provider name must be at least 3 characters long')
        return v.lower().replace(' ', '_')


class CreateOAuth2ProviderRequest(BaseModel):
    name: str
    client_id: str
    client_secret: str
    auth_url: str
    token_url: str
    user_info_url: str
    scope: str = 'openid email profile'
    auto_provision: bool = True
    default_role: str = 'service_owner'

    @validator('name')
    def validate_name(cls, v):
        if len(v) < 3:
            raise ValueError('Provider name must be at least 3 characters long')
        return v.lower().replace(' ', '_')


class SCIMUserRequest(BaseModel):
    id: str
    userName: str
    emails: List[Dict[str, Any]]
    name: Optional[Dict[str, str]] = None
    active: bool = True
    externalId: Optional[str] = None


class EnterpriseAuthProviderResponse(BaseModel):
    id: int
    name: str
    provider_type: str
    is_active: bool
    auto_provision: bool
    default_role: str
    created_at: datetime