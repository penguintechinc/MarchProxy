"""
OAuth2 Authentication Service for MarchProxy Enterprise
Handles OAuth2 integration with Google, Microsoft, GitHub, etc.
"""

import hashlib
import json
import logging
import secrets
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

import requests
from py4web import URL, abort, redirect, request, session
from py4web.utils.auth import Auth

from ...models import get_db
from ..license_service import LicenseService

logger = logging.getLogger(__name__)


class OAuth2Service:
    """OAuth2 Service for enterprise authentication with multiple providers"""

    def __init__(self, auth: Auth, license_service: LicenseService):
        self.auth = auth
        self.license_service = license_service
        self.db = get_db()
        self.providers = self._load_oauth2_providers()

    def _load_oauth2_providers(self) -> Dict:
        """Load OAuth2 provider configurations"""
        return {
            'google': {
                'name': 'Google',
                'client_id': None,  # Set via environment
                'client_secret': None,  # Set via environment
                'authorization_endpoint': 'https://accounts.google.com/o/oauth2/v2/auth',
                'token_endpoint': 'https://oauth2.googleapis.com/token',
                'userinfo_endpoint': 'https://www.googleapis.com/oauth2/v2/userinfo',
                'scopes': ['openid', 'email', 'profile'],
                'user_mapping': {
                    'email': 'email',
                    'first_name': 'given_name',
                    'last_name': 'family_name',
                    'external_id': 'id'
                },
                'admin_domains': []  # Domains that grant admin access
            },
            'microsoft': {
                'name': 'Microsoft',
                'client_id': None,
                'client_secret': None,
                'authorization_endpoint': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
                'token_endpoint': 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
                'userinfo_endpoint': 'https://graph.microsoft.com/v1.0/me',
                'scopes': ['openid', 'email', 'profile'],
                'user_mapping': {
                    'email': 'mail',
                    'first_name': 'givenName',
                    'last_name': 'surname',
                    'external_id': 'id'
                },
                'admin_domains': []
            },
            'github': {
                'name': 'GitHub',
                'client_id': None,
                'client_secret': None,
                'authorization_endpoint': 'https://github.com/login/oauth/authorize',
                'token_endpoint': 'https://github.com/login/oauth/access_token',
                'userinfo_endpoint': 'https://api.github.com/user',
                'scopes': ['user:email'],
                'user_mapping': {
                    'email': 'email',
                    'first_name': 'name',  # GitHub returns full name
                    'last_name': '',
                    'external_id': 'id'
                },
                'admin_domains': [],
                'admin_organizations': []  # GitHub orgs that grant admin access
            },
            'azure': {
                'name': 'Azure AD',
                'client_id': None,
                'client_secret': None,
                'tenant_id': None,  # Required for Azure AD
                'authorization_endpoint': 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize',
                'token_endpoint': 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
                'userinfo_endpoint': 'https://graph.microsoft.com/v1.0/me',
                'scopes': ['openid', 'email', 'profile'],
                'user_mapping': {
                    'email': 'mail',
                    'first_name': 'givenName',
                    'last_name': 'surname',
                    'external_id': 'id'
                },
                'admin_groups': []  # Azure AD groups that grant admin access
            }
        }

    def is_enabled(self, provider: str = None) -> bool:
        """Check if OAuth2 authentication is enabled"""
        if not self.license_service.has_feature('oauth2_authentication'):
            return False

        if provider:
            config = self.providers.get(provider, {})
            return bool(config.get('client_id') and config.get('client_secret'))

        # Check if any provider is configured
        return any(
            config.get('client_id') and config.get('client_secret')
            for config in self.providers.values()
        )

    def get_available_providers(self) -> List[Dict]:
        """Get list of configured OAuth2 providers"""
        available = []
        for key, config in self.providers.items():
            if config.get('client_id') and config.get('client_secret'):
                available.append({
                    'key': key,
                    'name': config['name'],
                    'url': URL('auth/oauth2/login', vars={'provider': key})
                })
        return available

    def initiate_oauth2_flow(self, provider: str, redirect_uri: Optional[str] = None) -> str:
        """Initiate OAuth2 authorization flow"""
        if not self.is_enabled(provider):
            abort(403, f"OAuth2 provider '{provider}' not available")

        config = self.providers[provider]

        # Generate state parameter for CSRF protection
        state = secrets.token_urlsafe(32)
        session[f'oauth2_state_{provider}'] = state
        session[f'oauth2_timestamp_{provider}'] = time.time()
        session[f'oauth2_redirect_{provider}'] = redirect_uri

        # Build authorization URL
        params = {
            'client_id': config['client_id'],
            'response_type': 'code',
            'scope': ' '.join(config['scopes']),
            'state': state,
            'redirect_uri': URL('auth/oauth2/callback', vars={'provider': provider}, scheme=True, host=True)
        }

        # Handle tenant-specific URLs (Azure AD)
        auth_url = config['authorization_endpoint']
        if '{tenant}' in auth_url and config.get('tenant_id'):
            auth_url = auth_url.format(tenant=config['tenant_id'])

        oauth_url = f"{auth_url}?{urlencode(params)}"

        logger.info(f"Initiating OAuth2 flow for provider: {provider}")
        return oauth_url

    def handle_oauth2_callback(self, provider: str, code: str, state: str) -> Dict:
        """Handle OAuth2 authorization callback"""
        if not self.is_enabled(provider):
            abort(403, f"OAuth2 provider '{provider}' not available")

        # Validate state parameter
        session_state = session.get(f'oauth2_state_{provider}')
        if not session_state or session_state != state:
            abort(400, "Invalid OAuth2 state parameter")

        # Check request timeout (10 minutes)
        request_age = time.time() - session.get(f'oauth2_timestamp_{provider}', 0)
        if request_age > 600:
            abort(400, "OAuth2 request timeout")

        config = self.providers[provider]

        try:
            # Exchange authorization code for access token
            token_data = self._exchange_code_for_token(provider, code)

            # Get user information
            user_info = self._get_user_info(provider, token_data['access_token'])

            # Map user attributes
            user_attributes = self._map_user_attributes(provider, user_info)

            # Provision or update user
            user = self._provision_oauth2_user(provider, user_attributes, token_data)

            # Clear OAuth2 session data
            for key in [f'oauth2_state_{provider}', f'oauth2_timestamp_{provider}', f'oauth2_redirect_{provider}']:
                session.pop(key, None)

            logger.info(f"OAuth2 authentication successful for provider {provider}, user: {user['email']}")
            return user

        except Exception as e:
            logger.error(f"OAuth2 callback error for provider {provider}: {e}")
            abort(401, f"OAuth2 authentication failed: {str(e)}")

    def _exchange_code_for_token(self, provider: str, code: str) -> Dict:
        """Exchange authorization code for access token"""
        config = self.providers[provider]

        token_url = config['token_endpoint']
        if '{tenant}' in token_url and config.get('tenant_id'):
            token_url = token_url.format(tenant=config['tenant_id'])

        data = {
            'client_id': config['client_id'],
            'client_secret': config['client_secret'],
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': URL('auth/oauth2/callback', vars={'provider': provider}, scheme=True, host=True)
        }

        headers = {'Accept': 'application/json'}

        response = requests.post(token_url, data=data, headers=headers, timeout=30)
        response.raise_for_status()

        token_data = response.json()

        if 'access_token' not in token_data:
            raise Exception("No access token in response")

        return token_data

    def _get_user_info(self, provider: str, access_token: str) -> Dict:
        """Get user information from OAuth2 provider"""
        config = self.providers[provider]

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }

        response = requests.get(config['userinfo_endpoint'], headers=headers, timeout=30)
        response.raise_for_status()

        user_info = response.json()

        # Handle special cases for different providers
        if provider == 'github':
            user_info = self._enrich_github_user_info(user_info, access_token)

        return user_info

    def _enrich_github_user_info(self, user_info: Dict, access_token: str) -> Dict:
        """Enrich GitHub user info with email and organization data"""
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }

        # Get primary email if not public
        if not user_info.get('email'):
            email_response = requests.get('https://api.github.com/user/emails', headers=headers, timeout=30)
            if email_response.status_code == 200:
                emails = email_response.json()
                primary_email = next((email['email'] for email in emails if email['primary']), None)
                if primary_email:
                    user_info['email'] = primary_email

        # Get organization memberships for admin determination
        orgs_response = requests.get('https://api.github.com/user/orgs', headers=headers, timeout=30)
        if orgs_response.status_code == 200:
            orgs = orgs_response.json()
            user_info['organizations'] = [org['login'] for org in orgs]

        return user_info

    def _map_user_attributes(self, provider: str, user_info: Dict) -> Dict:
        """Map provider user info to MarchProxy user attributes"""
        config = self.providers[provider]
        mapping = config['user_mapping']

        user_data = {
            'external_id': str(user_info.get(mapping['external_id'], '')),
            'auth_provider': f'oauth2_{provider}',
            'is_admin': False
        }

        # Map basic attributes
        for field, source_field in mapping.items():
            if source_field and source_field in user_info:
                value = user_info[source_field]
                user_data[field] = value

        # Handle special cases
        if provider == 'github' and not user_data.get('first_name'):
            # Split name field for GitHub
            full_name = user_info.get('name', '').strip()
            if full_name:
                name_parts = full_name.split(' ', 1)
                user_data['first_name'] = name_parts[0]
                user_data['last_name'] = name_parts[1] if len(name_parts) > 1 else ''

        # Determine admin status
        user_data['is_admin'] = self._determine_admin_status(provider, user_info, user_data)

        return user_data

    def _determine_admin_status(self, provider: str, user_info: Dict, user_data: Dict) -> bool:
        """Determine if user should have admin privileges"""
        config = self.providers[provider]

        # Check admin domains
        email = user_data.get('email', '')
        if email:
            domain = email.split('@')[1] if '@' in email else ''
            if domain in config.get('admin_domains', []):
                return True

        # Check GitHub organizations
        if provider == 'github':
            user_orgs = user_info.get('organizations', [])
            admin_orgs = config.get('admin_organizations', [])
            if any(org in admin_orgs for org in user_orgs):
                return True

        # Check Azure AD groups (would require additional Graph API call)
        if provider == 'azure':
            # This would require a separate API call to get group memberships
            # Left as placeholder for full implementation
            pass

        return False

    def _provision_oauth2_user(self, provider: str, user_attributes: Dict, token_data: Dict) -> Dict:
        """Provision or update OAuth2 user account"""
        email = user_attributes.get('email')
        external_id = user_attributes.get('external_id')
        auth_provider = user_attributes.get('auth_provider')

        if not email:
            abort(400, f"Email address required for {provider} user provisioning")

        # Check if user exists by email or external_id
        user = self.db(
            (self.db.auth_user.email == email) |
            ((self.db.auth_user.external_id == external_id) &
             (self.db.auth_user.auth_provider == auth_provider))
        ).select().first()

        if user:
            # Update existing user
            self.db(self.db.auth_user.id == user.id).update(
                first_name=user_attributes.get('first_name', user.first_name),
                last_name=user_attributes.get('last_name', user.last_name),
                is_admin=user_attributes.get('is_admin', user.is_admin),
                external_id=external_id,
                auth_provider=auth_provider,
                last_login=datetime.utcnow()
            )
            self.db.commit()

            logger.info(f"Updated {provider} OAuth2 user: {email}")
            return user.as_dict()
        else:
            # Create new user
            username = email.split('@')[0]  # Use email prefix as username

            # Ensure username is unique
            counter = 1
            original_username = username
            while self.db(self.db.auth_user.username == username).count():
                username = f"{original_username}{counter}"
                counter += 1

            user_id = self.db.auth_user.insert(
                username=username,
                email=email,
                first_name=user_attributes.get('first_name', ''),
                last_name=user_attributes.get('last_name', ''),
                is_admin=user_attributes.get('is_admin', False),
                external_id=external_id,
                auth_provider=auth_provider,
                password_hash='',  # No local password for OAuth2 users
                registration_date=datetime.utcnow(),
                last_login=datetime.utcnow()
            )
            self.db.commit()

            user = self.db.auth_user[user_id]
            logger.info(f"Created new {provider} OAuth2 user: {email}")
            return user.as_dict()

    def refresh_access_token(self, provider: str, refresh_token: str) -> Dict:
        """Refresh OAuth2 access token"""
        if not self.is_enabled(provider):
            abort(403, f"OAuth2 provider '{provider}' not available")

        config = self.providers[provider]

        token_url = config['token_endpoint']
        if '{tenant}' in token_url and config.get('tenant_id'):
            token_url = token_url.format(tenant=config['tenant_id'])

        data = {
            'client_id': config['client_id'],
            'client_secret': config['client_secret'],
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token'
        }

        headers = {'Accept': 'application/json'}

        response = requests.post(token_url, data=data, headers=headers, timeout=30)
        response.raise_for_status()

        token_data = response.json()
        return token_data

    def revoke_access_token(self, provider: str, access_token: str) -> bool:
        """Revoke OAuth2 access token"""
        # Implementation varies by provider
        # Some providers support token revocation endpoints
        logger.info(f"Token revocation requested for provider: {provider}")
        return True

    def configure_provider(self, provider: str, config: Dict) -> bool:
        """Configure OAuth2 provider settings"""
        if provider not in self.providers:
            return False

        # Update provider configuration
        self.providers[provider].update(config)

        # In production, this would persist to database/config
        logger.info(f"Updated configuration for OAuth2 provider: {provider}")
        return True