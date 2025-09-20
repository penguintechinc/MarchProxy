"""
SAML Authentication Service for MarchProxy Enterprise
Handles SAML SSO integration with enterprise identity providers
"""

import hashlib
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from urllib.parse import urlencode, urlparse

import requests
from py4web import URL, abort, redirect, request, session
from py4web.utils.auth import Auth

from ...models import get_db
from ..license_service import LicenseService

logger = logging.getLogger(__name__)


class SAMLService:
    """SAML Service Provider implementation for enterprise authentication"""

    def __init__(self, auth: Auth, license_service: LicenseService):
        self.auth = auth
        self.license_service = license_service
        self.db = get_db()
        self.config = self._load_saml_config()

    def _load_saml_config(self) -> Dict:
        """Load SAML configuration from environment/settings"""
        # This would typically come from environment variables or database
        return {
            'entity_id': 'marchproxy-sp',
            'assertion_consumer_service_url': URL('auth/saml/acs', scheme=True, host=True),
            'single_logout_service_url': URL('auth/saml/sls', scheme=True, host=True),
            'metadata_url': URL('auth/saml/metadata', scheme=True, host=True),
            'certificate_file': 'certs/saml.crt',
            'private_key_file': 'certs/saml.key',
            'name_id_format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
            'authn_requests_signed': True,
            'logout_requests_signed': True,
            'want_assertions_signed': True,
            'want_name_id_encrypted': False,
            'idp_metadata_url': None,  # Set per IdP configuration
            'attribute_mapping': {
                'email': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
                'first_name': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
                'last_name': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
                'groups': 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups',
                'department': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department'
            }
        }

    def is_enabled(self) -> bool:
        """Check if SAML authentication is enabled for this instance"""
        # Check license features
        if not self.license_service.has_feature('saml_authentication'):
            return False

        # Check if SAML is configured
        return bool(self.config.get('idp_metadata_url'))

    def initiate_sso(self, relay_state: Optional[str] = None) -> str:
        """Initiate SAML SSO authentication"""
        if not self.is_enabled():
            abort(403, "SAML authentication not available")

        # Generate SAML AuthnRequest
        authn_request = self._generate_authn_request()

        # Store request details in session for validation
        session['saml_request_id'] = authn_request['id']
        session['saml_request_timestamp'] = time.time()
        session['saml_relay_state'] = relay_state

        # Build SSO URL
        sso_url = self._build_sso_url(authn_request, relay_state)

        logger.info(f"Initiating SAML SSO for request ID: {authn_request['id']}")
        return sso_url

    def _generate_authn_request(self) -> Dict:
        """Generate SAML AuthnRequest"""
        request_id = f"id_{uuid.uuid4().hex}"
        timestamp = datetime.utcnow().isoformat() + 'Z'

        authn_request = {
            'id': request_id,
            'timestamp': timestamp,
            'destination': self._get_idp_sso_url(),
            'assertion_consumer_service_url': self.config['assertion_consumer_service_url'],
            'entity_id': self.config['entity_id'],
            'name_id_format': self.config['name_id_format']
        }

        return authn_request

    def _build_sso_url(self, authn_request: Dict, relay_state: Optional[str]) -> str:
        """Build SSO URL with SAML AuthnRequest"""
        # In a full implementation, this would generate proper SAML XML
        # and potentially sign it if required
        saml_request = self._encode_saml_request(authn_request)

        params = {
            'SAMLRequest': saml_request,
            'RelayState': relay_state or '',
        }

        if self.config['authn_requests_signed']:
            params['SigAlg'] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
            params['Signature'] = self._sign_request(params)

        sso_url = f"{self._get_idp_sso_url()}?{urlencode(params)}"
        return sso_url

    def _encode_saml_request(self, authn_request: Dict) -> str:
        """Encode SAML AuthnRequest as base64 (simplified)"""
        # In production, this would generate proper SAML XML
        import base64
        import zlib

        xml_template = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{authn_request['id']}"
    Version="2.0"
    IssueInstant="{authn_request['timestamp']}"
    Destination="{authn_request['destination']}"
    AssertionConsumerServiceURL="{authn_request['assertion_consumer_service_url']}">
    <saml:Issuer>{authn_request['entity_id']}</saml:Issuer>
    <samlp:NameIDPolicy Format="{authn_request['name_id_format']}" AllowCreate="true"/>
</samlp:AuthnRequest>"""

        compressed = zlib.compress(xml_template.encode('utf-8'))
        encoded = base64.b64encode(compressed).decode('utf-8')
        return encoded

    def process_saml_response(self, saml_response: str, relay_state: Optional[str] = None) -> Dict:
        """Process SAML Response from IdP"""
        if not self.is_enabled():
            abort(403, "SAML authentication not available")

        # Validate session state
        if 'saml_request_id' not in session:
            abort(400, "Invalid SAML session state")

        # Check request timeout (5 minutes)
        request_age = time.time() - session.get('saml_request_timestamp', 0)
        if request_age > 300:
            abort(400, "SAML request timeout")

        # Decode and validate SAML response
        assertion = self._decode_saml_response(saml_response)

        # Validate assertion
        if not self._validate_assertion(assertion):
            abort(401, "Invalid SAML assertion")

        # Extract user attributes
        user_attributes = self._extract_user_attributes(assertion)

        # Provision or update user
        user = self._provision_user(user_attributes)

        # Clear SAML session data
        for key in ['saml_request_id', 'saml_request_timestamp', 'saml_relay_state']:
            session.pop(key, None)

        logger.info(f"SAML authentication successful for user: {user['email']}")
        return user

    def _decode_saml_response(self, saml_response: str) -> Dict:
        """Decode and parse SAML Response (simplified)"""
        import base64
        import xml.etree.ElementTree as ET

        try:
            decoded = base64.b64decode(saml_response)
            root = ET.fromstring(decoded)

            # Extract assertion (simplified XML parsing)
            # In production, use proper SAML library like python3-saml

            assertion = {
                'subject': self._extract_xml_text(root, './/saml:Subject/saml:NameID'),
                'attributes': self._extract_attributes(root),
                'conditions': self._extract_conditions(root),
                'authn_statement': self._extract_authn_statement(root)
            }

            return assertion

        except Exception as e:
            logger.error(f"Failed to decode SAML response: {e}")
            abort(400, "Invalid SAML response format")

    def _validate_assertion(self, assertion: Dict) -> bool:
        """Validate SAML assertion"""
        # Check conditions (NotBefore, NotOnOrAfter)
        conditions = assertion.get('conditions', {})
        now = datetime.utcnow()

        if 'not_before' in conditions:
            not_before = datetime.fromisoformat(conditions['not_before'].replace('Z', '+00:00'))
            if now < not_before:
                logger.warning("SAML assertion not yet valid")
                return False

        if 'not_on_or_after' in conditions:
            not_after = datetime.fromisoformat(conditions['not_on_or_after'].replace('Z', '+00:00'))
            if now >= not_after:
                logger.warning("SAML assertion expired")
                return False

        # Validate audience restriction
        audience = conditions.get('audience')
        if audience and audience != self.config['entity_id']:
            logger.warning(f"Invalid audience: {audience}")
            return False

        # Additional validations would go here (signature, etc.)
        return True

    def _extract_user_attributes(self, assertion: Dict) -> Dict:
        """Extract user attributes from SAML assertion"""
        attributes = assertion.get('attributes', {})
        mapping = self.config['attribute_mapping']

        user_data = {
            'external_id': assertion.get('subject'),
            'auth_provider': 'saml',
            'is_admin': False  # Default, can be overridden by group membership
        }

        # Map SAML attributes to user fields
        for field, attr_name in mapping.items():
            if attr_name in attributes:
                value = attributes[attr_name]
                if isinstance(value, list) and len(value) == 1:
                    value = value[0]
                user_data[field] = value

        # Check for admin group membership
        groups = user_data.get('groups', [])
        if isinstance(groups, str):
            groups = [groups]

        admin_groups = ['MarchProxy-Admins', 'Domain Admins', 'Enterprise Admins']
        user_data['is_admin'] = any(group in admin_groups for group in groups)

        return user_data

    def _provision_user(self, user_attributes: Dict) -> Dict:
        """Provision or update user account"""
        email = user_attributes.get('email')
        external_id = user_attributes.get('external_id')

        if not email:
            abort(400, "Email address required for user provisioning")

        # Check if user exists by email or external_id
        user = self.db(
            (self.db.auth_user.email == email) |
            (self.db.auth_user.external_id == external_id)
        ).select().first()

        if user:
            # Update existing user
            self.db(self.db.auth_user.id == user.id).update(
                first_name=user_attributes.get('first_name', user.first_name),
                last_name=user_attributes.get('last_name', user.last_name),
                is_admin=user_attributes.get('is_admin', user.is_admin),
                external_id=external_id,
                auth_provider='saml',
                last_login=datetime.utcnow()
            )
            self.db.commit()

            logger.info(f"Updated SAML user: {email}")
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
                auth_provider='saml',
                password_hash='',  # No local password for SAML users
                registration_date=datetime.utcnow(),
                last_login=datetime.utcnow()
            )
            self.db.commit()

            user = self.db.auth_user[user_id]
            logger.info(f"Created new SAML user: {email}")
            return user.as_dict()

    def generate_metadata(self) -> str:
        """Generate SAML Service Provider metadata"""
        metadata_template = f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{self.config['entity_id']}">
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
            <!-- Certificate would go here -->
        </md:KeyDescriptor>
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                               Location="{self.config['single_logout_service_url']}"/>
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                   Location="{self.config['assertion_consumer_service_url']}"
                                   index="0" isDefault="true"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>"""

        return metadata_template

    def _get_idp_sso_url(self) -> str:
        """Get IdP SSO URL from metadata"""
        # In production, this would parse IdP metadata
        # For now, return configured URL
        return self.config.get('idp_sso_url', 'https://idp.example.com/sso')

    def _sign_request(self, params: Dict) -> str:
        """Sign SAML request (simplified)"""
        # In production, implement proper XML signature
        return "placeholder_signature"

    def _extract_xml_text(self, root, xpath: str) -> Optional[str]:
        """Extract text from XML element"""
        # Simplified XML parsing
        return None

    def _extract_attributes(self, root) -> Dict:
        """Extract attributes from SAML assertion"""
        # Simplified attribute extraction
        return {}

    def _extract_conditions(self, root) -> Dict:
        """Extract conditions from SAML assertion"""
        # Simplified conditions extraction
        return {}

    def _extract_authn_statement(self, root) -> Dict:
        """Extract authentication statement"""
        # Simplified authn statement extraction
        return {}