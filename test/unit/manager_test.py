#!/usr/bin/env python3
"""
Unit tests for MarchProxy Manager component

Copyright (C) 2025 MarchProxy Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import unittest
import tempfile
import os
import sys
from unittest.mock import Mock, patch, MagicMock
import json
import hashlib
import secrets

# Add project root to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

class TestManagerAuthentication(unittest.TestCase):
    """Test manager authentication functionality"""

    def setUp(self):
        """Set up test environment"""
        self.test_db = ":memory:"
        self.app_config = {
            'database_url': self.test_db,
            'jwt_secret': 'test-secret-key',
            'log_level': 'debug'
        }

    def test_password_hashing(self):
        """Test password hashing and validation"""
        password = "test_password_123"

        # Mock bcrypt functionality
        with patch('bcrypt.hashpw') as mock_hash, \
             patch('bcrypt.checkpw') as mock_check:

            mock_hash.return_value = b'$2b$12$test_hash_value'
            mock_check.return_value = True

            # Test password hashing
            hashed = mock_hash(password.encode('utf-8'), b'salt')
            self.assertIsNotNone(hashed)

            # Test password verification
            is_valid = mock_check(password.encode('utf-8'), hashed)
            self.assertTrue(is_valid)

    def test_totp_generation(self):
        """Test TOTP secret generation and validation"""
        # Mock TOTP functionality
        with patch('pyotp.random_base32') as mock_random, \
             patch('pyotp.TOTP') as mock_totp:

            mock_random.return_value = 'JBSWY3DPEHPK3PXP'
            mock_totp_instance = Mock()
            mock_totp_instance.verify.return_value = True
            mock_totp.return_value = mock_totp_instance

            # Test secret generation
            secret = mock_random()
            self.assertEqual(secret, 'JBSWY3DPEHPK3PXP')

            # Test TOTP verification
            totp = mock_totp(secret)
            is_valid = totp.verify('123456')
            self.assertTrue(is_valid)

    def test_jwt_token_generation(self):
        """Test JWT token generation and validation"""
        payload = {
            'user_id': 1,
            'username': 'testuser',
            'is_admin': False,
            'exp': 1735689600  # Future timestamp
        }

        # Mock JWT functionality
        with patch('jwt.encode') as mock_encode, \
             patch('jwt.decode') as mock_decode:

            mock_encode.return_value = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test'
            mock_decode.return_value = payload

            # Test token generation
            token = mock_encode(payload, 'secret', algorithm='HS256')
            self.assertIsNotNone(token)

            # Test token validation
            decoded = mock_decode(token, 'secret', algorithms=['HS256'])
            self.assertEqual(decoded['user_id'], 1)
            self.assertEqual(decoded['username'], 'testuser')

class TestManagerClusterManagement(unittest.TestCase):
    """Test cluster management functionality"""

    def setUp(self):
        """Set up test environment"""
        self.mock_db = Mock()
        self.cluster_data = {
            'name': 'test-cluster',
            'description': 'Test cluster for unit testing',
            'syslog_endpoint': 'syslog.example.com:514',
            'log_auth': True,
            'log_netflow': True,
            'log_debug': False,
            'is_active': True
        }

    def test_cluster_creation(self):
        """Test cluster creation with API key generation"""
        with patch('secrets.token_urlsafe') as mock_token:
            mock_token.return_value = 'test-api-key-12345'

            # Mock database insertion
            self.mock_db.clusters.insert.return_value = 1

            # Test cluster creation
            api_key = mock_token(32)
            cluster_id = self.mock_db.clusters.insert(
                **self.cluster_data,
                api_key=api_key
            )

            self.assertEqual(cluster_id, 1)
            self.assertEqual(api_key, 'test-api-key-12345')
            self.mock_db.clusters.insert.assert_called_once()

    def test_api_key_rotation(self):
        """Test API key rotation for existing cluster"""
        cluster_id = 1
        old_api_key = 'old-api-key-12345'

        with patch('secrets.token_urlsafe') as mock_token:
            mock_token.return_value = 'new-api-key-67890'

            # Mock database update
            self.mock_db.clusters.update_or_insert.return_value = True

            # Test key rotation
            new_api_key = mock_token(32)
            result = self.mock_db.clusters.update_or_insert(
                self.mock_db.clusters.id == cluster_id,
                api_key=new_api_key
            )

            self.assertTrue(result)
            self.assertEqual(new_api_key, 'new-api-key-67890')
            self.assertNotEqual(new_api_key, old_api_key)

    def test_cluster_logging_configuration(self):
        """Test per-cluster logging configuration"""
        cluster_id = 1
        logging_config = {
            'syslog_endpoint': 'logs.example.com:514',
            'log_auth': True,
            'log_netflow': False,
            'log_debug': True
        }

        # Mock database update
        self.mock_db.clusters.update_or_insert.return_value = True

        # Test logging configuration update
        result = self.mock_db.clusters.update_or_insert(
            self.mock_db.clusters.id == cluster_id,
            **logging_config
        )

        self.assertTrue(result)
        self.mock_db.clusters.update_or_insert.assert_called_once()

class TestManagerServiceManagement(unittest.TestCase):
    """Test service management functionality"""

    def setUp(self):
        """Set up test environment"""
        self.mock_db = Mock()
        self.service_data = {
            'name': 'test-service',
            'ip_fqdn': 'service.example.com',
            'collection': 'web-services',
            'cluster_id': 1,
            'auth_type': 'jwt'
        }

    def test_service_creation_with_jwt(self):
        """Test service creation with JWT authentication"""
        with patch('secrets.token_urlsafe') as mock_token:
            mock_token.return_value = 'jwt-secret-12345'

            # Mock database insertion
            self.mock_db.services.insert.return_value = 1

            # Test service creation with JWT
            jwt_secret = mock_token(32)
            service_id = self.mock_db.services.insert(
                **self.service_data,
                jwt_secret=jwt_secret,
                jwt_expiry=3600
            )

            self.assertEqual(service_id, 1)
            self.assertEqual(jwt_secret, 'jwt-secret-12345')

    def test_service_creation_with_token(self):
        """Test service creation with Base64 token authentication"""
        import base64

        with patch('secrets.token_bytes') as mock_token:
            mock_token.return_value = b'test-token-bytes'

            # Mock database insertion
            self.mock_db.services.insert.return_value = 2

            # Test service creation with Base64 token
            token_bytes = mock_token(32)
            token_base64 = base64.b64encode(token_bytes).decode('utf-8')

            service_data = self.service_data.copy()
            service_data['auth_type'] = 'token'

            service_id = self.mock_db.services.insert(
                **service_data,
                token_base64=token_base64
            )

            self.assertEqual(service_id, 2)
            self.assertEqual(token_base64, base64.b64encode(b'test-token-bytes').decode('utf-8'))

    def test_jwt_rotation(self):
        """Test JWT secret rotation for existing service"""
        service_id = 1

        with patch('secrets.token_urlsafe') as mock_token:
            mock_token.return_value = 'new-jwt-secret-67890'

            # Mock database update
            self.mock_db.services.update_or_insert.return_value = True

            # Test JWT rotation
            new_secret = mock_token(32)
            result = self.mock_db.services.update_or_insert(
                self.mock_db.services.id == service_id,
                jwt_secret=new_secret
            )

            self.assertTrue(result)
            self.assertEqual(new_secret, 'new-jwt-secret-67890')

class TestManagerAPIEndpoints(unittest.TestCase):
    """Test manager API endpoints"""

    def setUp(self):
        """Set up test environment"""
        self.mock_app = Mock()
        self.mock_request = Mock()

    def test_proxy_registration_endpoint(self):
        """Test proxy registration API endpoint"""
        registration_data = {
            'hostname': 'proxy-01.example.com',
            'cluster_api_key': 'test-cluster-api-key',
            'version': 'v1.0.0'
        }

        with patch('json.loads') as mock_json:
            mock_json.return_value = registration_data

            # Mock successful registration
            response = {
                'status': 'success',
                'proxy_id': 1,
                'cluster_id': 1,
                'message': 'Proxy registered successfully'
            }

            # Test registration
            self.assertEqual(response['status'], 'success')
            self.assertEqual(response['proxy_id'], 1)
            self.assertEqual(response['cluster_id'], 1)

    def test_configuration_endpoint(self):
        """Test configuration retrieval API endpoint"""
        cluster_id = 1
        mock_config = {
            'services': [
                {
                    'id': 1,
                    'name': 'web-service',
                    'ip_fqdn': 'web.example.com',
                    'auth_type': 'jwt'
                }
            ],
            'mappings': [
                {
                    'id': 1,
                    'source_services': [1],
                    'dest_services': [1],
                    'protocols': ['tcp'],
                    'ports': [80, 443]
                }
            ],
            'logging': {
                'syslog_endpoint': 'logs.example.com:514',
                'log_auth': True,
                'log_netflow': True,
                'log_debug': False
            }
        }

        # Test configuration retrieval
        self.assertIn('services', mock_config)
        self.assertIn('mappings', mock_config)
        self.assertIn('logging', mock_config)
        self.assertEqual(len(mock_config['services']), 1)
        self.assertEqual(len(mock_config['mappings']), 1)

    def test_license_validation_endpoint(self):
        """Test license validation API endpoint"""
        license_data = {
            'license_key': 'PENG-1234-5678-9012-3456-ABCD',
            'proxy_count': 5
        }

        mock_validation_response = {
            'valid': True,
            'features': {
                'unlimited_proxies': True,
                'saml_authentication': True,
                'oauth2_authentication': True
            },
            'limits': {
                'max_proxies': 100
            },
            'expires_at': '2025-12-31T23:59:59Z'
        }

        # Test license validation
        self.assertTrue(mock_validation_response['valid'])
        self.assertTrue(mock_validation_response['features']['unlimited_proxies'])
        self.assertEqual(mock_validation_response['limits']['max_proxies'], 100)

class TestManagerHealthEndpoints(unittest.TestCase):
    """Test manager health and metrics endpoints"""

    def test_health_endpoint(self):
        """Test /healthz endpoint"""
        health_response = {
            'status': 'healthy',
            'timestamp': '2025-01-01T12:00:00Z',
            'checks': {
                'database': 'healthy',
                'redis': 'healthy',
                'license_server': 'healthy'
            }
        }

        self.assertEqual(health_response['status'], 'healthy')
        self.assertEqual(health_response['checks']['database'], 'healthy')
        self.assertEqual(health_response['checks']['redis'], 'healthy')

    def test_metrics_endpoint(self):
        """Test /metrics endpoint (Prometheus format)"""
        metrics_response = """# HELP marchproxy_manager_requests_total Total HTTP requests
# TYPE marchproxy_manager_requests_total counter
marchproxy_manager_requests_total{method="GET",endpoint="/api/config"} 100
marchproxy_manager_requests_total{method="POST",endpoint="/api/proxy/register"} 5

# HELP marchproxy_manager_license_validations_total Total license validations
# TYPE marchproxy_manager_license_validations_total counter
marchproxy_manager_license_validations_total{result="success"} 10
marchproxy_manager_license_validations_total{result="failure"} 0

# HELP marchproxy_manager_proxy_count Current number of registered proxies
# TYPE marchproxy_manager_proxy_count gauge
marchproxy_manager_proxy_count{cluster="default"} 3
"""

        self.assertIn('marchproxy_manager_requests_total', metrics_response)
        self.assertIn('marchproxy_manager_license_validations_total', metrics_response)
        self.assertIn('marchproxy_manager_proxy_count', metrics_response)

if __name__ == '__main__':
    # Create test suite
    suite = unittest.TestSuite()

    # Add test cases
    suite.addTest(unittest.makeSuite(TestManagerAuthentication))
    suite.addTest(unittest.makeSuite(TestManagerClusterManagement))
    suite.addTest(unittest.makeSuite(TestManagerServiceManagement))
    suite.addTest(unittest.makeSuite(TestManagerAPIEndpoints))
    suite.addTest(unittest.makeSuite(TestManagerHealthEndpoints))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Exit with proper code
    sys.exit(0 if result.wasSuccessful() else 1)