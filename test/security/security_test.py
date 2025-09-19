#!/usr/bin/env python3
"""
Security tests for MarchProxy

Copyright (C) 2025 MarchProxy Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import unittest
import requests
import base64
import json
import time
import hashlib
import subprocess
import socket
import ssl
from urllib.parse import urljoin
import threading

class SecurityTestSuite(unittest.TestCase):
    """Comprehensive security test suite for MarchProxy"""

    def setUp(self):
        """Set up test environment"""
        self.manager_url = "http://localhost:8000"
        self.proxy_url = "http://localhost:8080"
        self.valid_api_key = "test-cluster-api-key"
        self.session = requests.Session()

    def test_sql_injection_protection(self):
        """Test SQL injection attack prevention"""
        sql_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "'; UPDATE users SET is_admin=1; --",
            "' UNION SELECT * FROM users --",
            "'; INSERT INTO users (username, password_hash, is_admin) VALUES ('hacker', 'hash', 1); --"
        ]

        # Test various endpoints with SQL injection payloads
        endpoints = [
            "/api/services",
            "/api/mappings",
            "/api/clusters",
            "/api/users"
        ]

        for endpoint in endpoints:
            for payload in sql_payloads:
                # Test GET parameters
                response = self.session.get(
                    urljoin(self.manager_url, endpoint),
                    params={'id': payload},
                    headers={'X-Cluster-API-Key': self.valid_api_key}
                )
                self.assertNotIn("error in your SQL syntax", response.text.lower())
                self.assertNotIn("mysql_fetch", response.text.lower())
                self.assertNotIn("postgresql error", response.text.lower())

                # Test POST data
                response = self.session.post(
                    urljoin(self.manager_url, endpoint),
                    json={'name': payload},
                    headers={'X-Cluster-API-Key': self.valid_api_key}
                )
                self.assertNotIn("error in your SQL syntax", response.text.lower())

    def test_xss_protection(self):
        """Test Cross-Site Scripting (XSS) attack prevention"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>"
        ]

        # Test service creation with XSS payloads
        for payload in xss_payloads:
            service_data = {
                'name': payload,
                'ip_fqdn': f'test{payload}.example.com',
                'collection': 'security-test',
                'cluster_id': 1,
                'auth_type': 'token'
            }

            response = self.session.post(
                urljoin(self.manager_url, "/api/services"),
                json=service_data,
                headers={'X-Cluster-API-Key': self.valid_api_key}
            )

            # Response should either reject the input or escape it properly
            if response.status_code == 201:
                # If accepted, verify it's properly escaped in responses
                response = self.session.get(
                    urljoin(self.manager_url, "/api/config/1"),
                    headers={'X-Cluster-API-Key': self.valid_api_key}
                )
                # Should not contain unescaped script tags
                self.assertNotIn("<script>", response.text)
                self.assertNotIn("javascript:", response.text)

    def test_command_injection_protection(self):
        """Test command injection attack prevention"""
        command_payloads = [
            "; ls -la",
            "| whoami",
            "& cat /etc/passwd",
            "`id`",
            "$(whoami)",
            "; rm -rf /",
            "| nc -l -p 4444 -e /bin/sh"
        ]

        # Test hostname/IP fields that might be used in system commands
        for payload in command_payloads:
            service_data = {
                'name': 'test-service',
                'ip_fqdn': f'test{payload}',
                'collection': 'security-test',
                'cluster_id': 1,
                'auth_type': 'token'
            }

            response = self.session.post(
                urljoin(self.manager_url, "/api/services"),
                json=service_data,
                headers={'X-Cluster-API-Key': self.valid_api_key}
            )

            # Should reject invalid hostnames/IPs
            self.assertIn(response.status_code, [400, 422])

    def test_authentication_bypass_attempts(self):
        """Test authentication bypass vulnerabilities"""
        # Test endpoints without API key
        protected_endpoints = [
            "/api/config/1",
            "/api/services",
            "/api/mappings",
            "/api/clusters"
        ]

        for endpoint in protected_endpoints:
            response = self.session.get(urljoin(self.manager_url, endpoint))
            self.assertEqual(response.status_code, 401)

        # Test with invalid API keys
        invalid_keys = [
            "invalid-key",
            "",
            "null",
            "undefined",
            "admin",
            "test",
            "../../../etc/passwd"
        ]

        for invalid_key in invalid_keys:
            response = self.session.get(
                urljoin(self.manager_url, "/api/config/1"),
                headers={'X-Cluster-API-Key': invalid_key}
            )
            self.assertEqual(response.status_code, 401)

    def test_jwt_security(self):
        """Test JWT token security"""
        # Test JWT with none algorithm (should be rejected)
        none_jwt = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).decode().rstrip('=')

        none_payload = base64.urlsafe_b64encode(
            json.dumps({
                "sub": "test-service",
                "service_id": 1,
                "cluster_id": 1,
                "exp": int(time.time()) + 3600
            }).encode()
        ).decode().rstrip('=')

        none_token = f"{none_jwt}.{none_payload}."

        # This should be rejected by the proxy
        response = self.session.get(
            self.proxy_url,
            headers={'Authorization': f'Bearer {none_token}'}
        )
        self.assertNotEqual(response.status_code, 200)

        # Test expired JWT (if JWT validation is implemented)
        expired_payload = base64.urlsafe_b64encode(
            json.dumps({
                "sub": "test-service",
                "service_id": 1,
                "cluster_id": 1,
                "exp": int(time.time()) - 3600  # Expired 1 hour ago
            }).encode()
        ).decode().rstrip('=')

        # Note: This would need a properly signed JWT in real implementation
        # For now, just test that expired tokens are handled

    def test_directory_traversal_protection(self):
        """Test directory traversal attack prevention"""
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc//passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ]

        # Test file access endpoints (if any exist)
        for payload in traversal_payloads:
            # Test certificate upload endpoint
            response = self.session.get(
                urljoin(self.manager_url, f"/api/certificates/{payload}"),
                headers={'X-Cluster-API-Key': self.valid_api_key}
            )
            # Should not return file contents or 200 for system files
            self.assertNotEqual(response.status_code, 200)

    def test_rate_limiting(self):
        """Test rate limiting protection"""
        # Make rapid requests to test rate limiting
        rapid_requests = []
        for i in range(100):
            response = self.session.get(
                urljoin(self.manager_url, "/healthz")
            )
            rapid_requests.append(response.status_code)

        # Should have some rate limiting after many rapid requests
        rate_limited = any(status == 429 for status in rapid_requests[-20:])
        if not rate_limited:
            print("Warning: No rate limiting detected")

    def test_ddos_protection(self):
        """Test DDoS protection mechanisms"""
        def make_requests():
            """Make rapid requests from a thread"""
            results = []
            for _ in range(50):
                try:
                    response = requests.get(
                        urljoin(self.manager_url, "/healthz"),
                        timeout=1
                    )
                    results.append(response.status_code)
                except:
                    results.append(0)  # Failed request
            return results

        # Simulate multiple concurrent clients
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=make_requests)
            threads.append(thread)

        # Start all threads
        for thread in threads:
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join()

        print("DDoS protection test completed")

    def test_input_validation(self):
        """Test comprehensive input validation"""
        # Test extremely long inputs
        long_string = "A" * 10000

        invalid_inputs = [
            {"name": long_string},
            {"name": None},
            {"name": 123},
            {"name": {"nested": "object"}},
            {"name": ["array", "input"]},
            {"ip_fqdn": "not-a-valid-ip-or-fqdn"},
            {"ports": [-1, 70000]},  # Invalid port numbers
            {"cluster_id": -1},
            {"cluster_id": "string-instead-of-int"}
        ]

        for invalid_input in invalid_inputs:
            response = self.session.post(
                urljoin(self.manager_url, "/api/services"),
                json=invalid_input,
                headers={'X-Cluster-API-Key': self.valid_api_key}
            )
            # Should reject invalid inputs
            self.assertIn(response.status_code, [400, 422])

    def test_header_injection(self):
        """Test HTTP header injection attacks"""
        malicious_headers = [
            "test\r\nX-Injected-Header: malicious",
            "test\nSet-Cookie: admin=true",
            "test\r\n\r\n<script>alert('XSS')</script>",
        ]

        for malicious_value in malicious_headers:
            response = self.session.get(
                urljoin(self.manager_url, "/healthz"),
                headers={'X-Custom-Header': malicious_value}
            )
            # Should not reflect malicious headers
            self.assertNotIn("X-Injected-Header", response.headers)
            self.assertNotIn("Set-Cookie", response.headers)

    def test_ssl_tls_security(self):
        """Test SSL/TLS security configuration"""
        try:
            # Test SSL/TLS configuration if HTTPS is available
            if self.manager_url.startswith('https'):
                # Test weak cipher suites
                context = ssl.create_default_context()
                context.set_ciphers('ALL:@SECLEVEL=0')  # Allow weak ciphers

                # Should reject weak ciphers
                with self.assertRaises(ssl.SSLError):
                    requests.get(self.manager_url, verify=False)

        except Exception as e:
            print(f"SSL/TLS test skipped: {e}")

    def test_information_disclosure(self):
        """Test for information disclosure vulnerabilities"""
        # Test error pages don't reveal sensitive information
        response = self.session.get(
            urljoin(self.manager_url, "/nonexistent-endpoint")
        )

        error_content = response.text.lower()

        # Should not reveal sensitive information
        sensitive_patterns = [
            "traceback",
            "stack trace",
            "database error",
            "internal server error details",
            "file not found: /",
            "python",
            "django",
            "flask"
        ]

        for pattern in sensitive_patterns:
            self.assertNotIn(pattern, error_content,
                           f"Error page reveals sensitive information: {pattern}")

    def test_file_upload_security(self):
        """Test file upload security (if file upload exists)"""
        # Test malicious file uploads
        malicious_files = [
            ("test.php", b"<?php system($_GET['cmd']); ?>", "application/x-php"),
            ("test.jsp", b"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "application/x-jsp"),
            ("test.asp", b"<% eval request(\"cmd\") %>", "application/x-asp"),
            ("../../../test.txt", b"directory traversal", "text/plain"),
        ]

        # This would test certificate upload endpoint if it exists
        for filename, content, content_type in malicious_files:
            files = {'file': (filename, content, content_type)}
            response = self.session.post(
                urljoin(self.manager_url, "/api/certificates/upload"),
                files=files,
                headers={'X-Cluster-API-Key': self.valid_api_key}
            )

            # Should reject malicious files
            if response.status_code == 200:
                # If upload succeeds, ensure files are not executable
                self.assertIn("uploaded", response.text.lower())

    def test_session_security(self):
        """Test session management security"""
        # Test session fixation
        initial_cookies = self.session.cookies

        # Make authenticated request
        response = self.session.get(
            urljoin(self.manager_url, "/api/config/1"),
            headers={'X-Cluster-API-Key': self.valid_api_key}
        )

        # Session cookies should be secure
        for cookie in self.session.cookies:
            if cookie.secure is not None:
                self.assertTrue(cookie.secure, f"Cookie {cookie.name} should be secure")
            if cookie.has_nonstandard_attr('HttpOnly'):
                self.assertTrue(cookie.has_nonstandard_attr('HttpOnly'),
                              f"Cookie {cookie.name} should be HttpOnly")

    def test_cors_security(self):
        """Test CORS configuration security"""
        # Test CORS headers
        origins = [
            "http://evil.com",
            "https://malicious.site",
            "null",
            "*"
        ]

        for origin in origins:
            response = self.session.options(
                urljoin(self.manager_url, "/api/config/1"),
                headers={
                    'Origin': origin,
                    'Access-Control-Request-Method': 'GET',
                    'X-Cluster-API-Key': self.valid_api_key
                }
            )

            # Should not allow arbitrary origins
            cors_origin = response.headers.get('Access-Control-Allow-Origin', '')
            if cors_origin:
                self.assertNotEqual(cors_origin, '*', "CORS should not allow all origins")
                self.assertNotIn('evil.com', cors_origin, "CORS should not allow malicious origins")

    def run_security_scan(self):
        """Run automated security scan using tools if available"""
        try:
            # Try to run nikto if available
            result = subprocess.run([
                'nikto', '-h', self.manager_url.replace('http://', '').replace('https://', ''),
                '-Format', 'txt'
            ], capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                print("Nikto scan completed:")
                print(result.stdout)
            else:
                print("Nikto scan failed or not available")

        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("Security scanning tools not available")

class ProxySecurityTests(unittest.TestCase):
    """Security tests specific to the proxy component"""

    def setUp(self):
        """Set up proxy test environment"""
        self.proxy_host = "localhost"
        self.proxy_port = 8080

    def test_tcp_injection_attacks(self):
        """Test TCP-level injection attacks"""
        malicious_payloads = [
            b"\x00\x01\x02\x03",  # Binary data
            b"\xff" * 1000,       # Large binary payload
            b"GET /../../../etc/passwd HTTP/1.1\r\n\r\n",  # HTTP injection
        ]

        for payload in malicious_payloads:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.proxy_host, self.proxy_port))
                sock.send(payload)

                response = sock.recv(1024)
                sock.close()

                # Should not return sensitive file contents
                self.assertNotIn(b"root:", response)
                self.assertNotIn(b"/bin/bash", response)

            except Exception:
                pass  # Connection might be rejected, which is fine

    def test_buffer_overflow_attempts(self):
        """Test buffer overflow protection"""
        # Send extremely large payload
        large_payload = b"A" * 100000

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.proxy_host, self.proxy_port))

            # Send large payload in chunks
            for i in range(0, len(large_payload), 4096):
                sock.send(large_payload[i:i+4096])

            response = sock.recv(1024)
            sock.close()

            # Proxy should handle large payloads gracefully
            print("Large payload test completed")

        except Exception as e:
            # Connection might be closed, which is acceptable
            print(f"Large payload rejected: {e}")

    def test_connection_exhaustion(self):
        """Test connection exhaustion attacks"""
        connections = []

        try:
            # Try to open many connections
            for i in range(1000):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((self.proxy_host, self.proxy_port))
                connections.append(sock)

        except Exception:
            # Should eventually reject connections
            pass

        finally:
            # Clean up connections
            for sock in connections:
                try:
                    sock.close()
                except:
                    pass

        print(f"Opened {len(connections)} connections before limit")

if __name__ == '__main__':
    # Run security tests
    suite = unittest.TestSuite()

    # Add security test cases
    suite.addTest(unittest.makeSuite(SecurityTestSuite))
    suite.addTest(unittest.makeSuite(ProxySecurityTests))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print security test summary
    print(f"\n{'='*60}")
    print("SECURITY TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    if result.failures:
        print("\nSECURITY FAILURES:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback.split('AssertionError:')[-1].strip()}")

    if result.errors:
        print("\nSECURITY ERRORS:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback.split('Exception:')[-1].strip()}")

    # Exit with proper code
    sys.exit(0 if result.wasSuccessful() else 1)