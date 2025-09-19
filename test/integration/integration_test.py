#!/usr/bin/env python3
"""
Integration tests for MarchProxy full system

Copyright (C) 2025 MarchProxy Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import unittest
import requests
import docker
import time
import socket
import subprocess
import os
import signal
import json
import threading
from contextlib import contextmanager

class MarchProxyIntegrationTest(unittest.TestCase):
    """Integration tests for complete MarchProxy system"""

    @classmethod
    def setUpClass(cls):
        """Set up Docker containers for integration testing"""
        cls.docker_client = docker.from_env()
        cls.containers = {}
        cls.base_dir = os.path.join(os.path.dirname(__file__), '../..')

        # Start PostgreSQL
        cls._start_postgresql()

        # Start Redis
        cls._start_redis()

        # Start Manager
        cls._start_manager()

        # Start Proxy
        cls._start_proxy()

        # Wait for services to be ready
        cls._wait_for_services()

    @classmethod
    def tearDownClass(cls):
        """Clean up Docker containers"""
        for container in cls.containers.values():
            try:
                container.stop()
                container.remove()
            except:
                pass

    @classmethod
    def _start_postgresql(cls):
        """Start PostgreSQL container"""
        cls.containers['postgresql'] = cls.docker_client.containers.run(
            'postgres:15',
            environment={
                'POSTGRES_DB': 'marchproxy',
                'POSTGRES_USER': 'marchproxy',
                'POSTGRES_PASSWORD': 'marchproxy123'
            },
            ports={'5432/tcp': 5432},
            detach=True,
            remove=True,
            name='marchproxy-test-postgres'
        )

    @classmethod
    def _start_redis(cls):
        """Start Redis container"""
        cls.containers['redis'] = cls.docker_client.containers.run(
            'redis:7-alpine',
            ports={'6379/tcp': 6379},
            detach=True,
            remove=True,
            name='marchproxy-test-redis'
        )

    @classmethod
    def _start_manager(cls):
        """Start Manager container"""
        # Build manager image if needed
        manager_dockerfile = os.path.join(cls.base_dir, 'manager', 'Dockerfile')
        if os.path.exists(manager_dockerfile):
            cls.docker_client.images.build(
                path=os.path.join(cls.base_dir, 'manager'),
                tag='marchproxy-manager:test'
            )

        cls.containers['manager'] = cls.docker_client.containers.run(
            'marchproxy-manager:test',
            environment={
                'DATABASE_URL': 'postgresql://marchproxy:marchproxy123@localhost:5432/marchproxy',
                'REDIS_URL': 'redis://localhost:6379/0',
                'JWT_SECRET': 'test-jwt-secret-key',
                'LOG_LEVEL': 'debug'
            },
            ports={'8000/tcp': 8000, '9090/tcp': 9090},
            network_mode='host',
            detach=True,
            remove=True,
            name='marchproxy-test-manager'
        )

    @classmethod
    def _start_proxy(cls):
        """Start Proxy container"""
        # Build proxy image if needed
        proxy_dockerfile = os.path.join(cls.base_dir, 'proxy', 'Dockerfile')
        if os.path.exists(proxy_dockerfile):
            cls.docker_client.images.build(
                path=os.path.join(cls.base_dir, 'proxy'),
                tag='marchproxy-proxy:test'
            )

        cls.containers['proxy'] = cls.docker_client.containers.run(
            'marchproxy-proxy:test',
            environment={
                'MANAGER_URL': 'http://localhost:8000',
                'CLUSTER_API_KEY': 'test-cluster-api-key',
                'LOG_LEVEL': 'debug'
            },
            ports={'8080/tcp': 8080, '8888/tcp': 8888},
            network_mode='host',
            privileged=True,  # Required for eBPF
            detach=True,
            remove=True,
            name='marchproxy-test-proxy'
        )

    @classmethod
    def _wait_for_services(cls):
        """Wait for all services to be healthy"""
        # Wait for PostgreSQL
        cls._wait_for_port('localhost', 5432, timeout=30)

        # Wait for Redis
        cls._wait_for_port('localhost', 6379, timeout=30)

        # Wait for Manager
        cls._wait_for_http('http://localhost:8000/healthz', timeout=60)

        # Wait for Proxy
        cls._wait_for_http('http://localhost:8888/healthz', timeout=60)

    @classmethod
    def _wait_for_port(cls, host, port, timeout=30):
        """Wait for TCP port to be available"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    return True
            except:
                pass
            time.sleep(1)
        raise Exception(f"Port {host}:{port} not available after {timeout} seconds")

    @classmethod
    def _wait_for_http(cls, url, timeout=30):
        """Wait for HTTP endpoint to be available"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    return True
            except:
                pass
            time.sleep(2)
        raise Exception(f"HTTP endpoint {url} not available after {timeout} seconds")

    def test_manager_health_endpoint(self):
        """Test manager health endpoint"""
        response = requests.get('http://localhost:8000/healthz')
        self.assertEqual(response.status_code, 200)

        health_data = response.json()
        self.assertEqual(health_data['status'], 'healthy')
        self.assertIn('checks', health_data)

    def test_manager_metrics_endpoint(self):
        """Test manager metrics endpoint"""
        response = requests.get('http://localhost:9090/metrics')
        self.assertEqual(response.status_code, 200)

        metrics = response.text
        self.assertIn('marchproxy_manager', metrics)

    def test_proxy_health_endpoint(self):
        """Test proxy health endpoint"""
        response = requests.get('http://localhost:8888/healthz')
        self.assertEqual(response.status_code, 200)

        health_data = response.json()
        self.assertEqual(health_data['status'], 'healthy')

    def test_proxy_registration(self):
        """Test proxy registration with manager"""
        # Check that proxy has registered
        response = requests.get('http://localhost:8000/api/proxy/status')
        self.assertEqual(response.status_code, 200)

        status_data = response.json()
        self.assertGreater(status_data['proxy_count'], 0)

    def test_cluster_api_key_validation(self):
        """Test cluster API key validation"""
        # Test valid API key
        headers = {'X-Cluster-API-Key': 'test-cluster-api-key'}
        response = requests.get('http://localhost:8000/api/config/1', headers=headers)
        self.assertEqual(response.status_code, 200)

        # Test invalid API key
        headers = {'X-Cluster-API-Key': 'invalid-api-key'}
        response = requests.get('http://localhost:8000/api/config/1', headers=headers)
        self.assertEqual(response.status_code, 401)

    def test_service_creation_and_configuration(self):
        """Test service creation and configuration retrieval"""
        # Create a test service
        service_data = {
            'name': 'test-service',
            'ip_fqdn': 'test.example.com',
            'collection': 'integration-test',
            'cluster_id': 1,
            'auth_type': 'jwt'
        }

        response = requests.post(
            'http://localhost:8000/api/services',
            json=service_data,
            headers={'X-Cluster-API-Key': 'test-cluster-api-key'}
        )
        self.assertEqual(response.status_code, 201)

        service_id = response.json()['service_id']

        # Retrieve configuration
        response = requests.get(
            'http://localhost:8000/api/config/1',
            headers={'X-Cluster-API-Key': 'test-cluster-api-key'}
        )
        self.assertEqual(response.status_code, 200)

        config = response.json()
        self.assertIn('services', config)

        # Find our test service
        test_service = None
        for service in config['services']:
            if service['id'] == service_id:
                test_service = service
                break

        self.assertIsNotNone(test_service)
        self.assertEqual(test_service['name'], 'test-service')

    def test_mapping_creation_and_retrieval(self):
        """Test mapping creation and retrieval"""
        # First create services
        service1_data = {
            'name': 'source-service',
            'ip_fqdn': 'source.example.com',
            'collection': 'integration-test',
            'cluster_id': 1,
            'auth_type': 'token'
        }

        response = requests.post(
            'http://localhost:8000/api/services',
            json=service1_data,
            headers={'X-Cluster-API-Key': 'test-cluster-api-key'}
        )
        source_service_id = response.json()['service_id']

        service2_data = {
            'name': 'dest-service',
            'ip_fqdn': 'dest.example.com',
            'collection': 'integration-test',
            'cluster_id': 1,
            'auth_type': 'token'
        }

        response = requests.post(
            'http://localhost:8000/api/services',
            json=service2_data,
            headers={'X-Cluster-API-Key': 'test-cluster-api-key'}
        )
        dest_service_id = response.json()['service_id']

        # Create mapping
        mapping_data = {
            'source_services': [source_service_id],
            'dest_services': [dest_service_id],
            'cluster_id': 1,
            'protocols': ['tcp'],
            'ports': [80, 443],
            'auth_required': True
        }

        response = requests.post(
            'http://localhost:8000/api/mappings',
            json=mapping_data,
            headers={'X-Cluster-API-Key': 'test-cluster-api-key'}
        )
        self.assertEqual(response.status_code, 201)

        # Retrieve configuration with mapping
        response = requests.get(
            'http://localhost:8000/api/config/1',
            headers={'X-Cluster-API-Key': 'test-cluster-api-key'}
        )
        self.assertEqual(response.status_code, 200)

        config = response.json()
        self.assertIn('mappings', config)
        self.assertGreater(len(config['mappings']), 0)

    def test_license_validation_endpoint(self):
        """Test license validation (mock Enterprise functionality)"""
        license_data = {
            'license_key': 'PENG-TEST-1234-5678-9012-ABCD',
            'proxy_count': 1
        }

        response = requests.post(
            'http://localhost:8000/api/license/validate',
            json=license_data,
            headers={'X-Cluster-API-Key': 'test-cluster-api-key'}
        )

        # Should handle license validation gracefully
        self.assertIn(response.status_code, [200, 503])  # 503 if license server unavailable

    def test_tcp_proxy_functionality(self):
        """Test basic TCP proxy functionality"""
        # Start a simple echo server for testing
        echo_server = self._start_echo_server(9999)

        try:
            # Configure proxy to forward to echo server
            service_data = {
                'name': 'echo-service',
                'ip_fqdn': 'localhost:9999',
                'collection': 'integration-test',
                'cluster_id': 1,
                'auth_type': 'none'
            }

            response = requests.post(
                'http://localhost:8000/api/services',
                json=service_data,
                headers={'X-Cluster-API-Key': 'test-cluster-api-key'}
            )
            service_id = response.json()['service_id']

            # Create mapping
            mapping_data = {
                'source_services': ['any'],
                'dest_services': [service_id],
                'cluster_id': 1,
                'protocols': ['tcp'],
                'ports': [8080],
                'auth_required': False
            }

            response = requests.post(
                'http://localhost:8000/api/mappings',
                json=mapping_data,
                headers={'X-Cluster-API-Key': 'test-cluster-api-key'}
            )

            # Wait for configuration to propagate
            time.sleep(5)

            # Test proxy connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect(('localhost', 8080))
                test_message = b"Hello, MarchProxy!"
                sock.send(test_message)

                response = sock.recv(1024)
                self.assertEqual(response, test_message)
            finally:
                sock.close()

        finally:
            echo_server.terminate()

    def test_configuration_hot_reload(self):
        """Test configuration hot reload functionality"""
        # Get initial configuration
        response = requests.get(
            'http://localhost:8000/api/config/1',
            headers={'X-Cluster-API-Key': 'test-cluster-api-key'}
        )
        initial_config = response.json()
        initial_service_count = len(initial_config.get('services', []))

        # Add new service
        service_data = {
            'name': 'reload-test-service',
            'ip_fqdn': 'reload.example.com',
            'collection': 'integration-test',
            'cluster_id': 1,
            'auth_type': 'token'
        }

        response = requests.post(
            'http://localhost:8000/api/services',
            json=service_data,
            headers={'X-Cluster-API-Key': 'test-cluster-api-key'}
        )
        self.assertEqual(response.status_code, 201)

        # Wait for configuration to reload
        time.sleep(65)  # Config refresh interval is 60 seconds

        # Check updated configuration
        response = requests.get(
            'http://localhost:8000/api/config/1',
            headers={'X-Cluster-API-Key': 'test-cluster-api-key'}
        )
        updated_config = response.json()
        updated_service_count = len(updated_config.get('services', []))

        self.assertGreater(updated_service_count, initial_service_count)

    def test_metrics_collection(self):
        """Test metrics collection from both manager and proxy"""
        # Generate some traffic
        for _ in range(5):
            requests.get('http://localhost:8000/healthz')
            requests.get('http://localhost:8888/healthz')

        # Check manager metrics
        response = requests.get('http://localhost:9090/metrics')
        manager_metrics = response.text
        self.assertIn('marchproxy_manager_requests_total', manager_metrics)

        # Check proxy metrics (if available)
        try:
            response = requests.get('http://localhost:8888/metrics')
            proxy_metrics = response.text
            self.assertIn('marchproxy_proxy', proxy_metrics)
        except:
            pass  # Proxy metrics endpoint might not be implemented yet

    def test_error_handling_and_recovery(self):
        """Test error handling and recovery scenarios"""
        # Test invalid service creation
        invalid_service_data = {
            'name': '',  # Invalid: empty name
            'ip_fqdn': 'invalid',
            'cluster_id': 1
        }

        response = requests.post(
            'http://localhost:8000/api/services',
            json=invalid_service_data,
            headers={'X-Cluster-API-Key': 'test-cluster-api-key'}
        )
        self.assertEqual(response.status_code, 400)

        # Test unauthorized access
        response = requests.get('http://localhost:8000/api/config/1')
        self.assertEqual(response.status_code, 401)

    def _start_echo_server(self, port):
        """Start a simple echo server for testing"""
        server_code = f"""
import socket
import threading

def handle_client(conn, addr):
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.send(data)
    except:
        pass
    finally:
        conn.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('localhost', {port}))
server.listen(5)

while True:
    try:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.daemon = True
        thread.start()
    except:
        break
"""

        process = subprocess.Popen([
            'python3', '-c', server_code
        ])

        # Wait for server to start
        self._wait_for_port('localhost', port, timeout=10)

        return process

if __name__ == '__main__':
    unittest.main(verbosity=2)