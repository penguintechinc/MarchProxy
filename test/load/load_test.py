#!/usr/bin/env python3
"""
Load tests for MarchProxy performance testing

Copyright (C) 2025 MarchProxy Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import asyncio
import aiohttp
import time
import statistics
import json
import argparse
import concurrent.futures
import threading
import socket
import ssl
from dataclasses import dataclass
from typing import List, Dict, Any
import matplotlib.pyplot as plt
import pandas as pd

@dataclass
class LoadTestResult:
    """Load test result data"""
    test_name: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    duration_seconds: float
    requests_per_second: float
    average_response_time: float
    median_response_time: float
    p95_response_time: float
    p99_response_time: float
    min_response_time: float
    max_response_time: float
    error_rate: float

class MarchProxyLoadTester:
    """Load testing framework for MarchProxy"""

    def __init__(self, manager_url: str, proxy_url: str, cluster_api_key: str):
        self.manager_url = manager_url
        self.proxy_url = proxy_url
        self.cluster_api_key = cluster_api_key
        self.results: List[LoadTestResult] = []

    async def test_manager_api_load(self, concurrent_users: int = 100, requests_per_user: int = 100):
        """Test manager API under load"""
        print(f"Testing Manager API load: {concurrent_users} users, {requests_per_user} requests each")

        response_times = []
        successful_requests = 0
        failed_requests = 0
        start_time = time.time()

        async def make_request(session: aiohttp.ClientSession):
            try:
                async with session.get(
                    f"{self.manager_url}/healthz",
                    headers={'X-Cluster-API-Key': self.cluster_api_key}
                ) as response:
                    if response.status == 200:
                        return True, time.time()
                    else:
                        return False, time.time()
            except Exception as e:
                return False, time.time()

        async def user_simulation(user_id: int):
            """Simulate a user making multiple requests"""
            connector = aiohttp.TCPConnector(limit=10)
            timeout = aiohttp.ClientTimeout(total=30)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                for _ in range(requests_per_user):
                    request_start = time.time()
                    success, request_end = await make_request(session)
                    response_time = request_end - request_start

                    response_times.append(response_time)
                    if success:
                        nonlocal successful_requests
                        successful_requests += 1
                    else:
                        nonlocal failed_requests
                        failed_requests += 1

        # Run concurrent users
        tasks = [user_simulation(i) for i in range(concurrent_users)]
        await asyncio.gather(*tasks)

        end_time = time.time()
        duration = end_time - start_time
        total_requests = concurrent_users * requests_per_user

        # Calculate statistics
        if response_times:
            avg_response_time = statistics.mean(response_times)
            median_response_time = statistics.median(response_times)
            p95_response_time = self._percentile(response_times, 95)
            p99_response_time = self._percentile(response_times, 99)
            min_response_time = min(response_times)
            max_response_time = max(response_times)
        else:
            avg_response_time = median_response_time = p95_response_time = p99_response_time = 0
            min_response_time = max_response_time = 0

        result = LoadTestResult(
            test_name="Manager API Load Test",
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            duration_seconds=duration,
            requests_per_second=total_requests / duration if duration > 0 else 0,
            average_response_time=avg_response_time,
            median_response_time=median_response_time,
            p95_response_time=p95_response_time,
            p99_response_time=p99_response_time,
            min_response_time=min_response_time,
            max_response_time=max_response_time,
            error_rate=(failed_requests / total_requests) * 100 if total_requests > 0 else 0
        )

        self.results.append(result)
        self._print_result(result)

    def test_tcp_proxy_load(self, concurrent_connections: int = 1000, bytes_per_connection: int = 1024):
        """Test TCP proxy under load"""
        print(f"Testing TCP Proxy load: {concurrent_connections} connections, {bytes_per_connection} bytes each")

        response_times = []
        successful_connections = 0
        failed_connections = 0
        start_time = time.time()

        def tcp_connection_test():
            """Test a single TCP connection"""
            try:
                conn_start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(30)

                # Extract host and port from proxy URL
                proxy_host = self.proxy_url.split('://')[1].split(':')[0]
                proxy_port = int(self.proxy_url.split(':')[-1])

                sock.connect((proxy_host, proxy_port))

                # Send test data
                test_data = b'A' * bytes_per_connection
                sock.send(test_data)

                # Receive response
                response = sock.recv(bytes_per_connection)
                sock.close()

                conn_end = time.time()
                response_time = conn_end - conn_start

                if len(response) > 0:
                    nonlocal successful_connections
                    successful_connections += 1
                    response_times.append(response_time)
                else:
                    nonlocal failed_connections
                    failed_connections += 1

            except Exception as e:
                nonlocal failed_connections
                failed_connections += 1

        # Run concurrent connections
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_connections) as executor:
            futures = [executor.submit(tcp_connection_test) for _ in range(concurrent_connections)]
            concurrent.futures.wait(futures)

        end_time = time.time()
        duration = end_time - start_time

        # Calculate statistics
        if response_times:
            avg_response_time = statistics.mean(response_times)
            median_response_time = statistics.median(response_times)
            p95_response_time = self._percentile(response_times, 95)
            p99_response_time = self._percentile(response_times, 99)
            min_response_time = min(response_times)
            max_response_time = max(response_times)
        else:
            avg_response_time = median_response_time = p95_response_time = p99_response_time = 0
            min_response_time = max_response_time = 0

        result = LoadTestResult(
            test_name="TCP Proxy Load Test",
            total_requests=concurrent_connections,
            successful_requests=successful_connections,
            failed_requests=failed_connections,
            duration_seconds=duration,
            requests_per_second=concurrent_connections / duration if duration > 0 else 0,
            average_response_time=avg_response_time,
            median_response_time=median_response_time,
            p95_response_time=p95_response_time,
            p99_response_time=p99_response_time,
            min_response_time=min_response_time,
            max_response_time=max_response_time,
            error_rate=(failed_connections / concurrent_connections) * 100 if concurrent_connections > 0 else 0
        )

        self.results.append(result)
        self._print_result(result)

    async def test_configuration_load(self, concurrent_requests: int = 50, duration_seconds: int = 60):
        """Test configuration endpoint under sustained load"""
        print(f"Testing Configuration load: {concurrent_requests} concurrent requests for {duration_seconds} seconds")

        response_times = []
        successful_requests = 0
        failed_requests = 0
        start_time = time.time()
        end_time = start_time + duration_seconds

        async def make_config_request(session: aiohttp.ClientSession):
            try:
                async with session.get(
                    f"{self.manager_url}/api/config/1",
                    headers={'X-Cluster-API-Key': self.cluster_api_key}
                ) as response:
                    if response.status == 200:
                        return True, time.time()
                    else:
                        return False, time.time()
            except Exception:
                return False, time.time()

        async def sustained_load():
            """Generate sustained load for specified duration"""
            connector = aiohttp.TCPConnector(limit=concurrent_requests)
            timeout = aiohttp.ClientTimeout(total=30)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                while time.time() < end_time:
                    tasks = []
                    for _ in range(concurrent_requests):
                        request_start = time.time()
                        task = asyncio.create_task(make_config_request(session))
                        tasks.append((task, request_start))

                    # Wait for all requests to complete
                    for task, request_start in tasks:
                        try:
                            success, request_end = await task
                            response_time = request_end - request_start
                            response_times.append(response_time)

                            if success:
                                nonlocal successful_requests
                                successful_requests += 1
                            else:
                                nonlocal failed_requests
                                failed_requests += 1
                        except Exception:
                            nonlocal failed_requests
                            failed_requests += 1

                    # Small delay between batches
                    await asyncio.sleep(0.1)

        await sustained_load()

        actual_duration = time.time() - start_time
        total_requests = successful_requests + failed_requests

        # Calculate statistics
        if response_times:
            avg_response_time = statistics.mean(response_times)
            median_response_time = statistics.median(response_times)
            p95_response_time = self._percentile(response_times, 95)
            p99_response_time = self._percentile(response_times, 99)
            min_response_time = min(response_times)
            max_response_time = max(response_times)
        else:
            avg_response_time = median_response_time = p95_response_time = p99_response_time = 0
            min_response_time = max_response_time = 0

        result = LoadTestResult(
            test_name="Configuration Load Test",
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            duration_seconds=actual_duration,
            requests_per_second=total_requests / actual_duration if actual_duration > 0 else 0,
            average_response_time=avg_response_time,
            median_response_time=median_response_time,
            p95_response_time=p95_response_time,
            p99_response_time=p99_response_time,
            min_response_time=min_response_time,
            max_response_time=max_response_time,
            error_rate=(failed_requests / total_requests) * 100 if total_requests > 0 else 0
        )

        self.results.append(result)
        self._print_result(result)

    def test_memory_leak_detection(self, duration_minutes: int = 30):
        """Test for memory leaks over extended period"""
        print(f"Testing for memory leaks over {duration_minutes} minutes")

        import psutil
        import requests

        duration_seconds = duration_minutes * 60
        end_time = time.time() + duration_seconds
        memory_samples = []

        def get_container_memory():
            """Get memory usage of MarchProxy containers"""
            try:
                # This would need to be adapted based on actual container monitoring
                manager_memory = 0
                proxy_memory = 0

                # Mock memory monitoring - in real implementation,
                # would query Docker API or Kubernetes metrics
                response = requests.get(f"{self.manager_url}/metrics", timeout=5)
                if response.status_code == 200:
                    # Parse memory metrics from Prometheus format
                    lines = response.text.split('\n')
                    for line in lines:
                        if 'process_resident_memory_bytes' in line and not line.startswith('#'):
                            manager_memory = float(line.split()[-1])
                            break

                return {
                    'timestamp': time.time(),
                    'manager_memory': manager_memory,
                    'proxy_memory': proxy_memory
                }
            except:
                return None

        # Monitor memory while generating load
        while time.time() < end_time:
            # Generate some load
            try:
                requests.get(f"{self.manager_url}/healthz", timeout=5)
                requests.get(f"{self.manager_url}/api/config/1",
                           headers={'X-Cluster-API-Key': self.cluster_api_key}, timeout=5)
            except:
                pass

            # Sample memory
            memory_sample = get_container_memory()
            if memory_sample:
                memory_samples.append(memory_sample)

            time.sleep(10)  # Sample every 10 seconds

        # Analyze memory usage trend
        if len(memory_samples) > 10:
            timestamps = [s['timestamp'] for s in memory_samples]
            manager_memory = [s['manager_memory'] for s in memory_samples if s['manager_memory'] > 0]

            if manager_memory:
                # Calculate memory growth rate
                memory_growth = (manager_memory[-1] - manager_memory[0]) / len(manager_memory)

                print(f"Memory Analysis:")
                print(f"  Initial Manager Memory: {manager_memory[0]:,.0f} bytes")
                print(f"  Final Manager Memory: {manager_memory[-1]:,.0f} bytes")
                print(f"  Average Growth per Sample: {memory_growth:,.0f} bytes")

                if memory_growth > 1024 * 1024:  # 1MB growth per sample
                    print(f"  WARNING: Potential memory leak detected!")
                else:
                    print(f"  Memory usage appears stable")

    def test_stress_breaking_point(self):
        """Find the breaking point of the system"""
        print("Finding system breaking point...")

        concurrent_levels = [10, 50, 100, 200, 500, 1000, 2000, 5000]
        breaking_point = None

        for level in concurrent_levels:
            print(f"Testing {level} concurrent users...")

            # Run a short load test
            asyncio.run(self._short_load_test(level))

            # Check if this level broke the system
            last_result = self.results[-1]
            if last_result.error_rate > 5:  # More than 5% errors
                breaking_point = level
                print(f"Breaking point found at {level} concurrent users")
                break
            elif last_result.average_response_time > 5.0:  # Response time > 5 seconds
                breaking_point = level
                print(f"Performance degradation at {level} concurrent users")
                break

            # Wait between tests
            time.sleep(5)

        if breaking_point:
            print(f"System breaking point: {breaking_point} concurrent users")
        else:
            print("System handled all tested load levels successfully")

    async def _short_load_test(self, concurrent_users: int):
        """Run a short load test for breaking point detection"""
        requests_per_user = 10
        response_times = []
        successful_requests = 0
        failed_requests = 0
        start_time = time.time()

        async def user_test(user_id: int):
            connector = aiohttp.TCPConnector(limit=5)
            timeout = aiohttp.ClientTimeout(total=10)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                for _ in range(requests_per_user):
                    try:
                        request_start = time.time()
                        async with session.get(f"{self.manager_url}/healthz") as response:
                            request_end = time.time()
                            response_time = request_end - request_start
                            response_times.append(response_time)

                            if response.status == 200:
                                nonlocal successful_requests
                                successful_requests += 1
                            else:
                                nonlocal failed_requests
                                failed_requests += 1
                    except Exception:
                        nonlocal failed_requests
                        failed_requests += 1

        tasks = [user_test(i) for i in range(concurrent_users)]
        await asyncio.gather(*tasks, return_exceptions=True)

        end_time = time.time()
        duration = end_time - start_time
        total_requests = concurrent_users * requests_per_user

        # Calculate basic statistics
        avg_response_time = statistics.mean(response_times) if response_times else 0
        error_rate = (failed_requests / total_requests) * 100 if total_requests > 0 else 0

        result = LoadTestResult(
            test_name=f"Stress Test - {concurrent_users} users",
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            duration_seconds=duration,
            requests_per_second=total_requests / duration if duration > 0 else 0,
            average_response_time=avg_response_time,
            median_response_time=0,
            p95_response_time=0,
            p99_response_time=0,
            min_response_time=0,
            max_response_time=0,
            error_rate=error_rate
        )

        self.results.append(result)

    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile of data"""
        if not data:
            return 0
        sorted_data = sorted(data)
        index = int((percentile / 100) * len(sorted_data))
        if index >= len(sorted_data):
            index = len(sorted_data) - 1
        return sorted_data[index]

    def _print_result(self, result: LoadTestResult):
        """Print formatted test result"""
        print(f"\n{result.test_name} Results:")
        print(f"  Total Requests: {result.total_requests:,}")
        print(f"  Successful: {result.successful_requests:,}")
        print(f"  Failed: {result.failed_requests:,}")
        print(f"  Duration: {result.duration_seconds:.2f} seconds")
        print(f"  Requests/Second: {result.requests_per_second:.2f}")
        print(f"  Error Rate: {result.error_rate:.2f}%")
        print(f"  Response Times:")
        print(f"    Average: {result.average_response_time:.3f}s")
        print(f"    Median: {result.median_response_time:.3f}s")
        print(f"    95th percentile: {result.p95_response_time:.3f}s")
        print(f"    99th percentile: {result.p99_response_time:.3f}s")
        print(f"    Min: {result.min_response_time:.3f}s")
        print(f"    Max: {result.max_response_time:.3f}s")

    def generate_report(self, output_file: str = "load_test_report.html"):
        """Generate HTML report with charts"""
        try:
            # Create performance charts
            self._create_charts()

            # Generate HTML report
            html_content = self._generate_html_report()

            with open(output_file, 'w') as f:
                f.write(html_content)

            print(f"Load test report generated: {output_file}")
        except Exception as e:
            print(f"Error generating report: {e}")

    def _create_charts(self):
        """Create performance charts"""
        if not self.results:
            return

        # Requests per second chart
        test_names = [r.test_name for r in self.results]
        rps_values = [r.requests_per_second for r in self.results]

        plt.figure(figsize=(12, 8))

        plt.subplot(2, 2, 1)
        plt.bar(range(len(test_names)), rps_values)
        plt.title('Requests per Second')
        plt.ylabel('RPS')
        plt.xticks(range(len(test_names)), [name[:20] for name in test_names], rotation=45)

        # Response time chart
        plt.subplot(2, 2, 2)
        avg_times = [r.average_response_time for r in self.results]
        p95_times = [r.p95_response_time for r in self.results]

        x = range(len(test_names))
        plt.bar(x, avg_times, alpha=0.7, label='Average')
        plt.bar(x, p95_times, alpha=0.7, label='95th percentile')
        plt.title('Response Times')
        plt.ylabel('Time (seconds)')
        plt.legend()
        plt.xticks(x, [name[:20] for name in test_names], rotation=45)

        # Error rate chart
        plt.subplot(2, 2, 3)
        error_rates = [r.error_rate for r in self.results]
        plt.bar(range(len(test_names)), error_rates)
        plt.title('Error Rates')
        plt.ylabel('Error Rate (%)')
        plt.xticks(range(len(test_names)), [name[:20] for name in test_names], rotation=45)

        # Success rate chart
        plt.subplot(2, 2, 4)
        success_rates = [100 - r.error_rate for r in self.results]
        plt.bar(range(len(test_names)), success_rates)
        plt.title('Success Rates')
        plt.ylabel('Success Rate (%)')
        plt.xticks(range(len(test_names)), [name[:20] for name in test_names], rotation=45)

        plt.tight_layout()
        plt.savefig('load_test_charts.png', dpi=300, bbox_inches='tight')
        plt.close()

    def _generate_html_report(self) -> str:
        """Generate HTML report content"""
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>MarchProxy Load Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { text-align: center; color: #333; }
        .summary { background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 5px; }
        .test-result { margin: 30px 0; border: 1px solid #ddd; padding: 20px; border-radius: 5px; }
        .metric { display: inline-block; margin: 10px 20px; }
        .metric-value { font-size: 1.5em; font-weight: bold; color: #2196F3; }
        .metric-label { color: #666; }
        .chart { text-align: center; margin: 30px 0; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f5f5f5; }
        .success { color: #4CAF50; }
        .warning { color: #FF9800; }
        .error { color: #F44336; }
    </style>
</head>
<body>
    <div class="header">
        <h1>MarchProxy Load Test Report</h1>
        <p>Generated on: """ + time.strftime("%Y-%m-%d %H:%M:%S") + """</p>
    </div>

    <div class="summary">
        <h2>Test Summary</h2>
        <div class="metric">
            <div class="metric-value">""" + str(len(self.results)) + """</div>
            <div class="metric-label">Tests Executed</div>
        </div>
        <div class="metric">
            <div class="metric-value">""" + str(sum(r.total_requests for r in self.results)) + """</div>
            <div class="metric-label">Total Requests</div>
        </div>
        <div class="metric">
            <div class="metric-value">""" + f"{sum(r.successful_requests for r in self.results) / sum(r.total_requests for r in self.results) * 100:.1f}%" + """</div>
            <div class="metric-label">Overall Success Rate</div>
        </div>
    </div>

    <div class="chart">
        <h2>Performance Charts</h2>
        <img src="load_test_charts.png" alt="Performance Charts" style="max-width: 100%;">
    </div>

    <h2>Detailed Results</h2>
    <table>
        <tr>
            <th>Test Name</th>
            <th>Total Requests</th>
            <th>Success Rate</th>
            <th>RPS</th>
            <th>Avg Response Time</th>
            <th>95th Percentile</th>
        </tr>"""

        for result in self.results:
            success_rate = 100 - result.error_rate
            success_class = "success" if success_rate > 95 else "warning" if success_rate > 90 else "error"

            html += f"""
        <tr>
            <td>{result.test_name}</td>
            <td>{result.total_requests:,}</td>
            <td class="{success_class}">{success_rate:.1f}%</td>
            <td>{result.requests_per_second:.1f}</td>
            <td>{result.average_response_time:.3f}s</td>
            <td>{result.p95_response_time:.3f}s</td>
        </tr>"""

        html += """
    </table>
</body>
</html>"""
        return html

async def main():
    """Main function to run load tests"""
    parser = argparse.ArgumentParser(description='MarchProxy Load Testing')
    parser.add_argument('--manager-url', default='http://localhost:8000', help='Manager URL')
    parser.add_argument('--proxy-url', default='tcp://localhost:8080', help='Proxy URL')
    parser.add_argument('--api-key', default='test-cluster-api-key', help='Cluster API key')
    parser.add_argument('--test', choices=['api', 'proxy', 'config', 'stress', 'memory', 'all'],
                       default='all', help='Test type to run')
    parser.add_argument('--users', type=int, default=100, help='Concurrent users')
    parser.add_argument('--requests', type=int, default=100, help='Requests per user')
    parser.add_argument('--duration', type=int, default=60, help='Test duration in seconds')

    args = parser.parse_args()

    tester = MarchProxyLoadTester(args.manager_url, args.proxy_url, args.api_key)

    print("Starting MarchProxy Load Tests...")
    print(f"Manager URL: {args.manager_url}")
    print(f"Proxy URL: {args.proxy_url}")
    print("=" * 60)

    try:
        if args.test in ['api', 'all']:
            await tester.test_manager_api_load(args.users, args.requests)

        if args.test in ['proxy', 'all']:
            tester.test_tcp_proxy_load(args.users, 1024)

        if args.test in ['config', 'all']:
            await tester.test_configuration_load(50, args.duration)

        if args.test in ['stress', 'all']:
            tester.test_stress_breaking_point()

        if args.test in ['memory', 'all']:
            tester.test_memory_leak_detection(30)

        # Generate report
        tester.generate_report()

        print("\n" + "=" * 60)
        print("Load testing completed successfully!")

    except Exception as e:
        print(f"Load testing failed: {e}")
        return 1

    return 0

if __name__ == '__main__':
    exit_code = asyncio.run(main())
    exit(exit_code)