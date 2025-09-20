#!/usr/bin/env python3
"""
Configuration synchronization service for MarchProxy monitoring.
Pulls configuration from the manager and updates monitoring service configs.
"""

import os
import json
import time
import requests
import logging
import yaml
from pathlib import Path
from typing import Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ConfigSync:
    def __init__(self):
        self.manager_url = os.getenv('MANAGER_URL', 'http://manager:8000')
        self.cluster_api_key = os.getenv('CLUSTER_API_KEY', 'default-api-key')
        self.sync_interval = int(os.getenv('SYNC_INTERVAL', '300'))  # 5 minutes
        self.config_dir = Path('/etc/monitoring')

        # Ensure config directory exists
        self.config_dir.mkdir(parents=True, exist_ok=True)

    def get_manager_config(self) -> Dict[str, Any]:
        """Fetch monitoring configuration from manager."""
        try:
            headers = {
                'Authorization': f'Bearer {self.cluster_api_key}',
                'Content-Type': 'application/json'
            }

            response = requests.get(
                f'{self.manager_url}/api/v1/monitoring/config',
                headers=headers,
                timeout=30
            )
            response.raise_for_status()

            return response.json()

        except Exception as e:
            logger.error(f"Failed to fetch manager config: {e}")
            return {}

    def update_alertmanager_config(self, config: Dict[str, Any]):
        """Update AlertManager configuration with manager settings."""
        try:
            monitoring_config = config.get('monitoring', {})
            smtp_config = monitoring_config.get('smtp', {})
            alerts_config = monitoring_config.get('alerts', {})

            # Update environment variables for AlertManager
            env_vars = {
                'SMTP_HOST': smtp_config.get('host', 'localhost'),
                'SMTP_PORT': str(smtp_config.get('port', 587)),
                'SMTP_FROM': smtp_config.get('from', 'marchproxy-alerts@company.com'),
                'SMTP_USERNAME': smtp_config.get('username', ''),
                'SMTP_PASSWORD': smtp_config.get('password', ''),

                'ALERT_EMAIL_DEFAULT': alerts_config.get('default_email', 'ops-team@company.com'),
                'ALERT_EMAIL_CRITICAL': alerts_config.get('critical_email', 'critical-alerts@company.com'),
                'ALERT_EMAIL_LICENSE': alerts_config.get('license_email', 'license-admin@company.com'),
                'ALERT_EMAIL_PERFORMANCE': alerts_config.get('performance_email', 'performance-team@company.com'),
                'ALERT_EMAIL_SECURITY': alerts_config.get('security_email', 'security-team@company.com'),

                'SLACK_WEBHOOK_URL': alerts_config.get('slack_webhook', ''),
                'PAGERDUTY_URL': alerts_config.get('pagerduty_url', ''),
            }

            # Write environment file for docker-compose
            env_file = self.config_dir / 'alertmanager.env'
            with open(env_file, 'w') as f:
                for key, value in env_vars.items():
                    f.write(f'{key}={value}\n')

            logger.info("Updated AlertManager configuration")

        except Exception as e:
            logger.error(f"Failed to update AlertManager config: {e}")

    def update_prometheus_targets(self, config: Dict[str, Any]):
        """Update Prometheus targets with registered proxies."""
        try:
            proxies = config.get('proxies', [])

            # Build target list for Prometheus
            proxy_targets = []
            for proxy in proxies:
                if proxy.get('status') == 'active':
                    target = f"{proxy.get('hostname', 'proxy')}:{proxy.get('metrics_port', 8081)}"
                    proxy_targets.append(target)

            # Update prometheus configuration
            prometheus_config = {
                'proxy_targets': proxy_targets,
                'manager_target': f"{config.get('manager', {}).get('hostname', 'manager')}:8000"
            }

            config_file = self.config_dir / 'prometheus_targets.json'
            with open(config_file, 'w') as f:
                json.dump(prometheus_config, f, indent=2)

            logger.info(f"Updated Prometheus targets: {len(proxy_targets)} proxies")

        except Exception as e:
            logger.error(f"Failed to update Prometheus targets: {e}")

    def update_grafana_datasources(self, config: Dict[str, Any]):
        """Update Grafana datasources configuration."""
        try:
            monitoring_config = config.get('monitoring', {})

            datasources = {
                'apiVersion': 1,
                'datasources': [
                    {
                        'name': 'Prometheus',
                        'type': 'prometheus',
                        'access': 'proxy',
                        'url': f"http://prometheus:9090",
                        'isDefault': True,
                        'editable': False
                    },
                    {
                        'name': 'Loki',
                        'type': 'loki',
                        'access': 'proxy',
                        'url': f"http://loki:3100",
                        'editable': False
                    }
                ]
            }

            # Add external datasources if configured
            external_datasources = monitoring_config.get('external_datasources', [])
            for ds in external_datasources:
                if ds.get('enabled'):
                    datasources['datasources'].append({
                        'name': ds.get('name'),
                        'type': ds.get('type'),
                        'access': 'proxy',
                        'url': ds.get('url'),
                        'basicAuth': ds.get('basic_auth', False),
                        'basicAuthUser': ds.get('username', ''),
                        'secureJsonData': {
                            'basicAuthPassword': ds.get('password', '')
                        } if ds.get('password') else {},
                        'editable': False
                    })

            config_file = self.config_dir / 'grafana_datasources.yaml'
            with open(config_file, 'w') as f:
                yaml.dump(datasources, f, default_flow_style=False)

            logger.info("Updated Grafana datasources")

        except Exception as e:
            logger.error(f"Failed to update Grafana datasources: {e}")

    def sync_configuration(self):
        """Main synchronization loop."""
        logger.info("Starting configuration sync")

        while True:
            try:
                config = self.get_manager_config()

                if config:
                    self.update_alertmanager_config(config)
                    self.update_prometheus_targets(config)
                    self.update_grafana_datasources(config)

                    # Write last sync timestamp
                    timestamp_file = self.config_dir / 'last_sync'
                    with open(timestamp_file, 'w') as f:
                        f.write(str(int(time.time())))

                    logger.info("Configuration sync completed successfully")
                else:
                    logger.warning("No configuration received from manager")

            except Exception as e:
                logger.error(f"Configuration sync failed: {e}")

            time.sleep(self.sync_interval)

if __name__ == '__main__':
    sync_service = ConfigSync()
    sync_service.sync_configuration()