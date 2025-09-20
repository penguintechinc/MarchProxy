"""
Configuration management for MarchProxy Manager.
Priority: Control Panel DB Settings > Environment Variables > Defaults
"""

import os
import json
from typing import Dict, Any, Optional
from pydal import DAL, Field

class ConfigManager:
    """Manages configuration with fallback hierarchy: DB > ENV > Defaults"""

    def __init__(self, db: DAL):
        self.db = db
        self._ensure_config_table()
        self._config_cache = {}
        self._cache_ttl = 300  # 5 minutes
        self._last_cache_update = 0

    def _ensure_config_table(self):
        """Ensure configuration table exists"""
        self.db.define_table(
            'system_config',
            Field('key', 'string', length=255, unique=True, notnull=True),
            Field('value', 'text'),
            Field('category', 'string', length=100, default='general'),
            Field('description', 'text'),
            Field('is_secret', 'boolean', default=False),
            Field('created_on', 'datetime', default=self.db.common_filter),
            Field('modified_on', 'datetime', update=self.db.common_filter),
            migrate=True
        )
        self.db.commit()

    def get_config(self, key: str, default: Any = None, category: str = None) -> Any:
        """Get configuration value with fallback hierarchy"""
        import time

        # Check cache first
        current_time = time.time()
        if (current_time - self._last_cache_update) < self._cache_ttl and key in self._config_cache:
            return self._config_cache[key]

        # Try database first
        try:
            query = self.db.system_config.key == key
            if category:
                query &= self.db.system_config.category == category

            config_row = self.db(query).select().first()
            if config_row and config_row.value:
                try:
                    # Try to parse as JSON for complex values
                    value = json.loads(config_row.value)
                except (json.JSONDecodeError, TypeError):
                    # Use as string if not JSON
                    value = config_row.value

                self._config_cache[key] = value
                return value
        except Exception as e:
            print(f"Error reading config from DB: {e}")

        # Fall back to environment variable
        env_value = os.getenv(key.upper(), default)
        if env_value is not None:
            self._config_cache[key] = env_value
            return env_value

        # Return default
        self._config_cache[key] = default
        return default

    def set_config(self, key: str, value: Any, category: str = 'general',
                  description: str = '', is_secret: bool = False) -> bool:
        """Set configuration value in database"""
        try:
            # Convert complex values to JSON
            if isinstance(value, (dict, list)):
                value_str = json.dumps(value)
            else:
                value_str = str(value) if value is not None else ''

            # Update or insert
            existing = self.db(self.db.system_config.key == key).select().first()
            if existing:
                existing.update_record(
                    value=value_str,
                    category=category,
                    description=description,
                    is_secret=is_secret
                )
            else:
                self.db.system_config.insert(
                    key=key,
                    value=value_str,
                    category=category,
                    description=description,
                    is_secret=is_secret
                )

            self.db.commit()

            # Update cache
            self._config_cache[key] = value

            return True
        except Exception as e:
            print(f"Error setting config: {e}")
            return False

    def get_database_config(self) -> Dict[str, Any]:
        """Get database configuration with fallbacks"""
        return {
            'host': self.get_config('db_host', os.getenv('DB_HOST', 'postgres'), 'database'),
            'port': int(self.get_config('db_port', os.getenv('DB_PORT', 5432), 'database')),
            'database': self.get_config('db_name', os.getenv('DB_NAME', 'marchproxy'), 'database'),
            'username': self.get_config('db_username', os.getenv('DB_USERNAME', 'marchproxy'), 'database'),
            'password': self.get_config('db_password', os.getenv('DB_PASSWORD', 'marchproxy123'), 'database'),
            'ssl_mode': self.get_config('db_ssl_mode', os.getenv('DB_SSL_MODE', 'prefer'), 'database'),
            'pool_size': int(self.get_config('db_pool_size', os.getenv('DB_POOL_SIZE', 20), 'database')),
            'max_overflow': int(self.get_config('db_max_overflow', os.getenv('DB_MAX_OVERFLOW', 10), 'database')),
        }

    def get_smtp_config(self) -> Dict[str, Any]:
        """Get SMTP configuration with fallbacks"""
        return {
            'host': self.get_config('smtp_host', os.getenv('SMTP_HOST', 'localhost'), 'smtp'),
            'port': int(self.get_config('smtp_port', os.getenv('SMTP_PORT', 587), 'smtp')),
            'username': self.get_config('smtp_username', os.getenv('SMTP_USERNAME', ''), 'smtp'),
            'password': self.get_config('smtp_password', os.getenv('SMTP_PASSWORD', ''), 'smtp'),
            'from_address': self.get_config('smtp_from', os.getenv('SMTP_FROM', 'marchproxy@company.com'), 'smtp'),
            'use_tls': bool(self.get_config('smtp_use_tls', os.getenv('SMTP_USE_TLS', 'true').lower() == 'true', 'smtp')),
            'use_ssl': bool(self.get_config('smtp_use_ssl', os.getenv('SMTP_USE_SSL', 'false').lower() == 'true', 'smtp')),
        }

    def get_syslog_config(self) -> Dict[str, Any]:
        """Get syslog configuration with fallbacks"""
        return {
            'enabled': bool(self.get_config('syslog_enabled', os.getenv('SYSLOG_ENABLED', 'true').lower() == 'true', 'syslog')),
            'host': self.get_config('syslog_host', os.getenv('SYSLOG_HOST', 'localhost'), 'syslog'),
            'port': int(self.get_config('syslog_port', os.getenv('SYSLOG_PORT', 514), 'syslog')),
            'protocol': self.get_config('syslog_protocol', os.getenv('SYSLOG_PROTOCOL', 'udp'), 'syslog'),
            'facility': self.get_config('syslog_facility', os.getenv('SYSLOG_FACILITY', 'local0'), 'syslog'),
            'tag': self.get_config('syslog_tag', os.getenv('SYSLOG_TAG', 'marchproxy'), 'syslog'),
        }

    def get_monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring configuration for external services"""
        smtp = self.get_smtp_config()

        return {
            'smtp': smtp,
            'alerts': {
                'default_email': self.get_config('alert_email_default', os.getenv('ALERT_EMAIL_DEFAULT', 'ops-team@company.com'), 'monitoring'),
                'critical_email': self.get_config('alert_email_critical', os.getenv('ALERT_EMAIL_CRITICAL', 'critical-alerts@company.com'), 'monitoring'),
                'license_email': self.get_config('alert_email_license', os.getenv('ALERT_EMAIL_LICENSE', 'license-admin@company.com'), 'monitoring'),
                'performance_email': self.get_config('alert_email_performance', os.getenv('ALERT_EMAIL_PERFORMANCE', 'performance-team@company.com'), 'monitoring'),
                'security_email': self.get_config('alert_email_security', os.getenv('ALERT_EMAIL_SECURITY', 'security-team@company.com'), 'monitoring'),
                'slack_webhook': self.get_config('slack_webhook_url', os.getenv('SLACK_WEBHOOK_URL', ''), 'monitoring'),
                'pagerduty_url': self.get_config('pagerduty_url', os.getenv('PAGERDUTY_URL', ''), 'monitoring'),
            },
            'retention': {
                'metrics_days': int(self.get_config('metrics_retention_days', os.getenv('METRICS_RETENTION_DAYS', 30), 'monitoring')),
                'logs_days': int(self.get_config('logs_retention_days', os.getenv('LOGS_RETENTION_DAYS', 7), 'monitoring')),
                'traces_days': int(self.get_config('traces_retention_days', os.getenv('TRACES_RETENTION_DAYS', 3), 'monitoring')),
            }
        }

    def get_redis_config(self) -> Dict[str, Any]:
        """Get Redis configuration with fallbacks"""
        return {
            'host': self.get_config('redis_host', os.getenv('REDIS_HOST', 'redis'), 'redis'),
            'port': int(self.get_config('redis_port', os.getenv('REDIS_PORT', 6379), 'redis')),
            'password': self.get_config('redis_password', os.getenv('REDIS_PASSWORD', ''), 'redis'),
            'database': int(self.get_config('redis_database', os.getenv('REDIS_DATABASE', 0), 'redis')),
            'ssl': bool(self.get_config('redis_ssl', os.getenv('REDIS_SSL', 'false').lower() == 'true', 'redis')),
            'pool_size': int(self.get_config('redis_pool_size', os.getenv('REDIS_POOL_SIZE', 10), 'redis')),
        }

    def get_license_config(self) -> Dict[str, Any]:
        """Get license configuration"""
        return {
            'key': self.get_config('license_key', os.getenv('LICENSE_KEY', ''), 'license'),
            'server_url': self.get_config('license_server_url', os.getenv('LICENSE_SERVER_URL', 'https://license.penguintech.io'), 'license'),
            'check_interval_hours': int(self.get_config('license_check_interval', os.getenv('LICENSE_CHECK_INTERVAL', 24), 'license')),
            'offline_grace_days': int(self.get_config('license_offline_grace', os.getenv('LICENSE_OFFLINE_GRACE', 7), 'license')),
        }

    def initialize_default_config(self):
        """Initialize default configuration values if not present"""
        defaults = [
            # Database
            ('db_host', os.getenv('DB_HOST', 'postgres'), 'database', 'Database hostname'),
            ('db_port', os.getenv('DB_PORT', 5432), 'database', 'Database port'),
            ('db_name', os.getenv('DB_NAME', 'marchproxy'), 'database', 'Database name'),
            ('db_username', os.getenv('DB_USERNAME', 'marchproxy'), 'database', 'Database username'),
            ('db_password', os.getenv('DB_PASSWORD', 'marchproxy123'), 'database', 'Database password', True),

            # SMTP
            ('smtp_host', os.getenv('SMTP_HOST', 'localhost'), 'smtp', 'SMTP server hostname'),
            ('smtp_port', os.getenv('SMTP_PORT', 587), 'smtp', 'SMTP server port'),
            ('smtp_username', os.getenv('SMTP_USERNAME', ''), 'smtp', 'SMTP username'),
            ('smtp_password', os.getenv('SMTP_PASSWORD', ''), 'smtp', 'SMTP password', True),
            ('smtp_from', os.getenv('SMTP_FROM', 'marchproxy@company.com'), 'smtp', 'Default from address'),

            # Syslog
            ('syslog_enabled', os.getenv('SYSLOG_ENABLED', 'true'), 'syslog', 'Enable syslog forwarding'),
            ('syslog_host', os.getenv('SYSLOG_HOST', 'localhost'), 'syslog', 'Syslog server hostname'),
            ('syslog_port', os.getenv('SYSLOG_PORT', 514), 'syslog', 'Syslog server port'),

            # Monitoring
            ('alert_email_default', os.getenv('ALERT_EMAIL_DEFAULT', 'ops-team@company.com'), 'monitoring', 'Default alert email'),
            ('metrics_retention_days', os.getenv('METRICS_RETENTION_DAYS', 30), 'monitoring', 'Metrics retention period'),

            # License
            ('license_key', os.getenv('LICENSE_KEY', ''), 'license', 'Enterprise license key', True),
        ]

        for config_item in defaults:
            key = config_item[0]
            value = config_item[1]
            category = config_item[2]
            description = config_item[3]
            is_secret = len(config_item) > 4 and config_item[4]

            # Only set if not already exists
            existing = self.db(self.db.system_config.key == key).select().first()
            if not existing:
                self.set_config(key, value, category, description, is_secret)

    def get_all_config(self, category: Optional[str] = None, include_secrets: bool = False) -> Dict[str, Any]:
        """Get all configuration values for management interface"""
        query = self.db.system_config.id > 0
        if category:
            query &= self.db.system_config.category == category
        if not include_secrets:
            query &= self.db.system_config.is_secret == False

        configs = {}
        for row in self.db(query).select():
            try:
                # Try to parse as JSON
                value = json.loads(row.value)
            except (json.JSONDecodeError, TypeError):
                value = row.value

            configs[row.key] = {
                'value': value,
                'category': row.category,
                'description': row.description,
                'is_secret': row.is_secret
            }

        return configs

    def clear_cache(self):
        """Clear configuration cache"""
        self._config_cache = {}
        self._last_cache_update = 0


# Global config manager instance
_config_manager = None

def get_config_manager(db: DAL = None) -> ConfigManager:
    """Get global configuration manager instance"""
    global _config_manager
    if _config_manager is None and db:
        _config_manager = ConfigManager(db)
        _config_manager.initialize_default_config()
    return _config_manager

def get_config(key: str, default: Any = None, category: str = None) -> Any:
    """Convenience function to get configuration value"""
    if _config_manager:
        return _config_manager.get_config(key, default, category)
    # Fallback to environment if no config manager
    return os.getenv(key.upper(), default)