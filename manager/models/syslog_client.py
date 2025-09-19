"""
UDP Syslog client implementation for MarchProxy Manager

Copyright (C) 2025 MarchProxy Contributors
Licensed under GNU Affero General Public License v3.0
"""

import socket
import json
import time
import threading
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import IntEnum
import logging

logger = logging.getLogger(__name__)


class SyslogSeverity(IntEnum):
    """Syslog severity levels (RFC 3164)"""
    EMERGENCY = 0    # System is unusable
    ALERT = 1        # Action must be taken immediately
    CRITICAL = 2     # Critical conditions
    ERROR = 3        # Error conditions
    WARNING = 4      # Warning conditions
    NOTICE = 5       # Normal but significant condition
    INFO = 6         # Informational messages
    DEBUG = 7        # Debug-level messages


class SyslogFacility(IntEnum):
    """Syslog facility codes (RFC 3164)"""
    KERNEL = 0       # Kernel messages
    USER = 1         # User-level messages
    MAIL = 2         # Mail system
    DAEMON = 3       # System daemons
    AUTH = 4         # Security/authorization messages
    SYSLOG = 5       # Messages generated internally by syslogd
    LPR = 6          # Line printer subsystem
    NEWS = 7         # Network news subsystem
    UUCP = 8         # UUCP subsystem
    CRON = 9         # Clock daemon
    AUTHPRIV = 10    # Security/authorization messages
    FTP = 11         # FTP daemon
    LOCAL0 = 16      # Local use facility 0
    LOCAL1 = 17      # Local use facility 1
    LOCAL2 = 18      # Local use facility 2
    LOCAL3 = 19      # Local use facility 3
    LOCAL4 = 20      # Local use facility 4
    LOCAL5 = 21      # Local use facility 5
    LOCAL6 = 22      # Local use facility 6
    LOCAL7 = 23      # Local use facility 7


class SyslogClient:
    """UDP Syslog client for centralized logging"""

    def __init__(self, host: str, port: int = 514, facility: SyslogFacility = SyslogFacility.LOCAL0,
                 hostname: str = None, app_name: str = "marchproxy-manager"):
        self.host = host
        self.port = port
        self.facility = facility
        self.hostname = hostname or socket.gethostname()
        self.app_name = app_name
        self.socket = None
        self.connected = False
        self._lock = threading.Lock()

    def connect(self) -> bool:
        """Connect to syslog server"""
        try:
            with self._lock:
                if self.socket:
                    self.socket.close()

                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # Test connection with a small packet
                test_message = self._format_message(SyslogSeverity.INFO, "Syslog connection established")
                self.socket.sendto(test_message.encode('utf-8'), (self.host, self.port))
                self.connected = True
                logger.info(f"Connected to syslog server {self.host}:{self.port}")
                return True

        except Exception as e:
            logger.error(f"Failed to connect to syslog server {self.host}:{self.port}: {e}")
            self.connected = False
            return False

    def disconnect(self):
        """Disconnect from syslog server"""
        with self._lock:
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
                self.socket = None
            self.connected = False

    def _format_message(self, severity: SyslogSeverity, message: str, structured_data: Dict[str, Any] = None) -> str:
        """Format syslog message according to RFC 3164/5424"""
        # Calculate priority
        priority = (self.facility << 3) | severity

        # Format timestamp (RFC 3339)
        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        # Format structured data if provided
        structured_part = ""
        if structured_data:
            sd_elements = []
            for key, value in structured_data.items():
                if isinstance(value, dict):
                    # Format as structured data element
                    params = []
                    for k, v in value.items():
                        # Escape special characters
                        escaped_value = str(v).replace('\\', '\\\\').replace('"', '\\"').replace(']', '\\]')
                        params.append(f'{k}="{escaped_value}"')
                    sd_elements.append(f'[{key} {" ".join(params)}]')
                else:
                    # Simple key-value pair
                    escaped_value = str(value).replace('\\', '\\\\').replace('"', '\\"').replace(']', '\\]')
                    sd_elements.append(f'[{key} value="{escaped_value}"]')

            structured_part = ''.join(sd_elements) if sd_elements else '-'
        else:
            structured_part = '-'

        # Format final message (RFC 5424 format)
        return f"<{priority}>1 {timestamp} {self.hostname} {self.app_name} - - {structured_part} {message}"

    def log(self, severity: SyslogSeverity, message: str, structured_data: Dict[str, Any] = None) -> bool:
        """Send log message to syslog server"""
        if not self.connected:
            if not self.connect():
                return False

        try:
            formatted_message = self._format_message(severity, message, structured_data)
            with self._lock:
                if self.socket:
                    self.socket.sendto(formatted_message.encode('utf-8'), (self.host, self.port))
                    return True
        except Exception as e:
            logger.error(f"Failed to send syslog message: {e}")
            self.connected = False

        return False

    def info(self, message: str, **kwargs):
        """Log info message"""
        return self.log(SyslogSeverity.INFO, message, kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message"""
        return self.log(SyslogSeverity.WARNING, message, kwargs)

    def error(self, message: str, **kwargs):
        """Log error message"""
        return self.log(SyslogSeverity.ERROR, message, kwargs)

    def debug(self, message: str, **kwargs):
        """Log debug message"""
        return self.log(SyslogSeverity.DEBUG, message, kwargs)

    def critical(self, message: str, **kwargs):
        """Log critical message"""
        return self.log(SyslogSeverity.CRITICAL, message, kwargs)


class ClusterSyslogManager:
    """Manage syslog clients for multiple clusters"""

    def __init__(self, db):
        self.db = db
        self.clients = {}  # cluster_id -> SyslogClient
        self._lock = threading.Lock()

    def get_client(self, cluster_id: int) -> Optional[SyslogClient]:
        """Get or create syslog client for cluster"""
        with self._lock:
            if cluster_id in self.clients:
                return self.clients[cluster_id]

            # Get cluster configuration
            cluster = self.db.clusters[cluster_id]
            if not cluster or not cluster.syslog_endpoint:
                return None

            try:
                # Parse syslog endpoint (format: host:port)
                if ':' in cluster.syslog_endpoint:
                    host, port_str = cluster.syslog_endpoint.rsplit(':', 1)
                    port = int(port_str)
                else:
                    host = cluster.syslog_endpoint
                    port = 514

                # Create client
                client = SyslogClient(
                    host=host,
                    port=port,
                    facility=SyslogFacility.LOCAL0,
                    app_name=f"marchproxy-cluster-{cluster_id}"
                )

                if client.connect():
                    self.clients[cluster_id] = client
                    return client

            except Exception as e:
                logger.error(f"Failed to create syslog client for cluster {cluster_id}: {e}")

        return None

    def log_auth_event(self, cluster_id: int, event_type: str, user_id: int = None,
                      ip_address: str = None, success: bool = True, details: Dict[str, Any] = None):
        """Log authentication event"""
        client = self.get_client(cluster_id)
        if not client:
            return

        # Get cluster logging configuration
        cluster = self.db.clusters[cluster_id]
        if not cluster or not cluster.log_auth:
            return

        severity = SyslogSeverity.INFO if success else SyslogSeverity.WARNING

        structured_data = {
            'auth': {
                'event_type': event_type,
                'success': success,
                'cluster_id': cluster_id,
                'timestamp': datetime.utcnow().isoformat()
            }
        }

        if user_id:
            structured_data['auth']['user_id'] = user_id
        if ip_address:
            structured_data['auth']['ip_address'] = ip_address
        if details:
            structured_data['auth'].update(details)

        message = f"Authentication event: {event_type} {'succeeded' if success else 'failed'}"
        client.log(severity, message, structured_data)

    def log_netflow_event(self, cluster_id: int, source_ip: str, dest_ip: str,
                         source_port: int, dest_port: int, protocol: str,
                         bytes_transferred: int = 0, details: Dict[str, Any] = None):
        """Log network flow event"""
        client = self.get_client(cluster_id)
        if not client:
            return

        # Get cluster logging configuration
        cluster = self.db.clusters[cluster_id]
        if not cluster or not cluster.log_netflow:
            return

        structured_data = {
            'netflow': {
                'source_ip': source_ip,
                'dest_ip': dest_ip,
                'source_port': source_port,
                'dest_port': dest_port,
                'protocol': protocol,
                'bytes_transferred': bytes_transferred,
                'cluster_id': cluster_id,
                'timestamp': datetime.utcnow().isoformat()
            }
        }

        if details:
            structured_data['netflow'].update(details)

        message = f"Network flow: {source_ip}:{source_port} -> {dest_ip}:{dest_port} ({protocol})"
        client.log(SyslogSeverity.INFO, message, structured_data)

    def log_debug_event(self, cluster_id: int, component: str, message: str,
                       details: Dict[str, Any] = None):
        """Log debug event"""
        client = self.get_client(cluster_id)
        if not client:
            return

        # Get cluster logging configuration
        cluster = self.db.clusters[cluster_id]
        if not cluster or not cluster.log_debug:
            return

        structured_data = {
            'debug': {
                'component': component,
                'cluster_id': cluster_id,
                'timestamp': datetime.utcnow().isoformat()
            }
        }

        if details:
            structured_data['debug'].update(details)

        client.log(SyslogSeverity.DEBUG, f"[{component}] {message}", structured_data)

    def refresh_clients(self):
        """Refresh all syslog clients (call when cluster config changes)"""
        with self._lock:
            # Disconnect all clients
            for client in self.clients.values():
                client.disconnect()
            self.clients.clear()

    def disconnect_all(self):
        """Disconnect all syslog clients"""
        with self._lock:
            for client in self.clients.values():
                client.disconnect()
            self.clients.clear()


# Authentication event logging decorator
def log_auth_event(cluster_id: int, event_type: str):
    """Decorator to log authentication events"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            from py4web import request

            # Get syslog manager from globals
            syslog_manager = globals().get('syslog_manager')
            if not syslog_manager:
                return func(*args, **kwargs)

            # Get client info
            ip_address = request.environ.get('REMOTE_ADDR', 'unknown')
            user_id = None

            try:
                result = func(*args, **kwargs)

                # Determine success based on result
                success = True
                if isinstance(result, dict) and 'error' in result:
                    success = False

                # Try to get user ID from result or request
                if hasattr(request, 'user') and request.user:
                    user_id = request.user.get('id')

                # Log the event
                syslog_manager.log_auth_event(
                    cluster_id=cluster_id,
                    event_type=event_type,
                    user_id=user_id,
                    ip_address=ip_address,
                    success=success
                )

                return result

            except Exception as e:
                # Log failed event
                syslog_manager.log_auth_event(
                    cluster_id=cluster_id,
                    event_type=event_type,
                    user_id=user_id,
                    ip_address=ip_address,
                    success=False,
                    details={'error': str(e)}
                )
                raise

        return wrapper
    return decorator