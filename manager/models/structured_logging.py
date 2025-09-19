"""
Structured logging implementation for MarchProxy Manager

Copyright (C) 2025 MarchProxy Contributors
Licensed under GNU Affero General Public License v3.0
"""

import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, Any, Optional
from logging.handlers import RotatingFileHandler
import threading


class StructuredFormatter(logging.Formatter):
    """JSON structured logging formatter"""

    def __init__(self, service_name: str = "marchproxy-manager", version: str = "1.0.0"):
        super().__init__()
        self.service_name = service_name
        self.version = version
        self.hostname = os.uname().nodename

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON"""
        log_entry = {
            '@timestamp': datetime.utcfromtimestamp(record.created).isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'service': {
                'name': self.service_name,
                'version': self.version
            },
            'host': {
                'hostname': self.hostname
            },
            'process': {
                'pid': os.getpid(),
                'thread': threading.current_thread().name
            }
        }

        # Add file/line info if available
        if record.pathname:
            log_entry['source'] = {
                'file': os.path.basename(record.pathname),
                'line': record.lineno,
                'function': record.funcName
            }

        # Add exception info if present
        if record.exc_info:
            log_entry['error'] = {
                'type': record.exc_info[0].__name__ if record.exc_info[0] else None,
                'message': str(record.exc_info[1]) if record.exc_info[1] else None,
                'stack_trace': self.formatException(record.exc_info)
            }

        # Add extra fields from record
        extra_fields = {}
        for key, value in record.__dict__.items():
            if key not in ('name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                          'filename', 'module', 'lineno', 'funcName', 'created',
                          'msecs', 'relativeCreated', 'thread', 'threadName',
                          'processName', 'process', 'getMessage', 'exc_info',
                          'exc_text', 'stack_info'):
                extra_fields[key] = value

        if extra_fields:
            log_entry['extra'] = extra_fields

        return json.dumps(log_entry, default=str, separators=(',', ':'))


class MarchProxyLogger:
    """Enhanced logger for MarchProxy with structured logging"""

    def __init__(self, service_name: str = "marchproxy-manager"):
        self.service_name = service_name
        self.loggers = {}
        self._setup_root_logger()

    def _setup_root_logger(self):
        """Setup root logger configuration"""
        # Get log level from environment
        log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
        log_format = os.environ.get('LOG_FORMAT', 'structured')  # 'structured' or 'simple'

        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, log_level, logging.INFO))

        # Clear existing handlers
        root_logger.handlers.clear()

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)

        if log_format == 'structured':
            console_handler.setFormatter(StructuredFormatter(self.service_name))
        else:
            console_handler.setFormatter(
                logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            )

        root_logger.addHandler(console_handler)

        # File handler (if log file specified)
        log_file = os.environ.get('LOG_FILE')
        if log_file:
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=50*1024*1024,  # 50MB
                backupCount=5
            )

            if log_format == 'structured':
                file_handler.setFormatter(StructuredFormatter(self.service_name))
            else:
                file_handler.setFormatter(
                    logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
                )

            root_logger.addHandler(file_handler)

    def get_logger(self, name: str) -> logging.Logger:
        """Get or create logger with given name"""
        if name not in self.loggers:
            self.loggers[name] = logging.getLogger(name)
        return self.loggers[name]

    def log_auth_event(self, event_type: str, user_id: int = None, ip_address: str = None,
                      success: bool = True, cluster_id: int = None, details: Dict[str, Any] = None):
        """Log authentication event with structured data"""
        logger = self.get_logger('auth')

        extra = {
            'event_type': 'authentication',
            'auth_event': event_type,
            'success': success,
            'timestamp': datetime.utcnow().isoformat()
        }

        if user_id:
            extra['user_id'] = user_id
        if ip_address:
            extra['client_ip'] = ip_address
        if cluster_id:
            extra['cluster_id'] = cluster_id
        if details:
            extra.update(details)

        level = logging.INFO if success else logging.WARNING
        message = f"Authentication {event_type}: {'success' if success else 'failed'}"

        logger.log(level, message, extra=extra)

    def log_api_request(self, method: str, path: str, status_code: int, duration_ms: float,
                       user_id: int = None, ip_address: str = None, cluster_id: int = None):
        """Log API request with structured data"""
        logger = self.get_logger('api')

        extra = {
            'event_type': 'api_request',
            'http': {
                'method': method,
                'path': path,
                'status_code': status_code
            },
            'duration_ms': duration_ms,
            'timestamp': datetime.utcnow().isoformat()
        }

        if user_id:
            extra['user_id'] = user_id
        if ip_address:
            extra['client_ip'] = ip_address
        if cluster_id:
            extra['cluster_id'] = cluster_id

        level = logging.INFO if status_code < 400 else logging.WARNING

        logger.log(level, f"{method} {path} - {status_code} ({duration_ms:.2f}ms)", extra=extra)

    def log_license_event(self, event_type: str, license_key: str = None, success: bool = True,
                         details: Dict[str, Any] = None):
        """Log license validation event"""
        logger = self.get_logger('license')

        extra = {
            'event_type': 'license',
            'license_event': event_type,
            'success': success,
            'timestamp': datetime.utcnow().isoformat()
        }

        if license_key:
            # Mask license key for security
            extra['license_key'] = f"{license_key[:8]}..." if len(license_key) > 8 else "***"
        if details:
            extra.update(details)

        level = logging.INFO if success else logging.ERROR

        logger.log(level, f"License {event_type}: {'success' if success else 'failed'}", extra=extra)

    def log_cluster_event(self, event_type: str, cluster_id: int, cluster_name: str = None,
                         user_id: int = None, success: bool = True, details: Dict[str, Any] = None):
        """Log cluster management event"""
        logger = self.get_logger('cluster')

        extra = {
            'event_type': 'cluster',
            'cluster_event': event_type,
            'cluster_id': cluster_id,
            'success': success,
            'timestamp': datetime.utcnow().isoformat()
        }

        if cluster_name:
            extra['cluster_name'] = cluster_name
        if user_id:
            extra['user_id'] = user_id
        if details:
            extra.update(details)

        level = logging.INFO if success else logging.ERROR

        logger.log(level, f"Cluster {event_type}: cluster {cluster_id}", extra=extra)

    def log_proxy_event(self, event_type: str, proxy_id: int = None, proxy_name: str = None,
                       cluster_id: int = None, success: bool = True, details: Dict[str, Any] = None):
        """Log proxy management event"""
        logger = self.get_logger('proxy')

        extra = {
            'event_type': 'proxy',
            'proxy_event': event_type,
            'success': success,
            'timestamp': datetime.utcnow().isoformat()
        }

        if proxy_id:
            extra['proxy_id'] = proxy_id
        if proxy_name:
            extra['proxy_name'] = proxy_name
        if cluster_id:
            extra['cluster_id'] = cluster_id
        if details:
            extra.update(details)

        level = logging.INFO if success else logging.WARNING

        logger.log(level, f"Proxy {event_type}: {proxy_name or proxy_id}", extra=extra)

    def log_certificate_event(self, event_type: str, cert_id: int, cert_name: str = None,
                             success: bool = True, details: Dict[str, Any] = None):
        """Log certificate management event"""
        logger = self.get_logger('certificate')

        extra = {
            'event_type': 'certificate',
            'cert_event': event_type,
            'cert_id': cert_id,
            'success': success,
            'timestamp': datetime.utcnow().isoformat()
        }

        if cert_name:
            extra['cert_name'] = cert_name
        if details:
            extra.update(details)

        level = logging.INFO if success else logging.ERROR

        logger.log(level, f"Certificate {event_type}: {cert_name or cert_id}", extra=extra)


# Global logger instance
structured_logger = MarchProxyLogger()


def get_structured_logger(name: str = None) -> logging.Logger:
    """Get structured logger instance"""
    if name:
        return structured_logger.get_logger(name)
    return structured_logger.get_logger('marchproxy')


# Decorator for logging API requests
def log_api_request():
    """Decorator to log API requests with timing"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            from py4web import request, response
            import time

            start_time = time.time()

            try:
                result = func(*args, **kwargs)

                # Calculate duration
                duration_ms = (time.time() - start_time) * 1000

                # Get client info
                ip_address = request.environ.get('REMOTE_ADDR', 'unknown')
                user_id = None
                if hasattr(request, 'user') and request.user:
                    user_id = request.user.get('id')

                # Log the request
                structured_logger.log_api_request(
                    method=request.method,
                    path=request.path,
                    status_code=response.status,
                    duration_ms=duration_ms,
                    user_id=user_id,
                    ip_address=ip_address
                )

                return result

            except Exception as e:
                # Log failed request
                duration_ms = (time.time() - start_time) * 1000
                ip_address = request.environ.get('REMOTE_ADDR', 'unknown')

                structured_logger.log_api_request(
                    method=request.method,
                    path=request.path,
                    status_code=500,
                    duration_ms=duration_ms,
                    ip_address=ip_address
                )
                raise

        return wrapper
    return decorator