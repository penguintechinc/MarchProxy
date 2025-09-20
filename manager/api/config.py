"""
Configuration API endpoints for MarchProxy Manager.
Provides configuration management with DB > ENV > Defaults fallback.
"""

from py4web import request, response, abort, HTTP
from ..apps.marchproxy.common import db, session, auth
from ..config.settings import get_config_manager
import json

def monitoring_config():
    """Get monitoring configuration for external services"""
    try:
        # Require authentication for config access
        if not session.get('user'):
            abort(401, "Authentication required")

        config_manager = get_config_manager(db)
        monitoring_config = config_manager.get_monitoring_config()

        # Add proxy information
        proxies = []
        for proxy in db(db.proxy_registration.status == 'active').select():
            proxies.append({
                'id': proxy.id,
                'hostname': proxy.hostname,
                'metrics_port': proxy.metrics_port or 8081,
                'cluster_id': proxy.cluster_id,
                'status': proxy.status
            })

        monitoring_config['proxies'] = proxies
        monitoring_config['manager'] = {
            'hostname': 'manager',
            'port': 8000
        }

        response.headers['Content-Type'] = 'application/json'
        return json.dumps(monitoring_config)

    except Exception as e:
        abort(500, f"Configuration error: {str(e)}")

def system_config():
    """Get/Set system configuration"""
    config_manager = get_config_manager(db)

    if request.method == 'GET':
        try:
            # Require authentication
            if not session.get('user'):
                abort(401, "Authentication required")

            category = request.params.get('category')
            include_secrets = request.params.get('include_secrets', 'false').lower() == 'true'

            # Only admins can view secrets
            if include_secrets and not session.get('user', {}).get('is_admin'):
                abort(403, "Admin access required")

            configs = config_manager.get_all_config(category, include_secrets)

            response.headers['Content-Type'] = 'application/json'
            return json.dumps(configs)

        except Exception as e:
            abort(500, f"Configuration error: {str(e)}")

    elif request.method == 'POST':
        try:
            # Require admin for config changes
            if not session.get('user', {}).get('is_admin'):
                abort(403, "Admin access required")

            data = request.json
            if not data:
                abort(400, "JSON data required")

            updated_configs = []
            for key, config_data in data.items():
                success = config_manager.set_config(
                    key=key,
                    value=config_data.get('value'),
                    category=config_data.get('category', 'general'),
                    description=config_data.get('description', ''),
                    is_secret=config_data.get('is_secret', False)
                )

                if success:
                    updated_configs.append(key)
                else:
                    abort(500, f"Failed to update config: {key}")

            # Clear cache after updates
            config_manager.clear_cache()

            response.headers['Content-Type'] = 'application/json'
            return json.dumps({
                'status': 'success',
                'updated': updated_configs,
                'count': len(updated_configs)
            })

        except Exception as e:
            abort(500, f"Configuration update error: {str(e)}")

    else:
        abort(405, "Method not allowed")

def database_config():
    """Get database configuration"""
    try:
        if not session.get('user'):
            abort(401, "Authentication required")

        config_manager = get_config_manager(db)
        db_config = config_manager.get_database_config()

        # Don't expose password in response
        db_config['password'] = '***' if db_config['password'] else ''

        response.headers['Content-Type'] = 'application/json'
        return json.dumps(db_config)

    except Exception as e:
        abort(500, f"Database configuration error: {str(e)}")

def smtp_config():
    """Get/Set SMTP configuration"""
    config_manager = get_config_manager(db)

    if request.method == 'GET':
        try:
            if not session.get('user'):
                abort(401, "Authentication required")

            smtp_config = config_manager.get_smtp_config()

            # Don't expose password in response
            smtp_config['password'] = '***' if smtp_config['password'] else ''

            response.headers['Content-Type'] = 'application/json'
            return json.dumps(smtp_config)

        except Exception as e:
            abort(500, f"SMTP configuration error: {str(e)}")

    elif request.method == 'POST':
        try:
            if not session.get('user', {}).get('is_admin'):
                abort(403, "Admin access required")

            data = request.json
            if not data:
                abort(400, "JSON data required")

            # Update SMTP configuration
            smtp_configs = [
                ('smtp_host', data.get('host')),
                ('smtp_port', data.get('port')),
                ('smtp_username', data.get('username')),
                ('smtp_from', data.get('from_address')),
                ('smtp_use_tls', data.get('use_tls')),
                ('smtp_use_ssl', data.get('use_ssl')),
            ]

            # Only update password if provided
            if data.get('password') and data.get('password') != '***':
                smtp_configs.append(('smtp_password', data.get('password')))

            for key, value in smtp_configs:
                if value is not None:
                    config_manager.set_config(key, value, 'smtp', is_secret=(key == 'smtp_password'))

            config_manager.clear_cache()

            response.headers['Content-Type'] = 'application/json'
            return json.dumps({'status': 'success', 'message': 'SMTP configuration updated'})

        except Exception as e:
            abort(500, f"SMTP configuration update error: {str(e)}")

def syslog_config():
    """Get/Set syslog configuration"""
    config_manager = get_config_manager(db)

    if request.method == 'GET':
        try:
            if not session.get('user'):
                abort(401, "Authentication required")

            syslog_config = config_manager.get_syslog_config()

            response.headers['Content-Type'] = 'application/json'
            return json.dumps(syslog_config)

        except Exception as e:
            abort(500, f"Syslog configuration error: {str(e)}")

    elif request.method == 'POST':
        try:
            if not session.get('user', {}).get('is_admin'):
                abort(403, "Admin access required")

            data = request.json
            if not data:
                abort(400, "JSON data required")

            # Update syslog configuration
            syslog_configs = [
                ('syslog_enabled', data.get('enabled')),
                ('syslog_host', data.get('host')),
                ('syslog_port', data.get('port')),
                ('syslog_protocol', data.get('protocol')),
                ('syslog_facility', data.get('facility')),
                ('syslog_tag', data.get('tag')),
            ]

            for key, value in syslog_configs:
                if value is not None:
                    config_manager.set_config(key, value, 'syslog')

            config_manager.clear_cache()

            response.headers['Content-Type'] = 'application/json'
            return json.dumps({'status': 'success', 'message': 'Syslog configuration updated'})

        except Exception as e:
            abort(500, f"Syslog configuration update error: {str(e)}")

def test_smtp():
    """Test SMTP configuration by sending a test email"""
    try:
        if not session.get('user', {}).get('is_admin'):
            abort(403, "Admin access required")

        config_manager = get_config_manager(db)
        smtp_config = config_manager.get_smtp_config()

        # Import email sending capability
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        # Create test message
        msg = MIMEMultipart()
        msg['From'] = smtp_config['from_address']
        msg['To'] = request.json.get('test_email', smtp_config['from_address'])
        msg['Subject'] = 'MarchProxy SMTP Test'

        body = """
        This is a test email from MarchProxy.

        If you received this email, your SMTP configuration is working correctly.

        Timestamp: %s
        """ % str(db.common_filter)

        msg.attach(MIMEText(body, 'plain'))

        # Connect and send
        if smtp_config['use_ssl']:
            server = smtplib.SMTP_SSL(smtp_config['host'], smtp_config['port'])
        else:
            server = smtplib.SMTP(smtp_config['host'], smtp_config['port'])
            if smtp_config['use_tls']:
                server.starttls()

        if smtp_config['username']:
            server.login(smtp_config['username'], smtp_config['password'])

        server.send_message(msg)
        server.quit()

        response.headers['Content-Type'] = 'application/json'
        return json.dumps({
            'status': 'success',
            'message': 'Test email sent successfully'
        })

    except Exception as e:
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({
            'status': 'error',
            'message': f'SMTP test failed: {str(e)}'
        })

# Route mappings
routes = [
    ('GET,POST /api/v1/config/system', system_config),
    ('GET /api/v1/config/database', database_config),
    ('GET,POST /api/v1/config/smtp', smtp_config),
    ('GET,POST /api/v1/config/syslog', syslog_config),
    ('GET /api/v1/monitoring/config', monitoring_config),
    ('POST /api/v1/config/smtp/test', test_smtp),
]