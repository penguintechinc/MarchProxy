"""
Native py4web authentication integration for MarchProxy Manager

Copyright (C) 2025 MarchProxy Contributors
Licensed under GNU Affero General Public License v3.0
"""

from py4web import Field
from py4web.utils.auth import Auth
from py4web.utils.mailer import Mailer
from pydal import DAL
import secrets
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict, Any


def setup_auth(db: DAL, base_url: str = "http://localhost:8000") -> Auth:
    """Setup py4web native authentication"""

    # Configure mailer (optional - can be disabled for development)
    mailer = Mailer(
        server="smtp://localhost:587",
        sender="noreply@marchproxy.local"
    )

    # Initialize Auth with py4web native features
    auth = Auth(
        session=None,  # Will be set by py4web
        db=db,
        sender=mailer,
        registration_requires_confirmation=False,  # Disable for admin-only registration
        registration_requires_approval=True,      # Admin approval required
        two_factor_required=lambda user: user.get('totp_enabled', False),
        login_expiration_time=3600,  # 1 hour
        password_complexity={
            "min": 8,
            "upper": 1,
            "lower": 1,
            "special": 1,
            "number": 1
        }
    )

    # Add custom fields to auth_user table
    auth.db.auth_user._before_insert.append(lambda f: f.update(
        is_admin=False,
        totp_enabled=False,
        totp_secret=None,
        auth_provider='local',
        external_id=None,
        last_login=None
    ))

    return auth


def extend_auth_user_table(auth: Auth):
    """Extend the native auth_user table with MarchProxy specific fields"""

    # Add custom fields to the auth_user table
    if 'is_admin' not in auth.db.auth_user.fields:
        auth.db.auth_user._before_define.append(lambda table: table._after_define.append(
            lambda: [
                table.is_admin.set_attributes(type='boolean', default=False),
                table.totp_enabled.set_attributes(type='boolean', default=False),
                table.totp_secret.set_attributes(type='string', length=32),
                table.auth_provider.set_attributes(type='string', default='local', length=50),
                table.external_id.set_attributes(type='string', length=255),
                table.last_login.set_attributes(type='datetime'),
                table.metadata.set_attributes(type='json')
            ]
        ))


class TOTPManager:
    """TOTP/2FA management using py4web auth integration"""

    def __init__(self, auth: Auth):
        self.auth = auth
        self.db = auth.db

    def enable_2fa(self, user_id: int, password: str) -> Optional[Dict[str, str]]:
        """Enable 2FA for user"""
        user = self.db.auth_user[user_id]
        if not user:
            return None

        # Verify current password using py4web's auth
        if not self.auth.verify_password(password, user.password):
            return None

        # Generate TOTP secret
        secret = pyotp.random_base32()

        # Update user record
        user.update_record(totp_secret=secret)

        # Generate QR code URI
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(
            name=user.email,
            issuer_name="MarchProxy"
        )

        return {
            'secret': secret,
            'qr_uri': uri,
            'qr_code': self._generate_qr_code(uri)
        }

    def verify_and_complete_2fa(self, user_id: int, secret: str, totp_code: str) -> bool:
        """Verify TOTP code and complete 2FA setup"""
        user = self.db.auth_user[user_id]
        if not user or user.totp_secret != secret:
            return False

        # Verify TOTP code
        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_code, valid_window=1):
            return False

        # Enable 2FA
        user.update_record(totp_enabled=True)
        return True

    def disable_2fa(self, user_id: int, password: str, totp_code: str = None) -> bool:
        """Disable 2FA for user"""
        user = self.db.auth_user[user_id]
        if not user:
            return False

        # Verify current password
        if not self.auth.verify_password(password, user.password):
            return False

        # If 2FA is enabled, require TOTP code
        if user.totp_enabled and user.totp_secret:
            if not totp_code:
                return False

            totp = pyotp.TOTP(user.totp_secret)
            if not totp.verify(totp_code, valid_window=1):
                return False

        # Disable 2FA
        user.update_record(totp_enabled=False, totp_secret=None)
        return True

    def verify_totp(self, user_id: int, totp_code: str) -> bool:
        """Verify TOTP code for user"""
        user = self.db.auth_user[user_id]
        if not user or not user.totp_enabled or not user.totp_secret:
            return False

        totp = pyotp.TOTP(user.totp_secret)
        return totp.verify(totp_code, valid_window=1)

    def _generate_qr_code(self, uri: str) -> str:
        """Generate QR code as base64 image"""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)

        return base64.b64encode(buffer.getvalue()).decode()


class APITokenManager:
    """API token management using py4web auth integration"""

    def __init__(self, auth: Auth):
        self.auth = auth
        self.db = auth.db
        self._setup_token_table()

    def _setup_token_table(self):
        """Setup API tokens table"""
        if 'api_tokens' not in self.db.tables:
            self.db.define_table(
                'api_tokens',
                Field('token_id', type='string', unique=True, required=True, length=64),
                Field('name', type='string', required=True, length=100),
                Field('token_hash', type='string', required=True, length=255),
                Field('user_id', type='reference auth_user'),
                Field('service_id', type='integer'),  # Will be foreign key when services table exists
                Field('cluster_id', type='integer'),  # Will be foreign key when clusters table exists
                Field('permissions', type='json'),
                Field('expires_at', type='datetime'),
                Field('last_used', type='datetime'),
                Field('is_active', type='boolean', default=True),
                Field('created_at', type='datetime', default=datetime.utcnow),
                Field('metadata', type='json'),
            )

    def create_token(self, user_id: int, name: str, permissions: Dict = None,
                    ttl_days: int = None) -> tuple[str, str]:
        """Create API token for user"""
        import bcrypt

        token = secrets.token_urlsafe(48)
        token_id = secrets.token_urlsafe(32)
        token_hash = bcrypt.hashpw(token.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        expires_at = None
        if ttl_days:
            expires_at = datetime.utcnow() + timedelta(days=ttl_days)

        self.db.api_tokens.insert(
            token_id=token_id,
            name=name,
            token_hash=token_hash,
            user_id=user_id,
            permissions=permissions or {},
            expires_at=expires_at
        )

        return token, token_id

    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate API token"""
        import bcrypt

        # Try to find token by checking hash
        for token_record in self.db(
            (self.db.api_tokens.is_active == True) &
            ((self.db.api_tokens.expires_at == None) |
             (self.db.api_tokens.expires_at > datetime.utcnow()))
        ).select():
            if bcrypt.checkpw(token.encode('utf-8'), token_record.token_hash.encode('utf-8')):
                # Update last used
                token_record.update_record(last_used=datetime.utcnow())

                return {
                    'token_id': token_record.token_id,
                    'name': token_record.name,
                    'user_id': token_record.user_id,
                    'permissions': token_record.permissions
                }

        return None


def create_admin_user(auth: Auth, username: str = 'admin',
                     email: str = 'admin@localhost',
                     password: str = 'admin123') -> int:
    """Create default admin user using py4web auth"""

    # Check if admin already exists
    existing = auth.db(auth.db.auth_user.email == email).select().first()
    if existing:
        return existing.id

    # Use py4web's native user creation
    user_id = auth.register(
        email=email,
        password=password,
        first_name='System',
        last_name='Administrator'
    ).get('id')

    if user_id:
        # Update with admin privileges
        user = auth.db.auth_user[user_id]
        user.update_record(
            is_admin=True,
            registration_key='',  # Approve the user
            registration_id=''
        )

        # Create default API token for admin
        token_manager = APITokenManager(auth)
        token, token_id = token_manager.create_token(
            user_id,
            'admin-default',
            {'admin': True}
        )

        print(f"Admin user created - Email: {email}, Password: {password}")
        print(f"Admin API token: {token}")

    return user_id


def setup_auth_groups(auth: Auth):
    """Setup authorization groups using py4web's auth system"""

    # Create admin group
    admin_group_id = auth.add_group('admin', 'System Administrators')

    # Create service owner group
    service_owner_group_id = auth.add_group('service_owner', 'Service Owners')

    # Define permissions
    permissions = [
        'read_clusters', 'create_clusters', 'update_clusters', 'delete_clusters',
        'read_services', 'create_services', 'update_services', 'delete_services',
        'read_mappings', 'create_mappings', 'update_mappings', 'delete_mappings',
        'read_proxies', 'manage_proxies',
        'read_certificates', 'create_certificates', 'update_certificates',
        'read_users', 'create_users', 'update_users', 'delete_users',
        'read_metrics', 'read_logs'
    ]

    # Add permissions
    for perm in permissions:
        auth.add_permission(admin_group_id, perm)

    # Service owners get limited permissions
    service_perms = [
        'read_clusters', 'read_services', 'create_services', 'update_services',
        'read_mappings', 'create_mappings', 'update_mappings',
        'read_proxies', 'read_certificates', 'read_metrics'
    ]

    for perm in service_perms:
        auth.add_permission(service_owner_group_id, perm)

    return {
        'admin': admin_group_id,
        'service_owner': service_owner_group_id
    }


def check_permission(auth: Auth, permission: str) -> bool:
    """Check if current user has permission"""
    if not auth.user_id:
        return False

    user = auth.get_user()
    if user.get('is_admin'):
        return True

    return auth.has_permission(permission, auth.user_id)


def require_permission(auth: Auth, permission: str):
    """Decorator to require permission for endpoint"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not check_permission(auth, permission):
                from py4web import abort
                abort(403)
            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_admin(auth: Auth):
    """Decorator to require admin access"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            user = auth.get_user()
            if not user or not user.get('is_admin'):
                from py4web import abort
                abort(403)
            return func(*args, **kwargs)
        return wrapper
    return decorator