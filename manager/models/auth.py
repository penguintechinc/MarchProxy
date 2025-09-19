"""
Authentication models for MarchProxy Manager

Copyright (C) 2025 MarchProxy Contributors
Licensed under GNU Affero General Public License v3.0
"""

import bcrypt
import pyotp
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import jwt
from pydal import DAL, Field
from pydantic import BaseModel, EmailStr, validator


class UserModel:
    """User model with authentication methods"""

    @staticmethod
    def define_table(db: DAL):
        """Define user table in database"""
        return db.define_table(
            'users',
            Field('username', type='string', unique=True, required=True, length=50),
            Field('email', type='string', unique=True, required=True, length=255),
            Field('password_hash', type='string', required=True, length=255),
            Field('is_admin', type='boolean', default=False),
            Field('is_active', type='boolean', default=True),
            Field('totp_secret', type='string', length=32),
            Field('totp_enabled', type='boolean', default=False),
            Field('auth_provider', type='string', default='local', length=50),
            Field('external_id', type='string', length=255),
            Field('last_login', type='datetime'),
            Field('created_at', type='datetime', default=datetime.utcnow),
            Field('updated_at', type='datetime', update=datetime.utcnow),
            Field('metadata', type='json'),
        )

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

    @staticmethod
    def generate_totp_secret() -> str:
        """Generate TOTP secret for 2FA"""
        return pyotp.random_base32()

    @staticmethod
    def verify_totp(secret: str, token: str, window: int = 1) -> bool:
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=window)

    @staticmethod
    def get_totp_uri(secret: str, username: str, issuer: str = "MarchProxy") -> str:
        """Get TOTP URI for QR code generation"""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=username, issuer_name=issuer)


class SessionModel:
    """Session model for managing user sessions"""

    @staticmethod
    def define_table(db: DAL):
        """Define session table in database"""
        return db.define_table(
            'sessions',
            Field('session_id', type='string', unique=True, required=True, length=64),
            Field('user_id', type='reference users', required=True),
            Field('ip_address', type='string', length=45),
            Field('user_agent', type='string', length=255),
            Field('data', type='json'),
            Field('expires_at', type='datetime', required=True),
            Field('created_at', type='datetime', default=datetime.utcnow),
            Field('last_activity', type='datetime', default=datetime.utcnow),
        )

    @staticmethod
    def generate_session_id() -> str:
        """Generate secure session ID"""
        return secrets.token_urlsafe(48)

    @staticmethod
    def create_session(db: DAL, user_id: int, ip_address: str = None,
                       user_agent: str = None, ttl_hours: int = 24) -> str:
        """Create new session for user"""
        session_id = SessionModel.generate_session_id()
        expires_at = datetime.utcnow() + timedelta(hours=ttl_hours)

        db.sessions.insert(
            session_id=session_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at
        )

        return session_id

    @staticmethod
    def validate_session(db: DAL, session_id: str) -> Optional[Dict[str, Any]]:
        """Validate session and return user info if valid"""
        session = db(
            (db.sessions.session_id == session_id) &
            (db.sessions.expires_at > datetime.utcnow())
        ).select().first()

        if session:
            # Update last activity
            session.update_record(last_activity=datetime.utcnow())

            # Get user info
            user = db.users[session.user_id]
            if user and user.is_active:
                return {
                    'user_id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_admin': user.is_admin,
                    'session_id': session_id
                }

        return None

    @staticmethod
    def destroy_session(db: DAL, session_id: str) -> bool:
        """Destroy session"""
        return db(db.sessions.session_id == session_id).delete() > 0


class APITokenModel:
    """API Token model for service authentication"""

    @staticmethod
    def define_table(db: DAL):
        """Define API token table in database"""
        return db.define_table(
            'api_tokens',
            Field('token_id', type='string', unique=True, required=True, length=64),
            Field('name', type='string', required=True, length=100),
            Field('token_hash', type='string', required=True, length=255),
            Field('user_id', type='reference users'),
            Field('service_id', type='reference services'),
            Field('cluster_id', type='reference clusters'),
            Field('permissions', type='json'),
            Field('expires_at', type='datetime'),
            Field('last_used', type='datetime'),
            Field('is_active', type='boolean', default=True),
            Field('created_at', type='datetime', default=datetime.utcnow),
            Field('metadata', type='json'),
        )

    @staticmethod
    def generate_token() -> tuple[str, str]:
        """Generate API token and return (token, token_id)"""
        token = secrets.token_urlsafe(48)
        token_id = secrets.token_urlsafe(32)
        return token, token_id

    @staticmethod
    def hash_token(token: str) -> str:
        """Hash API token for storage"""
        return bcrypt.hashpw(token.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    @staticmethod
    def verify_token(token: str, token_hash: str) -> bool:
        """Verify API token against hash"""
        return bcrypt.checkpw(token.encode('utf-8'), token_hash.encode('utf-8'))

    @staticmethod
    def create_token(db: DAL, name: str, user_id: int = None,
                    service_id: int = None, cluster_id: int = None,
                    permissions: Dict = None, ttl_days: int = None) -> tuple[str, str]:
        """Create new API token"""
        token, token_id = APITokenModel.generate_token()
        token_hash = APITokenModel.hash_token(token)

        expires_at = None
        if ttl_days:
            expires_at = datetime.utcnow() + timedelta(days=ttl_days)

        db.api_tokens.insert(
            token_id=token_id,
            name=name,
            token_hash=token_hash,
            user_id=user_id,
            service_id=service_id,
            cluster_id=cluster_id,
            permissions=permissions or {},
            expires_at=expires_at
        )

        return token, token_id

    @staticmethod
    def validate_token(db: DAL, token: str) -> Optional[Dict[str, Any]]:
        """Validate API token and return associated info"""
        # Try to find token by checking hash
        for token_record in db(
            (db.api_tokens.is_active == True) &
            ((db.api_tokens.expires_at == None) | (db.api_tokens.expires_at > datetime.utcnow()))
        ).select():
            if APITokenModel.verify_token(token, token_record.token_hash):
                # Update last used
                token_record.update_record(last_used=datetime.utcnow())

                return {
                    'token_id': token_record.token_id,
                    'name': token_record.name,
                    'user_id': token_record.user_id,
                    'service_id': token_record.service_id,
                    'cluster_id': token_record.cluster_id,
                    'permissions': token_record.permissions
                }

        return None


class JWTManager:
    """JWT token management for stateless authentication"""

    def __init__(self, secret_key: str, algorithm: str = 'HS256', ttl_hours: int = 24):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.ttl_hours = ttl_hours

    def create_token(self, payload: Dict[str, Any]) -> str:
        """Create JWT token with payload"""
        payload = payload.copy()
        payload['exp'] = datetime.utcnow() + timedelta(hours=self.ttl_hours)
        payload['iat'] = datetime.utcnow()
        payload['iss'] = 'marchproxy'

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def decode_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Decode and validate JWT token"""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_exp": True, "verify_iat": True}
            )
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def create_refresh_token(self, user_id: int) -> str:
        """Create refresh token with longer TTL"""
        payload = {
            'user_id': user_id,
            'type': 'refresh',
            'exp': datetime.utcnow() + timedelta(days=30)
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """Create new access token from refresh token"""
        payload = self.decode_token(refresh_token)
        if payload and payload.get('type') == 'refresh':
            new_payload = {
                'user_id': payload['user_id'],
                'type': 'access'
            }
            return self.create_token(new_payload)
        return None


# Pydantic models for request/response validation
class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: Optional[str] = None

class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v

class Enable2FARequest(BaseModel):
    password: str

class Verify2FARequest(BaseModel):
    totp_code: str
    secret: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str]
    token_type: str = "Bearer"
    expires_in: int

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_admin: bool
    is_active: bool
    totp_enabled: bool
    auth_provider: str
    created_at: datetime