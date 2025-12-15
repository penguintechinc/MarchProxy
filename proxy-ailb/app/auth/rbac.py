"""
MarchProxy AILB Role-Based Access Control (RBAC) System
Handles authentication and authorization for AI/LLM proxy
Ported from WaddleAI with adaptations for MarchProxy architecture
"""

from enum import Enum
from typing import List, Dict, Optional, Set, Any, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
import functools
import hashlib
import hmac
import secrets
import json
import logging

logger = logging.getLogger(__name__)


class Role(Enum):
    """User roles with hierarchical permissions"""
    ADMIN = "admin"
    RESOURCE_MANAGER = "resource_manager"
    AUDITOR = "auditor"
    USER = "user"
    SERVICE = "service"  # For service accounts/API keys


class Permission(Enum):
    """System permissions"""
    # System administration
    SYSTEM_CONFIG = "system:config"
    SYSTEM_MONITOR = "system:monitor"
    SYSTEM_HEALTH = "system:health"

    # User management
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"

    # API key management
    APIKEY_CREATE = "apikey:create"
    APIKEY_READ = "apikey:read"
    APIKEY_UPDATE = "apikey:update"
    APIKEY_DELETE = "apikey:delete"
    APIKEY_ROTATE = "apikey:rotate"

    # Quota management
    QUOTA_READ = "quota:read"
    QUOTA_UPDATE = "quota:update"
    QUOTA_RESET = "quota:reset"

    # Analytics and reporting
    ANALYTICS_READ = "analytics:read"
    ANALYTICS_SYSTEM = "analytics:system"
    ANALYTICS_SECURITY = "analytics:security"
    ANALYTICS_EXPORT = "analytics:export"

    # LLM/AI management
    LLM_CONFIG = "llm:config"
    LLM_MODELS = "llm:models"
    LLM_PROVIDERS = "llm:providers"

    # Proxy usage
    PROXY_USE = "proxy:use"
    PROXY_ROUTE = "proxy:route"
    PROXY_ADMIN = "proxy:admin"

    # Security
    SECURITY_AUDIT = "security:audit"
    SECURITY_CONFIG = "security:config"


@dataclass
class UserContext:
    """User context for authorization"""
    user_id: str
    username: str
    role: Role
    organization_id: str = ""
    managed_orgs: List[str] = field(default_factory=list)
    permissions: Set[Permission] = field(default_factory=set)
    api_key_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    expires_at: Optional[str] = None

    def has_permission(self, permission: Permission) -> bool:
        """Check if user has specific permission"""
        return permission in self.permissions

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "role": self.role.value,
            "organization_id": self.organization_id,
            "managed_orgs": self.managed_orgs,
            "permissions": [p.value for p in self.permissions],
            "api_key_id": self.api_key_id,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "expires_at": self.expires_at
        }


# Role-based permission mapping
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMIN: {
        # Full system access
        Permission.SYSTEM_CONFIG,
        Permission.SYSTEM_MONITOR,
        Permission.SYSTEM_HEALTH,
        Permission.USER_CREATE,
        Permission.USER_READ,
        Permission.USER_UPDATE,
        Permission.USER_DELETE,
        Permission.APIKEY_CREATE,
        Permission.APIKEY_READ,
        Permission.APIKEY_UPDATE,
        Permission.APIKEY_DELETE,
        Permission.APIKEY_ROTATE,
        Permission.QUOTA_READ,
        Permission.QUOTA_UPDATE,
        Permission.QUOTA_RESET,
        Permission.ANALYTICS_READ,
        Permission.ANALYTICS_SYSTEM,
        Permission.ANALYTICS_SECURITY,
        Permission.ANALYTICS_EXPORT,
        Permission.LLM_CONFIG,
        Permission.LLM_MODELS,
        Permission.LLM_PROVIDERS,
        Permission.PROXY_USE,
        Permission.PROXY_ROUTE,
        Permission.PROXY_ADMIN,
        Permission.SECURITY_AUDIT,
        Permission.SECURITY_CONFIG,
    },
    Role.RESOURCE_MANAGER: {
        Permission.SYSTEM_HEALTH,
        Permission.USER_READ,
        Permission.USER_UPDATE,  # For assigned orgs
        Permission.APIKEY_CREATE,  # For assigned orgs
        Permission.APIKEY_READ,
        Permission.APIKEY_UPDATE,
        Permission.QUOTA_READ,
        Permission.QUOTA_UPDATE,  # For assigned orgs
        Permission.QUOTA_RESET,  # For assigned orgs
        Permission.ANALYTICS_READ,
        Permission.LLM_MODELS,  # View only
        Permission.PROXY_USE,
        Permission.PROXY_ROUTE,
    },
    Role.AUDITOR: {
        Permission.SYSTEM_HEALTH,
        Permission.USER_READ,
        Permission.APIKEY_READ,
        Permission.QUOTA_READ,
        Permission.ANALYTICS_READ,
        Permission.ANALYTICS_SYSTEM,
        Permission.ANALYTICS_SECURITY,
        Permission.ANALYTICS_EXPORT,
        Permission.SECURITY_AUDIT,
        Permission.PROXY_USE,
    },
    Role.USER: {
        Permission.SYSTEM_HEALTH,
        Permission.APIKEY_CREATE,  # Own keys only
        Permission.APIKEY_READ,  # Own keys only
        Permission.APIKEY_UPDATE,  # Own keys only
        Permission.QUOTA_READ,  # Own quota only
        Permission.ANALYTICS_READ,  # Own usage only
        Permission.PROXY_USE,
    },
    Role.SERVICE: {
        Permission.SYSTEM_HEALTH,
        Permission.PROXY_USE,
        Permission.ANALYTICS_READ,  # Own usage only
    }
}


class AuthenticationError(Exception):
    """Authentication failed"""
    pass


class AuthorizationError(Exception):
    """Authorization failed"""
    pass


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    """
    Hash password using PBKDF2-SHA256

    Returns:
        Tuple of (hash, salt)
    """
    if salt is None:
        salt = secrets.token_hex(16)

    # Use PBKDF2 with SHA256
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        iterations=100000
    )
    password_hash = dk.hex()

    return password_hash, salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """Verify password against stored hash"""
    computed_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(computed_hash, password_hash)


class RBACManager:
    """Role-Based Access Control Manager"""

    def __init__(
        self,
        jwt_secret: str,
        redis_client=None,
        config: Optional[Dict] = None
    ):
        """
        Initialize RBAC Manager

        Args:
            jwt_secret: Secret key for JWT token signing
            redis_client: Optional Redis client for storage
            config: Optional configuration dictionary
        """
        self.jwt_secret = jwt_secret
        self.redis = redis_client
        self.config = config or {}

        # In-memory user storage (for standalone mode)
        self._users: Dict[str, Dict] = {}
        self._api_keys: Dict[str, Dict] = {}

        # Token settings
        self.token_expiry_hours = self.config.get("token_expiry_hours", 24)
        self.api_key_prefix = self.config.get("api_key_prefix", "mp")

        logger.info("RBACManager initialized")

    def add_user(
        self,
        username: str,
        password: str,
        role: Role,
        organization_id: str = "",
        managed_orgs: Optional[List[str]] = None,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Add a new user

        Returns:
            User ID
        """
        user_id = secrets.token_hex(16)
        password_hash, salt = hash_password(password)

        user_data = {
            "user_id": user_id,
            "username": username,
            "password_hash": password_hash,
            "password_salt": salt,
            "role": role.value,
            "organization_id": organization_id,
            "managed_orgs": managed_orgs or [],
            "metadata": metadata or {},
            "enabled": True,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }

        self._users[username] = user_data

        # Persist to Redis if available
        if self.redis:
            self.redis.set(
                f"ailb:user:{username}",
                json.dumps(user_data),
                ex=86400 * 30  # 30 day TTL
            )

        logger.info("Created user: %s with role %s", username, role.value)
        return user_id

    def get_user(self, username: str) -> Optional[Dict]:
        """Get user by username"""
        # Check in-memory first
        if username in self._users:
            return self._users[username]

        # Check Redis
        if self.redis:
            user_json = self.redis.get(f"ailb:user:{username}")
            if user_json:
                user_data = json.loads(user_json)
                self._users[username] = user_data
                return user_data

        return None

    def authenticate_user(self, username: str, password: str) -> UserContext:
        """Authenticate user with username/password"""
        user = self.get_user(username)

        if not user:
            logger.warning("Authentication failed: user not found: %s", username)
            raise AuthenticationError("Invalid username or password")

        if not user.get("enabled", True):
            logger.warning("Authentication failed: user disabled: %s", username)
            raise AuthenticationError("User account is disabled")

        if not verify_password(
            password,
            user["password_hash"],
            user["password_salt"]
        ):
            logger.warning("Authentication failed: invalid password for %s", username)
            raise AuthenticationError("Invalid username or password")

        return self._build_user_context(user)

    def authenticate_api_key(self, api_key: str) -> UserContext:
        """Authenticate using API key"""
        # Parse API key format: {prefix}-{key_id}-{secret}
        try:
            parts = api_key.split('-')
            if len(parts) < 3:
                raise AuthenticationError("Invalid API key format")

            prefix = parts[0]
            key_id = parts[1]

            if prefix != self.api_key_prefix:
                raise AuthenticationError("Invalid API key format")

        except Exception:
            raise AuthenticationError("Invalid API key format")

        # Look up API key
        key_data = self._get_api_key(key_id)
        if not key_data:
            logger.warning("API key not found: %s...", key_id[:8])
            raise AuthenticationError("Invalid API key")

        if not key_data.get("enabled", True):
            logger.warning("API key disabled: %s", key_id)
            raise AuthenticationError("API key is disabled")

        # Check expiration
        if key_data.get("expires_at"):
            expires = datetime.fromisoformat(key_data["expires_at"])
            if datetime.utcnow() > expires:
                logger.warning("API key expired: %s", key_id)
                raise AuthenticationError("API key has expired")

        # Verify key hash
        stored_hash = key_data.get("key_hash", "")
        computed_hash = hashlib.sha256(api_key.encode()).hexdigest()

        if not hmac.compare_digest(stored_hash, computed_hash):
            logger.warning("API key hash mismatch: %s", key_id)
            raise AuthenticationError("Invalid API key")

        # Get associated user
        user = self.get_user(key_data["username"])
        if not user:
            raise AuthenticationError("API key user not found")

        context = self._build_user_context(user)
        context.api_key_id = key_id

        # Update last used
        self._update_api_key_usage(key_id)

        logger.info("API key authenticated: %s for user %s",
                   key_id, user["username"])

        return context

    def _get_api_key(self, key_id: str) -> Optional[Dict]:
        """Get API key by ID"""
        if key_id in self._api_keys:
            return self._api_keys[key_id]

        if self.redis:
            key_json = self.redis.get(f"ailb:apikey:{key_id}")
            if key_json:
                key_data = json.loads(key_json)
                self._api_keys[key_id] = key_data
                return key_data

        return None

    def _update_api_key_usage(self, key_id: str):
        """Update API key last used timestamp"""
        if key_id in self._api_keys:
            self._api_keys[key_id]["last_used"] = datetime.utcnow().isoformat()

        if self.redis:
            self.redis.hset(f"ailb:apikey:{key_id}", "last_used",
                          datetime.utcnow().isoformat())

    def _build_user_context(self, user: Dict) -> UserContext:
        """Build user context from stored data"""
        role = Role(user["role"])
        permissions = ROLE_PERMISSIONS.get(role, set())

        return UserContext(
            user_id=user["user_id"],
            username=user["username"],
            role=role,
            organization_id=user.get("organization_id", ""),
            managed_orgs=user.get("managed_orgs", []),
            permissions=permissions,
            metadata=user.get("metadata", {}),
            created_at=user.get("created_at", "")
        )

    def generate_jwt_token(
        self,
        user_context: UserContext,
        expires_hours: Optional[int] = None
    ) -> str:
        """Generate JWT token for user"""
        import base64

        if expires_hours is None:
            expires_hours = self.token_expiry_hours

        now = datetime.utcnow()
        expires = now + timedelta(hours=expires_hours)

        # Create payload
        payload = {
            "user_id": user_context.user_id,
            "username": user_context.username,
            "role": user_context.role.value,
            "organization_id": user_context.organization_id,
            "managed_orgs": user_context.managed_orgs,
            "exp": int(expires.timestamp()),
            "iat": int(now.timestamp()),
            "iss": "marchproxy-ailb"
        }

        # Simple JWT implementation (header.payload.signature)
        header = {"alg": "HS256", "typ": "JWT"}

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b'=').decode()

        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()

        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            self.jwt_secret.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

        return f"{header_b64}.{payload_b64}.{signature_b64}"

    def verify_jwt_token(self, token: str) -> UserContext:
        """Verify JWT token and return user context"""
        import base64

        try:
            parts = token.split('.')
            if len(parts) != 3:
                raise AuthenticationError("Invalid token format")

            header_b64, payload_b64, signature_b64 = parts

            # Verify signature
            message = f"{header_b64}.{payload_b64}"
            expected_sig = hmac.new(
                self.jwt_secret.encode(),
                message.encode(),
                hashlib.sha256
            ).digest()
            expected_sig_b64 = base64.urlsafe_b64encode(
                expected_sig
            ).rstrip(b'=').decode()

            if not hmac.compare_digest(signature_b64, expected_sig_b64):
                raise AuthenticationError("Invalid token signature")

            # Decode payload
            # Add padding if needed
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += '=' * padding

            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            # Check expiration
            if datetime.utcnow().timestamp() > payload.get("exp", 0):
                raise AuthenticationError("Token has expired")

            role = Role(payload["role"])
            permissions = ROLE_PERMISSIONS.get(role, set())

            return UserContext(
                user_id=payload["user_id"],
                username=payload["username"],
                role=role,
                organization_id=payload.get("organization_id", ""),
                managed_orgs=payload.get("managed_orgs", []),
                permissions=permissions
            )

        except AuthenticationError:
            raise
        except Exception as e:
            logger.warning("Token verification failed: %s", str(e))
            raise AuthenticationError("Invalid token")

    def check_permission(
        self,
        user_context: UserContext,
        permission: Permission,
        resource_org_id: Optional[str] = None,
        resource_user_id: Optional[str] = None
    ) -> bool:
        """Check if user has permission for specific resource"""
        # Check base permission
        if permission not in user_context.permissions:
            return False

        # Admin has access to everything
        if user_context.role == Role.ADMIN:
            return True

        # Resource-specific checks
        if resource_org_id is not None:
            # Resource managers can only access their assigned orgs
            if user_context.role == Role.RESOURCE_MANAGER:
                if resource_org_id not in user_context.managed_orgs:
                    return False

            # Auditors can only access their assigned orgs
            elif user_context.role == Role.AUDITOR:
                if resource_org_id not in user_context.managed_orgs:
                    return False

            # Users can only access their own organization
            elif user_context.role == Role.USER:
                if resource_org_id != user_context.organization_id:
                    return False

        # User-specific checks
        if resource_user_id is not None:
            # Users can only access their own data
            if user_context.role in [Role.USER, Role.SERVICE]:
                if resource_user_id != user_context.user_id:
                    return False

        return True

    def require_permission(
        self,
        permission: Permission,
        resource_org_id: Optional[str] = None
    ) -> Callable:
        """Decorator to require specific permission"""
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # Extract user context from kwargs
                user_context = kwargs.get('user_context')
                if not user_context:
                    raise AuthorizationError("No user context provided")

                if not self.check_permission(
                    user_context, permission, resource_org_id
                ):
                    raise AuthorizationError(
                        f"Permission denied: {permission.value}"
                    )

                return func(*args, **kwargs)
            return wrapper
        return decorator

    def create_api_key(
        self,
        user_context: UserContext,
        name: str,
        permissions: Optional[Dict[str, bool]] = None,
        expires_days: Optional[int] = None
    ) -> tuple[str, str]:
        """
        Create new API key for user

        Returns:
            Tuple of (api_key, key_id)
        """
        # Generate API key components
        key_id = secrets.token_hex(8)
        secret = secrets.token_urlsafe(32)
        api_key = f"{self.api_key_prefix}-{key_id}-{secret}"

        # Hash the full API key
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        expires_at = None
        if expires_days:
            expires_at = (
                datetime.utcnow() + timedelta(days=expires_days)
            ).isoformat()

        # Determine access level based on user role
        access_level = "proxy"
        if user_context.role in [Role.ADMIN, Role.RESOURCE_MANAGER]:
            access_level = "management"
        if user_context.role == Role.ADMIN:
            access_level = "admin"

        key_data = {
            "key_id": key_id,
            "key_hash": key_hash,
            "username": user_context.username,
            "user_id": user_context.user_id,
            "organization_id": user_context.organization_id,
            "name": name,
            "permissions": permissions or {},
            "access_level": access_level,
            "enabled": True,
            "expires_at": expires_at,
            "created_at": datetime.utcnow().isoformat(),
            "last_used": None
        }

        self._api_keys[key_id] = key_data

        # Persist to Redis if available
        if self.redis:
            self.redis.set(
                f"ailb:apikey:{key_id}",
                json.dumps(key_data),
                ex=86400 * 365 if not expires_at else None  # 1 year or until expiry
            )

        logger.info(
            "Created API key %s for user %s",
            key_id, user_context.username
        )

        return api_key, key_id

    def revoke_api_key(self, key_id: str, user_context: UserContext) -> bool:
        """Revoke an API key"""
        key_data = self._get_api_key(key_id)
        if not key_data:
            return False

        # Check permission
        if user_context.role != Role.ADMIN:
            if key_data["user_id"] != user_context.user_id:
                raise AuthorizationError("Cannot revoke another user's API key")

        # Disable the key
        key_data["enabled"] = False
        key_data["revoked_at"] = datetime.utcnow().isoformat()
        self._api_keys[key_id] = key_data

        if self.redis:
            self.redis.set(
                f"ailb:apikey:{key_id}",
                json.dumps(key_data)
            )

        logger.info("Revoked API key: %s", key_id)
        return True

    def list_api_keys(self, user_context: UserContext) -> List[Dict]:
        """List API keys for a user"""
        keys = []

        # Filter based on role
        for key_id, key_data in self._api_keys.items():
            if user_context.role == Role.ADMIN:
                # Admin sees all
                keys.append(self._sanitize_key_data(key_data))
            elif key_data["user_id"] == user_context.user_id:
                # Users see their own
                keys.append(self._sanitize_key_data(key_data))
            elif (user_context.role == Role.RESOURCE_MANAGER and
                  key_data.get("organization_id") in user_context.managed_orgs):
                # Resource managers see their org's keys
                keys.append(self._sanitize_key_data(key_data))

        return keys

    def _sanitize_key_data(self, key_data: Dict) -> Dict:
        """Remove sensitive data from key info"""
        return {
            "key_id": key_data["key_id"],
            "name": key_data["name"],
            "username": key_data["username"],
            "access_level": key_data["access_level"],
            "enabled": key_data["enabled"],
            "expires_at": key_data.get("expires_at"),
            "created_at": key_data["created_at"],
            "last_used": key_data.get("last_used")
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get RBAC statistics"""
        return {
            "total_users": len(self._users),
            "total_api_keys": len(self._api_keys),
            "active_api_keys": sum(
                1 for k in self._api_keys.values() if k.get("enabled", True)
            ),
            "users_by_role": {
                role.value: sum(
                    1 for u in self._users.values()
                    if u.get("role") == role.value
                )
                for role in Role
            }
        }
