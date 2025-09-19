"""
Authentication API endpoints for MarchProxy Manager

Copyright (C) 2025 MarchProxy Contributors
Licensed under GNU Affero General Public License v3.0
"""

from py4web import request, response, abort, redirect
from py4web.utils.cors import enable_cors
from pydantic import ValidationError
import json
import logging
from datetime import datetime
from ..models.auth import (
    UserModel, SessionModel, JWTManager, APITokenModel,
    LoginRequest, RegisterRequest, Enable2FARequest, Verify2FARequest,
    TokenResponse, UserResponse
)

logger = logging.getLogger(__name__)


def auth_api(db, jwt_manager: JWTManager):
    """Authentication API endpoints"""

    @enable_cors()
    def login():
        """User login endpoint"""
        if request.method == 'POST':
            try:
                data = LoginRequest(**request.json)
            except ValidationError as e:
                response.status = 400
                return {"error": "Validation error", "details": str(e)}

            # Find user
            user = db(db.users.username == data.username).select().first()
            if not user or not UserModel.verify_password(data.password, user.password_hash):
                response.status = 401
                return {"error": "Invalid credentials"}

            # Check if user is active
            if not user.is_active:
                response.status = 403
                return {"error": "Account is disabled"}

            # Check 2FA if enabled
            if user.totp_enabled:
                if not data.totp_code:
                    response.status = 422
                    return {"error": "TOTP code required"}

                if not UserModel.verify_totp(user.totp_secret, data.totp_code):
                    response.status = 401
                    return {"error": "Invalid TOTP code"}

            # Update last login
            user.update_record(last_login=datetime.utcnow())

            # Create session
            session_id = SessionModel.create_session(
                db, user.id,
                ip_address=request.environ.get('REMOTE_ADDR'),
                user_agent=request.environ.get('HTTP_USER_AGENT')
            )

            # Create JWT tokens
            access_payload = {
                'user_id': user.id,
                'username': user.username,
                'is_admin': user.is_admin,
                'session_id': session_id,
                'type': 'access'
            }
            access_token = jwt_manager.create_token(access_payload)
            refresh_token = jwt_manager.create_refresh_token(user.id)

            return TokenResponse(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=jwt_manager.ttl_hours * 3600
            ).dict()

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def logout():
        """User logout endpoint"""
        if request.method == 'POST':
            # Get session from token
            auth_header = request.environ.get('HTTP_AUTHORIZATION', '')
            if not auth_header.startswith('Bearer '):
                response.status = 401
                return {"error": "Missing or invalid authorization header"}

            token = auth_header[7:]
            payload = jwt_manager.decode_token(token)
            if not payload:
                response.status = 401
                return {"error": "Invalid token"}

            session_id = payload.get('session_id')
            if session_id:
                SessionModel.destroy_session(db, session_id)

            return {"message": "Logged out successfully"}

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def register():
        """User registration endpoint (admin only)"""
        if request.method == 'POST':
            # Check authentication
            auth_result = _check_auth(db, jwt_manager, admin_required=True)
            if 'error' in auth_result:
                response.status = auth_result['status']
                return auth_result

            try:
                data = RegisterRequest(**request.json)
            except ValidationError as e:
                response.status = 400
                return {"error": "Validation error", "details": str(e)}

            # Check if username or email already exists
            existing = db(
                (db.users.username == data.username) |
                (db.users.email == data.email)
            ).select().first()

            if existing:
                response.status = 409
                return {"error": "Username or email already exists"}

            # Create user
            password_hash = UserModel.hash_password(data.password)
            user_id = db.users.insert(
                username=data.username,
                email=data.email,
                password_hash=password_hash
            )

            user = db.users[user_id]
            return UserResponse(
                id=user.id,
                username=user.username,
                email=user.email,
                is_admin=user.is_admin,
                is_active=user.is_active,
                totp_enabled=user.totp_enabled,
                auth_provider=user.auth_provider,
                created_at=user.created_at
            ).dict()

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def refresh_token():
        """Refresh access token"""
        if request.method == 'POST':
            data = request.json
            refresh_token = data.get('refresh_token')

            if not refresh_token:
                response.status = 400
                return {"error": "Refresh token required"}

            new_access_token = jwt_manager.refresh_access_token(refresh_token)
            if not new_access_token:
                response.status = 401
                return {"error": "Invalid or expired refresh token"}

            return {
                "access_token": new_access_token,
                "token_type": "Bearer",
                "expires_in": jwt_manager.ttl_hours * 3600
            }

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def enable_2fa():
        """Enable 2FA for user"""
        if request.method == 'POST':
            # Check authentication
            auth_result = _check_auth(db, jwt_manager)
            if 'error' in auth_result:
                response.status = auth_result['status']
                return auth_result

            user_id = auth_result['user']['id']

            try:
                data = Enable2FARequest(**request.json)
            except ValidationError as e:
                response.status = 400
                return {"error": "Validation error", "details": str(e)}

            # Verify current password
            user = db.users[user_id]
            if not UserModel.verify_password(data.password, user.password_hash):
                response.status = 401
                return {"error": "Invalid password"}

            # Generate TOTP secret
            totp_secret = UserModel.generate_totp_secret()
            totp_uri = UserModel.get_totp_uri(totp_secret, user.username)

            # Store secret (but don't enable yet)
            user.update_record(totp_secret=totp_secret)

            return {
                "secret": totp_secret,
                "qr_uri": totp_uri,
                "message": "Scan QR code and verify with TOTP code to complete setup"
            }

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def verify_2fa():
        """Verify and complete 2FA setup"""
        if request.method == 'POST':
            # Check authentication
            auth_result = _check_auth(db, jwt_manager)
            if 'error' in auth_result:
                response.status = auth_result['status']
                return auth_result

            user_id = auth_result['user']['id']

            try:
                data = Verify2FARequest(**request.json)
            except ValidationError as e:
                response.status = 400
                return {"error": "Validation error", "details": str(e)}

            # Verify TOTP code
            if not UserModel.verify_totp(data.secret, data.totp_code):
                response.status = 400
                return {"error": "Invalid TOTP code"}

            # Enable 2FA for user
            user = db.users[user_id]
            user.update_record(totp_enabled=True)

            return {"message": "2FA enabled successfully"}

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def disable_2fa():
        """Disable 2FA for user"""
        if request.method == 'POST':
            # Check authentication
            auth_result = _check_auth(db, jwt_manager)
            if 'error' in auth_result:
                response.status = auth_result['status']
                return auth_result

            user_id = auth_result['user']['id']
            data = request.json

            # Verify current password
            user = db.users[user_id]
            if not UserModel.verify_password(data.get('password', ''), user.password_hash):
                response.status = 401
                return {"error": "Invalid password"}

            # Verify TOTP code if 2FA is currently enabled
            if user.totp_enabled:
                totp_code = data.get('totp_code')
                if not totp_code or not UserModel.verify_totp(user.totp_secret, totp_code):
                    response.status = 400
                    return {"error": "Invalid TOTP code"}

            # Disable 2FA
            user.update_record(totp_enabled=False, totp_secret=None)

            return {"message": "2FA disabled successfully"}

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    @enable_cors()
    def profile():
        """Get/update user profile"""
        # Check authentication
        auth_result = _check_auth(db, jwt_manager)
        if 'error' in auth_result:
            response.status = auth_result['status']
            return auth_result

        user_id = auth_result['user']['id']
        user = db.users[user_id]

        if request.method == 'GET':
            return UserResponse(
                id=user.id,
                username=user.username,
                email=user.email,
                is_admin=user.is_admin,
                is_active=user.is_active,
                totp_enabled=user.totp_enabled,
                auth_provider=user.auth_provider,
                created_at=user.created_at
            ).dict()

        elif request.method == 'PUT':
            data = request.json
            update_data = {}

            # Allow updating email
            if 'email' in data:
                update_data['email'] = data['email']

            # Allow updating password with current password verification
            if 'new_password' in data:
                current_password = data.get('current_password')
                if not current_password or not UserModel.verify_password(current_password, user.password_hash):
                    response.status = 401
                    return {"error": "Current password required for password change"}

                update_data['password_hash'] = UserModel.hash_password(data['new_password'])

            if update_data:
                user.update_record(**update_data)

            return {"message": "Profile updated successfully"}

        else:
            response.status = 405
            return {"error": "Method not allowed"}

    # Return API endpoints
    return {
        'login': login,
        'logout': logout,
        'register': register,
        'refresh_token': refresh_token,
        'enable_2fa': enable_2fa,
        'verify_2fa': verify_2fa,
        'disable_2fa': disable_2fa,
        'profile': profile
    }


def _check_auth(db, jwt_manager, admin_required=False):
    """Helper function to check authentication"""
    auth_header = request.environ.get('HTTP_AUTHORIZATION', '')
    if not auth_header.startswith('Bearer '):
        return {"error": "Missing or invalid authorization header", "status": 401}

    token = auth_header[7:]
    payload = jwt_manager.decode_token(token)
    if not payload:
        return {"error": "Invalid or expired token", "status": 401}

    user_id = payload.get('user_id')
    if not user_id:
        return {"error": "Invalid token payload", "status": 401}

    # Validate session if present
    session_id = payload.get('session_id')
    if session_id:
        session_info = SessionModel.validate_session(db, session_id)
        if not session_info:
            return {"error": "Invalid or expired session", "status": 401}

    # Get user
    user = db.users[user_id]
    if not user or not user.is_active:
        return {"error": "User not found or inactive", "status": 401}

    # Check admin requirement
    if admin_required and not user.is_admin:
        return {"error": "Admin access required", "status": 403}

    return {
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin
        },
        "payload": payload
    }