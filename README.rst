
DRF Cas JWT
=========================================

DRF-cas-jwt is a Django app to integrate DRF with CAS (Central Authentication Service) using JWT tokens.
Features secure token management with refresh rotation, reuse detection, rate limiting, and audit logging.


Quick start
-----------

1. Add "drf_cas_jwt" to your INSTALLED_APPS setting::

    INSTALLED_APPS = [
        ...,
        "drf_cas_jwt",
    ]

2. Add caching configuration to settings.py for rate limiting (Redis recommended)::

    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": "redis://127.0.0.1:6379/1",
        }
    }

3. Set the variable CAS_JWT_LOGOUT_REDIRECT and CAS_JWT_LOGIN_REDIRECT in settings.py::

    CAS_JWT_LOGIN_REDIRECT = "https://yourfrontend.com"
    CAS_JWT_LOGOUT_REDIRECT = "https://cas.example.com/logout"

4. Add "CasJwtAuthentication" to your REST_FRAMEWORK setting::

    REST_FRAMEWORK = {
        "DEFAULT_AUTHENTICATION_CLASSES": [
            ...,
            "drf_cas_jwt.authentication.CasJwtAuthentication",
            # "rest_framework_simplejwt.authentication.JWTAuthentication",
        ]
    }

5. Include the drf_cas_jwt URLconf in your project urls.py::

    from drf_cas_jwt.views import CasLogin, CasLogout
    
    urlpatterns = [
        ...,
        path("auth/login", CasLogin.as_view(), name="cas-jwt-login"),
        path("auth/logout", CasLogout.as_view(), name="cas-jwt-logout"),
    ]

6. Run migrations::

    python manage.py migrate drf_cas_jwt


Security Features
-----------------

**Token Management (v1.0.0)**

- **HMAC-SHA256 Token Hashing**: Tokens stored as secure hashes, never plaintext
- **HttpOnly Cookies**: Refresh tokens stored in HttpOnly/Secure/SameSite cookies (XSS/CSRF protection)
- **Refresh Token Rotation**: New jti generated on each token refresh, old tokens tracked for replay detection
- **Reuse Detection**: If a rotated token reappears, entire token chain is revoked (security breach signal)
- **Rate Limiting**: Configurable login/refresh attempts per IP+user (cache-based, distributed)
- **Audit Logging**: All auth events (LOGIN, LOGOUT, REFRESH, REUSE_DETECTED) logged with IP, timestamp


API Endpoints
-------------

**Login**

``GET /auth/login?ticket=...`` (CAS redirect)

Returns::

    {
        "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
        "user": {
            "id": 1,
            "email": "john@example.com"
        }
    }

Refresh token automatically set in HttpOnly cookie.

**Logout**

``POST /auth/logout``

Authorization: ``Bearer <access_token>``

Returns::

    {
        "detail": "Successfully logged out"
    }

Clears refresh_token cookie and revokes entire token chain.


Client Integration
------------------

**Fetch Access Token**

During login, store access_token from response body::

    const response = await fetch('/auth/login?ticket=...');
    const data = await response.json();
    localStorage.setItem('access_token', data.access_token);

**Make Authenticated Requests**

Add Authorization header with Bearer token::

    fetch('/api/profile', {
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('access_token')}`
        }
    })

**Refresh Token (automatic via cookie)**

Refresh token is stored in HttpOnly cookie, sent automatically by browser.
SimpleJWT endpoint can be used to refresh access token::

    POST /api/token/refresh/
    (refresh_token sent in cookie automatically)

**Logout**

Send POST to logout endpoint::

    fetch('/auth/logout', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('access_token')}`
        }
    })

Browser automatically clears refresh_token cookie.


Database Models
---------------

**Token**

Tracks active JWT tokens (access tokens).

- ``id`` (UUID): Unique identifier
- ``user``: Foreign key to User
- ``jti``: JWT ID for refresh tracking
- ``token``: HMAC-SHA256 hash of JWT
- ``ip``: Client IP address
- ``created_at``: Timestamp
- ``deleted_at``: Soft-delete timestamp (None = active)

**RefreshTokenFamily**

Tracks refresh token rotation and detects reuse attacks.

- ``jti``: JWT ID of refresh token
- ``user``: Foreign key to User
- ``parent_jti``: jti of previous token (rotation chain)
- ``ip``: Client IP
- ``created_at``: Timestamp
- ``rotated_at``: When this token was rotated to next jti
- ``revoked_at``: When revoked (reuse detected or manual logout)

**TokenAuditLog**

Audit trail for security investigations.

- ``user``: Foreign key to User
- ``event``: LOGIN, LOGOUT, REFRESH, REFRESH_DENIED, AUTH_DENIED, REUSE_DETECTED
- ``reason``: success, invalid_token, token_reuse, rate_limit, expired, etc
- ``ip``: Client IP
- ``user_agent``: Browser user agent
- ``created_at``: Timestamp


Configuration
-------------

Default settings (override in settings.py)::

    DRF_CAS_JWT = {
        "RATE_LIMIT_ATTEMPTS": 5,          # Max login attempts
        "RATE_LIMIT_WINDOW": 60,           # Time window in seconds
        "REFRESH_TOKEN_ROTATE": True,      # Enable refresh rotation
        "AUDIT_LOG_ENABLED": True,         # Log all auth events
    }


Testing
-------

Run test suite::

    pytest drf_cas_jwt/tests.py -v

See ``docs/TESTS.md`` for detailed test documentation.
