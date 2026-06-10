"""
Fixtures e configuração para testes com pytest-django.
"""

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Token, TokenAuditLog, RefreshTokenFamily

User = get_user_model()


@pytest.fixture
def api_client():
    """Cliente HTTP para testes."""
    return APIClient()


@pytest.fixture
def user():
    """Usuário de teste."""
    return User.objects.create_user(
        username='testuser',
        email='test@example.com',
        password='testpass123'
    )


@pytest.fixture
def other_user():
    """Outro usuário para testes de isolamento."""
    return User.objects.create_user(
        username='otheruser',
        email='other@example.com',
        password='testpass123'
    )


@pytest.fixture
def refresh_token(user):
    """Refresh token para o usuário de teste."""
    refresh = RefreshToken.for_user(user)
    return refresh


@pytest.fixture
def access_token(refresh_token):
    """Access token derivado do refresh token."""
    return refresh_token.access_token


@pytest.fixture
def token_record(user, access_token):
    """Registro de token persistido no banco."""
    from .views import hash_token_hmac
    token_hash = hash_token_hmac(str(access_token))
    jti = str(access_token.get('jti', 'test-jti'))
    return Token.objects.create(
        user=user,
        token=token_hash,
        ip='127.0.0.1',
        jti=jti,
    )


@pytest.fixture
def refresh_token_family(user, refresh_token):
    """Família de refresh token registrada."""
    jti = str(refresh_token.get('jti', 'test-jti'))
    return RefreshTokenFamily.objects.create(
        jti=jti,
        user=user,
        ip='127.0.0.1',
    )


@pytest.fixture
def authenticated_request(api_client, access_token):
    """Client autenticado com access token."""
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(access_token)}')
    return api_client


@pytest.fixture
def audit_log_entry(user):
    """Entrada de audit log."""
    return TokenAuditLog.objects.create(
        user=user,
        event='LOGIN',
        reason='success',
        ip='127.0.0.1',
        user_agent='Mozilla/5.0',
    )
