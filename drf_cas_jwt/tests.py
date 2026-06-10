"""
Testes de segurança para DRF CAS JWT 1.0.0
"""

import hmac
import hashlib

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory

from .views import get_ipaddress, hash_token_hmac
from .models import Token, TokenAuditLog, RefreshTokenFamily
from .rate_limit import (
    check_rate_limit,
    reset_rate_limit,
    increment_rate_limit,
)
from .refresh_utils import (
    is_token_valid,
    log_token_event,
    mark_as_rotated,
    revoke_token_family,
    detect_and_revoke_reuse,
    create_refresh_token_family,
)

User = get_user_model()


@pytest.mark.django_db
class TestTokenHashing:
    """Testes de hash de token com HMAC-SHA256."""

    def test_token_hash_uses_hmac_sha256(self):
        """Verifica que tokens são hasheados com HMAC-SHA256."""
        token = 'test_token_value'
        token_hash = hash_token_hmac(token)

        # Recompor hash manualmente para validar
        expected = hmac.new(
            settings.SECRET_KEY.encode(),
            token.encode(),
            hashlib.sha256
        ).hexdigest()

        assert token_hash == expected

    def test_token_hash_not_md5(self):
        """Verifica que NÃO é MD5 (mais de 32 chars)."""
        token = 'test_token'
        token_hash = hash_token_hmac(token)

        # SHA256 hex = 64 chars, MD5 = 32 chars
        assert len(token_hash) == 64

    def test_token_hash_changes_with_different_secret(self, settings):
        """Verifica que hash muda se secret mudar."""
        token = 'test_token'
        hash1 = hash_token_hmac(token)

        # Simular mudança de secret
        original_secret = settings.SECRET_KEY
        settings.SECRET_KEY = 'different_secret_key'

        hash2 = hash_token_hmac(token)

        settings.SECRET_KEY = original_secret

        assert hash1 != hash2

    def test_token_hash_deterministic(self):
        """Verifica que hash é determinístico para mesmo token."""
        token = 'test_token'
        hash1 = hash_token_hmac(token)
        hash2 = hash_token_hmac(token)

        assert hash1 == hash2


@pytest.mark.django_db
class TestRefreshRotation:
    """Testes de rotação de refresh tokens."""

    def test_create_refresh_token_family(self):
        """Cria nova família de refresh token."""
        user = User.objects.create_user(username='testuser', password='test123')
        jti = 'test-jti-123'
        family = create_refresh_token_family(
            jti=jti,
            user=user,
            ip='192.168.1.100',
        )

        assert family.jti == jti
        assert family.user == user
        assert family.ip == '192.168.1.100'
        assert family.rotated_at is None
        assert family.revoked_at is None

    def test_mark_as_rotated(self):
        """Marca token como rotacionado."""
        user = User.objects.create_user(username='testuser', password='test123')
        family = RefreshTokenFamily.objects.create(
            jti='old-jti',
            user=user,
            ip='192.168.1.100',
        )

        mark_as_rotated('old-jti')

        family.refresh_from_db()
        assert family.rotated_at is not None

    def test_refresh_rotation_with_parent(self):
        """Rotação de token rastreia parent jti."""
        user = User.objects.create_user(username='testuser', password='test123')
        parent_jti = 'parent-jti-123'
        new_jti = 'new-jti-456'

        # Criar token pai
        create_refresh_token_family(
            jti=parent_jti,
            user=user,
            ip='192.168.1.100',
        )
        mark_as_rotated(parent_jti)

        # Rotacionar para novo token
        new_family = create_refresh_token_family(
            jti=new_jti,
            user=user,
            ip='192.168.1.100',
            parent_jti=parent_jti,
        )

        assert new_family.parent_jti == parent_jti


@pytest.mark.django_db
class TestReuseDetection:
    """Testes de detecção de reuse de refresh tokens."""

    def test_detect_reuse_when_rotated_token_reappears(self):
        """Detecta reuse quando token rotacionado reaparece."""
        user = User.objects.create_user(username='testuser', password='test123')
        jti = 'reused-jti'

        # Criar token original
        family = RefreshTokenFamily.objects.create(
            jti=jti,
            user=user,
            ip='192.168.1.100',
        )

        # Rotacionar (marcar como rotated)
        mark_as_rotated(jti)
        family.refresh_from_db()
        assert family.rotated_at is not None

        # Tentar usar token antigo novamente (reuse)
        is_reuse, returned_family = detect_and_revoke_reuse(jti, user)

        assert is_reuse is True
        assert returned_family.jti == jti

    def test_reuse_revokes_entire_chain(self):
        """Reuse detectado revoga toda cadeia de tokens."""
        user = User.objects.create_user(username='testuser', password='test123')

        # Criar 3 tokens em rotação
        jti1 = 'jti-1'
        jti2 = 'jti-2'
        jti3 = 'jti-3'

        family1 = RefreshTokenFamily.objects.create(
            jti=jti1,
            user=user,
            ip='192.168.1.100'
        )
        family2 = RefreshTokenFamily.objects.create(
            jti=jti2,
            user=user,
            ip='192.168.1.100'
        )
        family3 = RefreshTokenFamily.objects.create(
            jti=jti3,
            user=user,
            ip='192.168.1.100'
        )

        # Marcar como rotacionados
        mark_as_rotated(jti1)
        mark_as_rotated(jti2)

        # Detectar reuse do jti1
        is_reuse, _ = detect_and_revoke_reuse(jti1, user)
        assert is_reuse is True

        # Verificar que todas as famílias foram revogadas
        family1.refresh_from_db()
        family2.refresh_from_db()
        family3.refresh_from_db()

        assert family1.revoked_at is not None
        assert family2.revoked_at is not None
        assert family3.revoked_at is not None

    def test_no_reuse_for_new_token(self):
        """Novo token não é detectado como reuse."""
        user = User.objects.create_user(username='testuser', password='test123')
        jti = 'new-jti'

        # Criar token (sem marcar como rotado)
        RefreshTokenFamily.objects.create(
            jti=jti,
            user=user,
            ip='192.168.1.100'
        )

        # Tentar usar (não é reuse)
        is_reuse, family = detect_and_revoke_reuse(jti, user)

        assert is_reuse is False
        assert family.revoked_at is None


@pytest.mark.django_db
class TestTokenValidation:
    """Testes de validação de tokens."""

    def test_token_valid_when_active(self):
        """Token é válido quando ativo."""
        user = User.objects.create_user(username='testuser', password='test123')
        jti = 'valid-jti'
        RefreshTokenFamily.objects.create(
            jti=jti,
            user=user,
            ip='192.168.1.100'
        )

        assert is_token_valid(jti) is True

    def test_token_invalid_when_revoked(self):
        """Token é inválido quando revogado."""
        jti = 'revoked-jti'
        revoke_token_family(jti)

        # Token não existe = inválido
        assert is_token_valid(jti) is False

    def test_token_invalid_when_not_exists(self):
        """Token inexistente é inválido."""
        assert is_token_valid('nonexistent-jti') is False


@pytest.mark.django_db
class TestAuditLog:
    """Testes de audit log."""

    def test_audit_log_created_on_login(self):
        """Log criado no login."""
        user = User.objects.create_user(username='testuser', password='test123')
        log_token_event(
            user=user,
            event='LOGIN',
            reason='success',
            ip='192.168.1.100',
            user_agent='Mozilla/5.0',
        )

        log = TokenAuditLog.objects.get(user=user, event='LOGIN')
        assert log.reason == 'success'
        assert log.ip == '192.168.1.100'

    def test_audit_log_created_on_logout(self):
        """Log criado no logout."""
        user = User.objects.create_user(username='testuser', password='test123')
        log_token_event(
            user=user,
            event='LOGOUT',
            reason='success',
            ip='192.168.1.100',
        )

        log = TokenAuditLog.objects.get(user=user, event='LOGOUT')
        assert log.event == 'LOGOUT'

    def test_audit_log_created_on_reuse_detected(self):
        """Log criado quando reuse é detectado."""
        user = User.objects.create_user(username='testuser', password='test123')
        jti = 'reused-jti'
        RefreshTokenFamily.objects.create(
            jti=jti,
            user=user,
            ip='192.168.1.100'
        )
        mark_as_rotated(jti)

        detect_and_revoke_reuse(jti, user)

        log = TokenAuditLog.objects.filter(user=user, event='REUSE_DETECTED')
        assert log.exists()

    def test_audit_log_queryable_by_user_and_date(self):
        """Audit log é consultável por usuário e data."""
        user = User.objects.create_user(username='testuser', password='test123')
        log_token_event(
            user=user,
            event='LOGIN',
            reason='success',
            ip='192.168.1.100'
        )
        log_token_event(
            user=user,
            event='LOGOUT',
            reason='success',
            ip='192.168.1.100'
        )

        logs = TokenAuditLog.objects.filter(user=user)
        assert logs.count() == 2


@pytest.mark.django_db
class TestRateLimit:
    """Testes de rate limiting."""

    def test_check_rate_limit_not_exceeded(self):
        """Rate limit não excedido retorna False."""
        user_id = 1
        ip = '192.168.1.100'

        is_limited, remaining = check_rate_limit(user_id, ip, attempts=5, window=60)

        assert is_limited is False
        assert remaining == 4  # 5 - 1 (tentativa atual)

    def test_increment_rate_limit(self):
        """Incrementar contador de rate limit."""
        user_id = 1
        ip = '192.168.1.100'

        for i in range(5):
            increment_rate_limit(user_id, ip, window=60)

        is_limited, remaining = check_rate_limit(user_id, ip, attempts=5, window=60)
        assert is_limited is True

    def test_rate_limit_exceeded(self):
        """Rate limit excedido retorna True."""
        user_id = 1
        ip = '192.168.1.100'

        # Incrementar 5 vezes
        for _ in range(5):
            increment_rate_limit(user_id, ip, window=60)

        is_limited, remaining = check_rate_limit(user_id, ip, attempts=5, window=60)
        assert is_limited is True
        assert remaining == 0

    def test_reset_rate_limit(self):
        """Reset de rate limit."""
        user_id = 1
        ip = '192.168.1.100'

        increment_rate_limit(user_id, ip, window=60)
        reset_rate_limit(user_id, ip)

        is_limited, remaining = check_rate_limit(user_id, ip, attempts=5, window=60)
        assert is_limited is False


@pytest.mark.django_db
class TestLogoutIdempotent:
    """Testes para garantir logout idempotente."""

    def test_logout_twice_succeeds(self):
        """Fazer logout 2x sucessivamente deve funcionar."""
        user = User.objects.create_user(username='testuser', password='test123')
        token = Token.objects.create(
            user=user,
            token='test_hash',
            ip='192.168.1.100',
            jti='test-jti'
        )

        # Primeiro logout
        revoke_token_family(token.jti or 'test-jti')
        token.delete()

        # Segundo logout (não deve falhar)
        revoke_token_family(token.jti or 'test-jti')


@pytest.mark.django_db
class TestIpAddressExtraction:
    """Testes de extração de IP."""

    def test_get_ipaddress_from_remote_addr(self):
        """Extrair IP de REMOTE_ADDR."""
        factory = APIRequestFactory()
        request = factory.get('/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'

        ip = get_ipaddress(request)
        assert ip == '127.0.0.1'

    def test_get_ipaddress_from_x_forwarded_for(self):
        """Extrair IP de X-Forwarded-For (com proxy)."""
        factory = APIRequestFactory()
        request = factory.get('/', HTTP_X_FORWARDED_FOR='203.0.113.1, 192.168.1.1')

        ip = get_ipaddress(request)
        assert ip == '203.0.113.1'  # Primeiro IP é o original
