"""
Testes para cleanup tasks.
"""

from datetime import timedelta

import pytest
from django.test import TestCase
from django.utils import timezone

from .tasks import (
    cleanup_expired_tokens,
    cleanup_old_audit_logs,
    cleanup_soft_deleted_tokens,
    cleanup_revoked_refresh_tokens,
)
from .models import Token, TokenAuditLog, RefreshTokenFamily


@pytest.mark.django_db
class TestCleanupTasks(TestCase):
    """Testes para tasks de limpeza de tokens."""

    def setUp(self):
        """Criar dados de teste."""
        from django.contrib.auth.models import User

        self.user = User.objects.create_user(username='testuser', password='pass123')
        self.now = timezone.now()

    def test_cleanup_soft_deleted_tokens_old(self):
        """Remover tokens soft-deletados há >30 dias."""
        # Token soft-deleted há 40 dias
        old_token = Token.objects.create(
            user=self.user,
            token='token_old_hash_1234567890',
            ip='192.168.1.1',
            jti='jti-old'
        )
        old_token.delete()  # Soft delete
        old_token.deleted_at = self.now - timedelta(days=40)
        old_token.save()

        # Token soft-deleted há 10 dias (não deve remover)
        recent_token = Token.objects.create(
            user=self.user,
            token='token_recent_hash_1234567890',
            ip='192.168.1.1',
            jti='jti-recent'
        )
        recent_token.delete()  # Soft delete
        recent_token.deleted_at = self.now - timedelta(days=10)
        recent_token.save()

        # Executar cleanup
        result = cleanup_soft_deleted_tokens()

        # Verificar que token antigo foi deletado
        assert result['deleted_tokens'] == 1
        assert not Token.objects.filter(jti='jti-old').exists()

        # Verificar que token recente ainda existe
        assert Token.admin_objects.filter(jti='jti-recent').exists()

    def test_cleanup_revoked_refresh_tokens_old(self):
        """Remover RefreshTokenFamily revogadas há >30 dias."""
        # Refresh revogado há 40 dias
        old_family = RefreshTokenFamily.objects.create(
            jti='jti-old-revoked',
            user=self.user,
            ip='192.168.1.1'
        )
        old_family.revoked_at = self.now - timedelta(days=40)
        old_family.save()

        # Refresh revogado há 10 dias (não deve remover)
        recent_family = RefreshTokenFamily.objects.create(
            jti='jti-recent-revoked',
            user=self.user,
            ip='192.168.1.1'
        )
        recent_family.revoked_at = self.now - timedelta(days=10)
        recent_family.save()

        # Refresh ativo (não deve remover)
        RefreshTokenFamily.objects.create(
            jti='jti-active',
            user=self.user,
            ip='192.168.1.1'
        )

        # Executar cleanup
        result = cleanup_revoked_refresh_tokens()

        # Verificar que apenas o antigo foi deletado
        assert result['deleted_refresh_tokens'] == 1
        assert not RefreshTokenFamily.objects.filter(jti='jti-old-revoked').exists()

        # Verificar que recent ainda existe
        assert RefreshTokenFamily.objects.filter(jti='jti-recent-revoked').exists()

        # Verificar que ativo ainda existe
        assert RefreshTokenFamily.objects.filter(jti='jti-active').exists()

    def test_cleanup_old_audit_logs(self):
        """Remover TokenAuditLog com >90 dias."""
        # Audit log antigo (>90 dias)
        old_log = TokenAuditLog.objects.create(
            user=self.user,
            event='LOGIN',
            reason='success',
            ip='192.168.1.1'
        )
        old_log.created_at = self.now - timedelta(days=100)
        old_log.save()

        # Audit log recente (<90 dias, não remover)
        recent_log = TokenAuditLog.objects.create(
            user=self.user,
            event='LOGOUT',
            reason='success',
            ip='192.168.1.1'
        )
        recent_log.created_at = self.now - timedelta(days=30)
        recent_log.save()

        # Executar cleanup
        result = cleanup_old_audit_logs()

        # Verificar que apenas o antigo foi deletado
        assert result['deleted_audit_logs'] == 1
        assert not TokenAuditLog.objects.filter(id=old_log.id).exists()

        # Verificar que recente ainda existe
        assert TokenAuditLog.objects.filter(id=recent_log.id).exists()

    def test_cleanup_expired_tokens_complete(self):
        """Teste completo: remover TUDO que está expirado."""
        # 1. Token antigo
        old_token = Token.objects.create(
            user=self.user,
            token='token_old',
            ip='192.168.1.1',
            jti='jti-token-old'
        )
        old_token.delete()
        old_token.deleted_at = self.now - timedelta(days=40)
        old_token.save()

        # 2. RefreshTokenFamily revogada antiga
        old_family = RefreshTokenFamily.objects.create(
            jti='jti-family-old',
            user=self.user,
            ip='192.168.1.1'
        )
        old_family.revoked_at = self.now - timedelta(days=40)
        old_family.save()

        # 3. Audit log antigo
        old_audit = TokenAuditLog.objects.create(
            user=self.user,
            event='LOGIN',
            reason='success',
            ip='192.168.1.1'
        )
        old_audit.created_at = self.now - timedelta(days=100)
        old_audit.save()

        # Executar cleanup
        result = cleanup_expired_tokens()

        # Verificar contagem
        assert result['deleted_tokens'] >= 1
        assert result['deleted_refresh_families'] >= 1
        assert result['deleted_audit_logs'] >= 1

    def test_cleanup_preserves_active_tokens(self):
        """Limpeza não deve remover tokens ativos."""
        # Token ativo
        Token.objects.create(
            user=self.user,
            token='token_active',
            ip='192.168.1.1',
            jti='jti-active'
        )

        # RefreshTokenFamily ativa
        RefreshTokenFamily.objects.create(
            jti='jti-active-family',
            user=self.user,
            ip='192.168.1.1'
        )

        # Audit log recente
        recent_audit = TokenAuditLog.objects.create(
            user=self.user,
            event='LOGIN',
            reason='success',
            ip='192.168.1.1'
        )

        # Executar cleanup
        cleanup_expired_tokens()

        # Verificar que tudo ativo ainda existe
        assert Token.objects.filter(jti='jti-active').exists()
        assert RefreshTokenFamily.objects.filter(jti='jti-active-family').exists()
        assert TokenAuditLog.objects.filter(id=recent_audit.id).exists()

    def test_cleanup_returns_dict_with_timestamp(self):
        """Verificar que cleanup retorna dict com timestamp."""
        result = cleanup_expired_tokens()

        assert isinstance(result, dict)
        assert 'timestamp' in result
        assert 'deleted_tokens' in result
        assert 'deleted_refresh_families' in result
        assert 'deleted_audit_logs' in result
