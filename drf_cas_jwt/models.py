from uuid import uuid4

from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from .managers import SoftDeleteManager, SoftDeleteManagerAdmin

User = get_user_model()


class Token(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4)
    jti = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        null=True,
        blank=True,
        help_text="JWT ID (jti claim) para rastreamento de refresh tokens"
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    ip = models.GenericIPAddressField()
    token = models.CharField(max_length=64, verbose_name="Token JWT (HMAC-SHA256)")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True, db_index=True)

    objects = SoftDeleteManager()
    admin_objects = SoftDeleteManagerAdmin()

    class Meta:
        indexes = [
            models.Index(fields=['user', 'deleted_at']),
            models.Index(fields=['jti', 'deleted_at']),
        ]

    def clean(self):
        if not self.user:
            raise ValidationError("O campo 'user' é obrigatório para criar um Token.")

    def delete(self, hard_delete=False, *args, **kwargs):
        if hard_delete:
            return super().delete(*args, **kwargs)

        self.deleted_at = timezone.now()
        self.save()


class RefreshTokenFamily(models.Model):
    """
    Rastreia família de refresh tokens para detecção de reuse e rotação.
    Cada refresh token gera um jti único; ao renovar, um novo jti é criado.
    Se um jti antigo reaparece, a cadeia inteira é revogada.
    """

    jti = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text="JWT ID (jti claim) do refresh token"
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    parent_jti = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="jti do refresh anterior (se foi rotacionado)"
    )
    ip = models.GenericIPAddressField()
    created_at = models.DateTimeField(auto_now_add=True)
    rotated_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Data quando esse jti foi rotacionado para um novo"
    )
    revoked_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Data da revogação por reuse ou outro motivo"
    )

    class Meta:
        indexes = [
            models.Index(fields=['user', 'revoked_at']),
            models.Index(fields=['jti', 'revoked_at']),
        ]

    def __str__(self):
        return f"RefreshTokenFamily({self.user_id}, {self.jti[:8]}...)"


class TokenAuditLog(models.Model):
    """
    Log de eventos de autenticação para auditoria e detecção de anomalias.
    """

    EVENT_CHOICES = (
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('REFRESH', 'Token Refresh'),
        ('REFRESH_DENIED', 'Refresh Negado'),
        ('AUTH_DENIED', 'Autenticação Negada'),
        ('REUSE_DETECTED', 'Reuse de Refresh Detectado'),
    )

    REASON_CHOICES = (
        ('invalid_token', 'Token Inválido'),
        ('token_reuse', 'Reuse de Token'),
        ('rate_limit', 'Rate Limit Excedido'),
        ('expired', 'Token Expirado'),
        ('device_mismatch', 'Device Não Corresponde'),
        ('success', 'Sucesso'),
    )

    id = models.UUIDField(primary_key=True, default=uuid4)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    event = models.CharField(max_length=20, choices=EVENT_CHOICES)
    reason = models.CharField(
        max_length=30,
        choices=REASON_CHOICES,
        default='success'
    )
    ip = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['event', 'created_at']),
        ]

    def __str__(self):
        return f"{self.user_id} - {self.event} ({self.reason})"


class SecurityAlertRecipient(models.Model):
    """
    Configura quais usuários/emails recebem alertas de segurança.

    Pode ser vinculado a um User existente (campo user) ou ser um email
    externo de monitoramento (somente campo email).
    """

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='alert_recipient',
        help_text="Usuário Django associado (opcional)"
    )
    email = models.EmailField(
        unique=True,
        help_text="Email que receberá os alertas"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Desabilitar sem excluir o registro"
    )

    # Preferências de notificação
    notify_on_reuse = models.BooleanField(
        default=True,
        help_text="Alertar quando reuse de refresh token for detectado"
    )
    notify_on_rate_limit = models.BooleanField(
        default=False,
        help_text="Alertar quando rate limit for excedido por um usuário"
    )
    notify_on_login = models.BooleanField(
        default=False,
        help_text="Alertar a cada login (útil para contas sensíveis)"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Destinatário de Alertas de Segurança"
        verbose_name_plural = "Destinatários de Alertas de Segurança"

    def __str__(self):
        if self.user:
            return f"AlertRecipient({self.user.email} → {self.email})"
        return f"AlertRecipient({self.email})"
