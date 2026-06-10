"""
Celery/RQ/Q2 tasks para limpeza e manutenção de tokens.
"""

from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from .models import Token, TokenAuditLog, RefreshTokenFamily


def cleanup_expired_tokens():
    """
    Remove tokens soft-deletados há mais de 30 dias.
    Remove RefreshTokenFamily revogadas há mais de 30 dias.
    Remove TokenAuditLog com mais de 90 dias.

    Executar diariamente via Django-RQ ou Django-Q2.

    :return: dict com contagem de registros deletados
    """
    cleanup_days = getattr(settings, 'DRF_CAS_JWT_CLEANUP_DAYS', 30)
    audit_days = getattr(settings, 'DRF_CAS_JWT_AUDIT_RETENTION_DAYS', 90)

    cutoff_date = timezone.now() - timedelta(days=cleanup_days)
    audit_cutoff = timezone.now() - timedelta(days=audit_days)

    # 1. Hard-delete de tokens soft-deletados
    deleted_tokens = Token.objects.using('default').raw(
        f"SELECT id FROM drf_cas_jwt_token WHERE deleted_at IS NOT NULL "
        f"AND deleted_at < '{cutoff_date.isoformat()}'"
    )
    deleted_token_ids = [token.id for token in deleted_tokens]
    token_count, _ = Token.objects.filter(id__in=deleted_token_ids).delete()

    # 2. Hard-delete de RefreshTokenFamily revogadas
    revoked_families = RefreshTokenFamily.objects.using('default').raw(
        f"SELECT id FROM drf_cas_jwt_refreshtokenfamily WHERE revoked_at IS NOT NULL "
        f"AND revoked_at < '{cutoff_date.isoformat()}'"
    )
    revoked_family_ids = [family.id for family in revoked_families]
    family_count, _ = RefreshTokenFamily.objects.filter(
        id__in=revoked_family_ids
    ).delete()

    # 3. Delete de TokenAuditLog antigos
    audit_count, _ = TokenAuditLog.objects.filter(
        created_at__lt=audit_cutoff
    ).delete()

    return {
        'deleted_tokens': token_count,
        'deleted_refresh_families': family_count,
        'deleted_audit_logs': audit_count,
        'timestamp': timezone.now().isoformat(),
    }


def cleanup_revoked_refresh_tokens():
    """
    Remove APENAS RefreshTokenFamily revogadas há mais de N dias.
    Útil para limpeza frequente sem afetar tokens ativos.

    :return: dict com contagem de registros deletados
    """
    cleanup_days = getattr(settings, 'DRF_CAS_JWT_CLEANUP_DAYS', 30)
    cutoff_date = timezone.now() - timedelta(days=cleanup_days)

    deleted_count, _ = RefreshTokenFamily.objects.filter(
        revoked_at__isnull=False,
        revoked_at__lt=cutoff_date
    ).delete()

    return {
        'deleted_refresh_tokens': deleted_count,
        'timestamp': timezone.now().isoformat(),
    }


def cleanup_soft_deleted_tokens():
    """
    Remove APENAS tokens soft-deletados há mais de N dias.
    Útil para limpeza frequente sem afetar refresh tokens.

    :return: dict com contagem de registros deletados
    """
    cleanup_days = getattr(settings, 'DRF_CAS_JWT_CLEANUP_DAYS', 30)
    cutoff_date = timezone.now() - timedelta(days=cleanup_days)

    deleted_count, _ = Token.objects.filter(
        deleted_at__isnull=False,
        deleted_at__lt=cutoff_date
    ).delete()

    return {
        'deleted_tokens': deleted_count,
        'timestamp': timezone.now().isoformat(),
    }


def cleanup_old_audit_logs():
    """
    Remove TokenAuditLog com mais de N dias (retenção configurável).
    Útil para manter banco de dados limpo sem perder logs recentes.

    :return: dict com contagem de registros deletados
    """
    audit_days = getattr(settings, 'DRF_CAS_JWT_AUDIT_RETENTION_DAYS', 90)
    cutoff_date = timezone.now() - timedelta(days=audit_days)

    deleted_count, _ = TokenAuditLog.objects.filter(
        created_at__lt=cutoff_date
    ).delete()

    return {
        'deleted_audit_logs': deleted_count,
        'timestamp': timezone.now().isoformat(),
    }
