"""
Utilitários para gerenciamento de refresh tokens com rotação e detecção de reuse.
"""

from django.db import transaction
from django.utils import timezone

from .models import TokenAuditLog, RefreshTokenFamily


def create_refresh_token_family(jti, user, ip, parent_jti=None):
    """
    Cria um novo registro de família de refresh token.

    :param jti: JWT ID do novo refresh token
    :param user: Django User
    :param ip: IP address do cliente
    :param parent_jti: jti do token anterior (se rotacionado)
    :return: RefreshTokenFamily instance
    """
    return RefreshTokenFamily.objects.create(
        jti=jti,
        user=user,
        ip=ip,
        parent_jti=parent_jti,
    )


def mark_as_rotated(old_jti):
    """
    Marca um refresh token como rotacionado.

    :param old_jti: JWT ID do token antigo
    """
    try:
        token_family = RefreshTokenFamily.objects.get(jti=old_jti)
        token_family.rotated_at = timezone.now()
        token_family.save()
    except RefreshTokenFamily.DoesNotExist:
        pass


@transaction.atomic
def revoke_token_family(jti):
    """
    Revoga toda a família conectada a um jti (ancestrais e descendentes).

    A revogação fica restrita ao mesmo usuário do jti informado.

    :param jti: JWT ID do refresh token
    :return: int quantidade de registros atualizados
    """
    try:
        token_family = RefreshTokenFamily.objects.get(jti=jti)
    except RefreshTokenFamily.DoesNotExist:
        return 0

    user = token_family.user
    to_visit = {jti}
    visited = set()

    # Percorre o grafo da família via parent_jti para incluir toda a cadeia.
    while to_visit:
        current = to_visit.pop()
        if current in visited:
            continue
        visited.add(current)

        parent = (
            RefreshTokenFamily.objects
            .filter(user=user, jti=current)
            .values_list('parent_jti', flat=True)
            .first()
        )
        if parent:
            to_visit.add(parent)

        children = RefreshTokenFamily.objects.filter(
            user=user,
            parent_jti=current,
        ).values_list('jti', flat=True)
        to_visit.update(children)

    return RefreshTokenFamily.objects.filter(
        user=user,
        jti__in=visited,
        revoked_at__isnull=True,
    ).update(revoked_at=timezone.now())


@transaction.atomic
def detect_and_revoke_reuse(jti, user, ip='', user_agent=''):
    """
    Detecta se um refresh token foi reutilizado (replay) e revoga a cadeia inteira.

    Se um jti que foi marcado como 'rotated' reaparece, significa que foi capturado
    e está sendo reutilizado. Neste caso, revogamos toda a cadeia de tokens do usuário.

    :param jti: JWT ID do refresh token
    :param user: Django User
    :param ip: IP address (para audit log e alerta)
    :param user_agent: User-Agent (para audit log e alerta)
    :return: tuple (is_reuse: bool, family: RefreshTokenFamily or None)
    """
    from .alerts import send_reuse_alert
    from .anomaly import compute_anomaly_score

    try:
        token_family = RefreshTokenFamily.objects.get(jti=jti, user=user)

        # Verificar se esse jti já foi rotacionado
        if token_family.rotated_at is not None:
            # REUSE DETECTADO!
            # Revogar toda a cadeia de tokens deste usuário
            RefreshTokenFamily.objects.filter(
                user=user,
                revoked_at__isnull=True
            ).update(revoked_at=timezone.now())

            # Log do evento com detalhes de IP e user_agent
            log_token_event(
                user=user,
                event='REUSE_DETECTED',
                reason='token_reuse',
                ip=ip,
                user_agent=user_agent,
            )

            # Calcular score de anomalia e enviar alerta por email
            anomaly_score = compute_anomaly_score(user, ip) if ip else None
            send_reuse_alert(
                user=user,
                ip=ip,
                user_agent=user_agent,
                anomaly_score=anomaly_score,
            )

            return True, token_family

        # Não é reuse, retornar com sucesso
        return False, token_family

    except RefreshTokenFamily.DoesNotExist:
        # jti não encontrado = novo token, sem reuse
        return False, None


def is_token_valid(jti):
    """
    Verifica se um refresh token é válido (existe e não foi revogado).

    :param jti: JWT ID
    :return: bool
    """
    try:
        RefreshTokenFamily.objects.get(
            jti=jti,
            revoked_at__isnull=True
        )
        return True
    except RefreshTokenFamily.DoesNotExist:
        return False


def log_token_event(user, event, reason, ip, user_agent=''):
    """
    Registra um evento de autenticação no audit log.

    :param user: Django User
    :param event: Tipo de evento (LOGIN, LOGOUT, REFRESH, etc)
    :param reason: Razão (success, invalid_token, rate_limit, etc)
    :param ip: IP address
    :param user_agent: User-Agent string
    """
    TokenAuditLog.objects.create(
        user=user,
        event=event,
        reason=reason,
        ip=ip,
        user_agent=user_agent,
    )
