"""
Alertas de segurança por email para eventos críticos de autenticação.

Usa as configurações EMAIL_* do settings.py e envia para todos os
SecurityAlertRecipient ativos com a notificação habilitada.
"""

import logging

from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail

logger = logging.getLogger('drf_cas_jwt')


def _get_active_recipients(notify_field):
    """
    Retorna lista de emails dos destinatários ativos com determinada notificação habilitada.

    :param notify_field: Nome do campo BooleanField em SecurityAlertRecipient
    :return: list de emails (str)
    """
    from .models import SecurityAlertRecipient

    return list(
        SecurityAlertRecipient.objects.filter(
            is_active=True,
            **{notify_field: True},
        ).values_list('email', flat=True)
    )


def _send_alert(subject, body, recipient_list):
    """
    Envia email para a lista de destinatários. Falhas são logadas mas não propagadas.

    :param subject: Assunto do email
    :param body: Corpo do email (texto)
    :param recipient_list: Lista de emails
    """
    if not recipient_list:
        return

    from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@localhost')

    try:
        send_mail(
            subject=subject,
            message=body,
            from_email=from_email,
            recipient_list=recipient_list,
            fail_silently=False,
        )
        logger.info("Alerta de segurança enviado para %d destinatário(s)", len(recipient_list))
    except Exception as exc:
        logger.error("Falha ao enviar alerta de segurança: %s", exc)


def send_reuse_alert(user, ip, user_agent='', anomaly_score=None):
    """
    Envia alerta de REUSE_DETECTED para destinatários configurados.

    :param user: Django User afetado
    :param ip: IP de origem do ataque de replay
    :param user_agent: User-Agent do cliente suspeito
    :param anomaly_score: dict retornado por compute_anomaly_score (opcional)
    """
    recipients = _get_active_recipients('notify_on_reuse')
    if not recipients:
        return

    timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    risk_info = ""
    if anomaly_score:
        risk_info = (
            f"\nScore de anomalia: {anomaly_score['total']:.2f}"
            f" (IP: {anomaly_score['ip_change']}, Horário: {anomaly_score['off_hours']})"
            f"\nRisco alto: {'Sim' if anomaly_score['is_high_risk'] else 'Não'}"
        )

    subject = f"[DRF-CAS-JWT] ALERTA: Reuse de token detectado — {user.email}"
    body = f"""
ALERTA DE SEGURANÇA — Reuse de Refresh Token Detectado

Usuário:    {user.id}
Email:      {user.email}
IP:         {ip}
User-Agent: {user_agent or 'N/A'}
Horário:    {timestamp}
{risk_info}

O que aconteceu:
Um refresh token já rotacionado foi usado novamente. Isso indica que o token
pode ter sido capturado (ex.: man-in-the-middle, vazamento). Como precaução,
TODOS os refresh tokens ativos deste usuário foram revogados imediatamente.

Ação recomendada:
- Verificar logs do usuário no painel de auditoria
- Confirmar com o usuário se reconhece o IP acima
- Considerar forçar reset de senha se o IP for desconhecido

Este email foi gerado automaticamente pelo drf-cas-jwt.
""".strip()

    _send_alert(subject, body, recipients)


def send_rate_limit_alert(user, ip, action='refresh'):
    """
    Envia alerta quando rate limit é excedido repetidamente.

    :param user: Django User
    :param ip: IP de origem
    :param action: Ação que excedeu o limite (refresh, login)
    """
    recipients = _get_active_recipients('notify_on_rate_limit')
    if not recipients:
        return

    timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    subject = f"[DRF-CAS-JWT] ALERTA: Rate limit excedido — {user.email}"
    body = f"""
ALERTA DE SEGURANÇA — Rate Limit Excedido

Usuário: {user.id}
IP:      {ip}
Ação:    {action}
Horário: {timestamp}

O usuário excedeu o número máximo de tentativas permitidas.
Isso pode indicar uma tentativa de brute force.

Este email foi gerado automaticamente pelo drf-cas-jwt.
""".strip()

    _send_alert(subject, body, recipients)


def send_login_alert(user, ip, user_agent=''):
    """
    Envia alerta de login para destinatários configurados com notify_on_login=True.
    Útil para monitorar contas sensíveis (admins, super-users).

    :param user: Django User
    :param ip: IP de origem
    :param user_agent: User-Agent do cliente
    """
    recipients = _get_active_recipients('notify_on_login')
    if not recipients:
        return

    timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    subject = f"[DRF-CAS-JWT] Login detectado — {user.email}"
    body = f"""
Notificação de Login

Usuário:    {user.id}
Email:      {user.email}
IP:         {ip}
User-Agent: {user_agent or 'N/A'}
Horário:    {timestamp}

Este email foi gerado automaticamente pelo drf-cas-jwt.
""".strip()

    _send_alert(subject, body, recipients)
