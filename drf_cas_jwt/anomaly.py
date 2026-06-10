"""
Detecção de anomalias em eventos de autenticação.

Analisa padrões suspeitos como mudança brusca de IP, horário incomum,
e calcula um score de risco para o evento.
"""

import ipaddress
from datetime import timedelta

from django.utils import timezone


def _get_ip_network(ip_str):
    """Retorna a rede /24 (IPv4) ou /48 (IPv6) do IP para comparação de subnet."""
    try:
        addr = ipaddress.ip_address(ip_str)
        if isinstance(addr, ipaddress.IPv4Address):
            return ipaddress.ip_network(f"{ip_str}/24", strict=False)
        else:
            return ipaddress.ip_network(f"{ip_str}/48", strict=False)
    except ValueError:
        return None


def score_ip_change(user, current_ip, lookback_hours=24):
    """
    Calcula score de anomalia baseado em mudança de IP.

    - Score 0.0: mesmo IP dos últimos acessos
    - Score 0.3: IP diferente mas mesma subnet /24
    - Score 0.6: IP de subnet diferente, mesmo país (não detectável sem GeoIP)
    - Score 0.8: IP completamente diferente dos últimos N acessos

    :param user: Django User
    :param current_ip: IP da requisição atual
    :param lookback_hours: Horas para considerar no histórico
    :return: float entre 0.0 e 1.0
    """
    from .models import TokenAuditLog

    cutoff = timezone.now() - timedelta(hours=lookback_hours)
    recent_ips = (
        TokenAuditLog.objects.filter(
            user=user,
            event__in=['LOGIN', 'REFRESH'],
            reason='success',
            created_at__gte=cutoff,
        )
        .exclude(ip=current_ip)
        .values_list('ip', flat=True)
        .distinct()
    )

    if not recent_ips:
        return 0.0

    current_net = _get_ip_network(current_ip)
    if current_net is None:
        return 0.0

    # Verificar se algum IP recente está na mesma subnet
    same_subnet = any(
        _get_ip_network(ip) == current_net
        for ip in recent_ips
        if ip
    )

    if same_subnet:
        return 0.3

    return 0.8


def score_off_hours(hour=None):
    """
    Score de anomalia por acesso em horário incomum (madrugada).

    - Score 0.0: horário comercial (7h–22h UTC)
    - Score 0.2: horário de madrugada (0h–6h UTC)

    :param hour: Hora UTC (0-23). Se None, usa hora atual.
    :return: float entre 0.0 e 0.2
    """
    if hour is None:
        hour = timezone.now().hour

    if 0 <= hour < 6:
        return 0.2
    return 0.0


def compute_anomaly_score(user, current_ip, lookback_hours=24):
    """
    Calcula score total de anomalia para um evento de autenticação.

    Combina múltiplos sinais. Score >= 0.7 é considerado alto risco.

    :param user: Django User
    :param current_ip: IP da requisição atual
    :param lookback_hours: Horas para histórico de IPs
    :return: dict com score total e detalhes dos sinais
    """
    ip_score = score_ip_change(user, current_ip, lookback_hours)
    off_hours_score = score_off_hours()

    total = round(ip_score + off_hours_score, 2)
    total = min(total, 1.0)  # Cap em 1.0

    return {
        'total': total,
        'ip_change': ip_score,
        'off_hours': off_hours_score,
        'is_high_risk': total >= 0.7,
    }
