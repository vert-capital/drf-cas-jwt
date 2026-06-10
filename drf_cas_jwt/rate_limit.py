"""
Rate limiting utilities para prevenir brute force em refresh tokens e login.
"""

from django.core.cache import cache


def get_rate_limit_key(user_id, ip, action):
    """Gera chave de cache para rate limiting."""
    return f"ratelimit:{action}:{user_id}:{ip}"


def check_rate_limit(user_id, ip, action='refresh', attempts=5, window=60):
    """
    Verifica se o limite de tentativas foi excedido.

    :param user_id: ID do usuário
    :param ip: IP address
    :param action: Tipo de ação (refresh, login)
    :param attempts: Número máximo de tentativas
    :param window: Janela de tempo em segundos
    :return: tuple (is_limited: bool, remaining: int)
    """
    key = get_rate_limit_key(user_id, ip, action)
    current = cache.get(key, 0)

    if current >= attempts:
        return True, 0

    remaining = attempts - current - 1
    return False, remaining


def increment_rate_limit(user_id, ip, action='refresh', window=60):
    """
    Incrementa o contador de tentativas.

    :param user_id: ID do usuário
    :param ip: IP address
    :param action: Tipo de ação (refresh, login)
    :param window: Janela de tempo em segundos
    """
    key = get_rate_limit_key(user_id, ip, action)
    cache.set(key, cache.get(key, 0) + 1, window)


def reset_rate_limit(user_id, ip, action='refresh'):
    """
    Reseta o contador de tentativas.

    :param user_id: ID do usuário
    :param ip: IP address
    :param action: Tipo de ação
    """
    key = get_rate_limit_key(user_id, ip, action)
    cache.delete(key)


def is_rate_limited_strict(user_id, ip, action='refresh'):
    """
    Verifica se o usuário está em modo de rate limit estrito
    (bloqueado por N minutos após exceder limite).

    :param user_id: ID do usuário
    :param ip: IP address
    :param action: Tipo de ação
    :return: tuple (is_locked: bool, unlock_time_seconds: int)
    """
    lock_key = f"ratelimit_locked:{action}:{user_id}:{ip}"
    remaining = cache.ttl(lock_key) if hasattr(cache, 'ttl') else -1

    if remaining > 0:
        return True, remaining

    return False, 0


def apply_strict_lock(user_id, ip, action='refresh', lock_duration=900):
    """
    Aplica lock de rate limit por N segundos (padrão 15 min).

    :param user_id: ID do usuário
    :param ip: IP address
    :param action: Tipo de ação
    :param lock_duration: Duração do lock em segundos
    """
    lock_key = f"ratelimit_locked:{action}:{user_id}:{ip}"
    cache.set(lock_key, True, lock_duration)
