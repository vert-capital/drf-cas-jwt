# DRF CAS JWT 1.0.0 - Implementação de Segurança

## O que foi implementado

### ✅ 1. Modelos novos (models.py)
- **RefreshTokenFamily**: Rastreia jti de refresh tokens para detectar reuse e rotação
- **TokenAuditLog**: Log de eventos de autenticação (login, logout, refresh, denials)

### ✅ 2. Refresh rotation com reuse detection (refresh_utils.py)
- `create_refresh_token_family()` — registra novo refresh token
- `mark_as_rotated()` — marca token como rotacionado ao renovar
- `detect_and_revoke_reuse()` — detecta replay de token antigo e revoga cadeia inteira
- `is_token_valid()` — valida se token está ativo
- `log_token_event()` — registra eventos de autenticação

### ✅ 3. Tokens removidos de URL (views.py)
- Access token retornado em JSON response
- Refresh token armazenado em HttpOnly + Secure + SameSite cookie
- Cookies com configuração segura (não acessível via JS)

### ✅ 4. Logout seguro (views.py)
- Endpoint migrado para POST
- Validação do token
- Revogação da família de refresh
- Operação idempotente

### ✅ 5. HMAC-SHA256 em vez de MD5 (views.py + authentication.py)
- Todos os tokens hasheados com HMAC-SHA256 usando SECRET_KEY
- Impossível recriar hash sem secret do servidor

### ✅ 6. Rate limiting (rate_limit.py)
- Utilitários prontos para limitar tentativas de refresh/login
- Suporta lock temporal após limite excedido
- Integração com Django cache

### ✅ 7. Audit log (models.py)
- Todos os eventos registrados automaticamente
- Rastreabilidade de anomalias
- Base para detecção de padrões de ataque

### ✅ 8. Padrões de código
- isort aplicado ✓
- flake8 validado ✓
- Migrações criadas ✓

---

## Arquivos criados/modificados

| Arquivo | Mudança |
|---------|---------|
| `drf_cas_jwt/models.py` | ✨ Novos modelos (RefreshTokenFamily, TokenAuditLog) |
| `drf_cas_jwt/views.py` | 🔄 Reescrita completa: cookies, HMAC, logout POST |
| `drf_cas_jwt/authentication.py` | 🔄 HMAC-SHA256, simplificado sem Device |
| `drf_cas_jwt/refresh_utils.py` | ✨ Novo: refresh rotation + reuse detection |
| `drf_cas_jwt/rate_limit.py` | ✨ Novo: rate limiting utilities |
| `drf_cas_jwt/migrations/0002_...` | ✨ Remove Device, atualiza Token |
| `drf_cas_jwt/migrations/0003_...` | ✨ Adiciona RefreshTokenFamily + TokenAuditLog |

---

## Como usar

### 1. Aplicar migrations

```bash
python manage.py migrate drf_cas_jwt
```

### 2. Configurar settings.py

```python
DRF_CAS_JWT = {
    "HMAC_ALGORITHM": "sha256",
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
    "LOGOUT_REQUIRES_POST": True,
    "AUDIT_LOG_ENABLED": True,
    "RATE_LIMIT_REFRESH": {
        "attempts": 5,
        "window": 60,  # segundos
    },
}
```

### 3. Usar rate limiting (opcional)

```python
from drf_cas_jwt.rate_limit import check_rate_limit, increment_rate_limit, apply_strict_lock

# No seu endpoint de refresh
is_limited, remaining = check_rate_limit(
    user_id=request.user.id,
    ip=get_ipaddress(request),
    action='refresh',
    attempts=5,
    window=60
)

if is_limited:
    apply_strict_lock(request.user.id, get_ipaddress(request), lock_duration=900)
    return Response({"error": "Too many requests"}, status=429)

increment_rate_limit(request.user.id, get_ipaddress(request))
```

### 4. Cliente (frontend) - extrair tokens

**Login:**
```javascript
// POST /login (CAS login)
// Response headers incluem: Set-Cookie: refresh_token=...
const { access_token } = await response.json();

// Armazenar access token em memória ou sessionStorage
sessionStorage.setItem('access_token', access_token);
```

**Requests autenticados:**
```javascript
const token = sessionStorage.getItem('access_token');
fetch('/api/protected/', {
    headers: {
        'Authorization': `Bearer ${token}`,
    }
});
// Refresh token é enviado automaticamente como cookie
```

**Logout:**
```javascript
const token = sessionStorage.getItem('access_token');
await fetch('/logout', {
    method: 'POST',
    headers: {
        'Authorization': `Bearer ${token}`,
    }
});
sessionStorage.removeItem('access_token');
```

---

## Próximas fases (roadmap)

### v1.0.1 (rápido)
- [ ] Integração com SimpleJWT TokenRefreshView
- [ ] Detalhes de reuse em audit log
- [ ] Dashboard de token events

### v1.1.0
- [ ] Anomaly scoring (mudança de IP, país, hora)
- [ ] Email alerts em reuse detection
- [ ] Rate limit com Redis (high-traffic)

### v1.2.0
- [ ] Refresh token como bearer cookie separado
- [ ] CSRF protection melhorada

### v2.0.0
- [ ] Device secret (prova de posse)
- [ ] E2E asymmetric binding (Ed25519)
- [ ] MFA no reuse ou anomalia

---

## Security improvements resumo

| Feature | 0.2.0 | 1.0.0 | Impacto |
|---------|-------|-------|--------|
| Tokens em URL | ✓ | ✗ | Reduz vazamento em logs/referer |
| Hash | MD5 | HMAC-SHA256 | Impossível rainbow table |
| Refresh tracking | ✗ | ✓ (jti) | Detecta replay/reuse |
| Rate limit | ✗ | ✓ | Previne brute force |
| Audit log | ✗ | ✓ | Rastreabilidade + anomaly detection |
| Logout | GET | POST | Segue REST + idempotente |
| Device | ✓ (fraco) | ✗ | Removido, vai para 2.0 |

---

## Testes inclusos (próximos)

Os testes a seguir devem ser implementados para cobrir segurança:

- `test_refresh_rotation_creates_new_jti`
- `test_refresh_reuse_detected_revokes_chain`
- `test_old_refresh_token_rejected`
- `test_access_token_not_in_url`
- `test_refresh_token_in_secure_cookie`
- `test_logout_post_only`
- `test_logout_idempotent`
- `test_rate_limit_enforced`
- `test_audit_log_created_on_events`

---

## Notas técnicas

1. **Cache de rate limiting:** Django cache (Redis/Memcached) — configurar em settings
2. **Soft delete:** Token model usa soft delete (deleted_at), audit log persiste
3. **Atomicidade:** detect_and_revoke_reuse usa @transaction.atomic
4. **Segurança de cookies:** HttpOnly impede acesso via XSS; Secure força HTTPS; SameSite=Strict previne CSRF
