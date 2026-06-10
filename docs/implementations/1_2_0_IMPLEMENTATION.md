# DRF CAS JWT 1.2.0 - Anomaly Detection + Email Alerts + CSRF Protection

## O que foi implementado

### ✅ 1. Model `SecurityAlertRecipient` (v1.1.0)

Novo model para configurar quem recebe alertas de segurança por email.

```python
# Exemplo: cadastrar destinatário via shell
from drf_cas_jwt.models import SecurityAlertRecipient
from django.contrib.auth import get_user_model

User = get_user_model()

# Vinculado a um usuário Django
admin_user = User.objects.get(username='admin')
SecurityAlertRecipient.objects.create(
    user=admin_user,
    email='admin@empresa.com',
    notify_on_reuse=True,
    notify_on_rate_limit=True,
    notify_on_login=True,
)

# Email externo (monitoramento/SIEM)
SecurityAlertRecipient.objects.create(
    email='seguranca@empresa.com',
    notify_on_reuse=True,
    notify_on_rate_limit=False,
    notify_on_login=False,
)
```

**Campos:**
- `user` (OneToOne, opcional) — usuário Django associado
- `email` (único) — email que receberá os alertas
- `is_active` — habilitar/desabilitar sem excluir
- `notify_on_reuse` (padrão: `True`) — alerta em replay de refresh token
- `notify_on_rate_limit` (padrão: `False`) — alerta em brute force
- `notify_on_login` (padrão: `False`) — alerta a cada login (para contas sensíveis)

### ✅ 2. Anomaly Scoring (`anomaly.py`) (v1.1.0)

Calcula score de risco (0.0–1.0) combinando múltiplos sinais para cada evento de autenticação.

**Sinais implementados:**

| Sinal | Score | Condição |
|-------|-------|----------|
| Mesmo IP | 0.0 | IP idêntico aos últimos acessos |
| Mesma subnet /24 | 0.3 | IP diferente mas mesma rede |
| IP completamente diferente | 0.8 | Subnet distinta dos últimos acessos |
| Horário normal (7h–23h) | +0.0 | UTC |
| Madrugada (0h–6h) | +0.2 | UTC |

**Score ≥ 0.7 = alto risco.**

```python
from drf_cas_jwt.anomaly import compute_anomaly_score

score = compute_anomaly_score(user, current_ip='203.0.113.55')
# {
#     'total': 0.8,
#     'ip_change': 0.8,
#     'off_hours': 0.0,
#     'is_high_risk': True,
# }
```

### ✅ 3. Email Alerts (`alerts.py`) (v1.1.0)

Três tipos de alerta disparados automaticamente por eventos críticos.

#### `send_reuse_alert(user, ip, user_agent, anomaly_score)`
Disparado em `REUSE_DETECTED`. Email inclui:
- Usuário afetado (username, ID, email)
- IP do atacante + User-Agent
- Score de anomalia (se calculado)
- Instruções de ação para o administrador

#### `send_rate_limit_alert(user, ip, action)`
Disparado quando rate limit é excedido (para destinatários com `notify_on_rate_limit=True`).

#### `send_login_alert(user, ip, user_agent)`
Disparado em cada login (para destinatários com `notify_on_login=True`).
Útil para monitorar admins e contas privilegiadas.

**Comportamento de falha:** erros de envio são logados (`logger.error`) mas nunca propagam exceção — o fluxo de autenticação continua normalmente.

### ✅ 4. Integração automática em `refresh_utils.py` (v1.1.0)

`detect_and_revoke_reuse()` agora executa automaticamente:
1. Revoga cadeia de tokens
2. Calcula `compute_anomaly_score()`
3. Chama `send_reuse_alert()` com score incluído

`CasLogin.successful_login()` agora chama `send_login_alert()` após cada login bem-sucedido.

### ✅ 5. Admin: `SecurityAlertRecipientAdmin` (v1.1.0)

Novo painel em `/admin/drf_cas_jwt/securityalertrecipient/`:
- Listar destinatários com status de cada notificação
- Filtros por `is_active`, tipo de notificação
- Busca por email ou username
- CRUD completo (único admin que permite adicionar/editar)

### ✅ 6. CSRF Protection (v1.2.0)

**Double-submit cookie + SameSite=Strict:**

- `CasLogin.successful_login()` chama `get_csrf_token(request)` ao emitir tokens → garante que o cookie `csrftoken` seja gerado para SPAs
- `CasTokenRefreshView.post()` valida o header `X-CSRFToken` via `CsrfViewMiddleware.process_view()` antes de processar qualquer refresh
- Retorna `403 FORBIDDEN` com mensagem clara se CSRF ausente ou inválido

**Camadas de proteção combinadas:**

| Camada | Mecanismo | Protege contra |
|--------|-----------|----------------|
| Cookie SameSite=Strict | Browser policy | CSRF cross-origin |
| Header X-CSRFToken | Double-submit | CSRF em subdomínios |
| HttpOnly cookie | Browser policy | XSS leitura do token |
| HMAC-SHA256 | Criptografia | Falsificação de token |

### ✅ 7. Versão bumped

`setup.cfg` e `setup.py` atualizados de `1.0.1` → `1.2.0`.

---

## Arquivos criados/modificados

| Arquivo | Mudança |
|---------|---------|
| `setup.cfg` | `version = 1.2.0` |
| `setup.py` | `version="1.2.0"` |
| `drf_cas_jwt/models.py` | ✨ Novo model `SecurityAlertRecipient` |
| `drf_cas_jwt/anomaly.py` | ✨ Novo: anomaly scoring por IP e horário |
| `drf_cas_jwt/alerts.py` | ✨ Novo: alertas de segurança por email |
| `drf_cas_jwt/refresh_utils.py` | 🔄 `detect_and_revoke_reuse` dispara anomaly + alert |
| `drf_cas_jwt/views.py` | 🔄 CSRF token na resposta de login; validação no refresh |
| `drf_cas_jwt/admin.py` | ✨ `SecurityAlertRecipientAdmin` adicionado |
| `drf_cas_jwt/migrations/0004_add_security_alert_recipient.py` | ✨ Migração do novo model |

---

## Como configurar

### 1. Aplicar migrations

```bash
python manage.py migrate drf_cas_jwt
```

### 2. Configurar email no settings.py

```python
# Usar variáveis do .env (ver .env.sample)
EMAIL_HOST = env('EMAIL_HOST', default='mail')
EMAIL_HOST_USER = env('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD', default='')
EMAIL_PORT = env.int('EMAIL_PORT', default=1025)
EMAIL_USE_TLS = env.bool('EMAIL_USE_TLS', default=False)
DEFAULT_FROM_EMAIL = 'noreply@seudominio.com'
```

### 3. Configurar cache para Redis (rate limiting)

```python
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": env('REDIS_URL', default='redis://redis:6379/0'),
        "TIMEOUT": env.int('REDIS_TIMEOUT', default=10800),
    }
}
```

### 4. Adicionar destinatários de alerta

Via admin (`/admin/drf_cas_jwt/securityalertrecipient/`) ou via shell:

```python
from drf_cas_jwt.models import SecurityAlertRecipient

# Equipe de segurança — só alertas críticos
SecurityAlertRecipient.objects.create(
    email='soc@empresa.com',
    notify_on_reuse=True,
    notify_on_rate_limit=True,
    notify_on_login=False,
)

# Conta de admin — todos os alertas
from django.contrib.auth import get_user_model
User = get_user_model()
SecurityAlertRecipient.objects.create(
    user=User.objects.get(username='admin'),
    email='admin@empresa.com',
    notify_on_reuse=True,
    notify_on_rate_limit=True,
    notify_on_login=True,
)
```

### 5. Middleware CSRF no settings.py

Garantir que `django.middleware.csrf.CsrfViewMiddleware` está na lista:

```python
MIDDLEWARE = [
    ...
    'django.middleware.csrf.CsrfViewMiddleware',
    ...
]
```

---

## Cliente (frontend) — CSRF no refresh

O cookie `csrftoken` é emitido automaticamente no login. O frontend deve incluir o header `X-CSRFToken` no `POST /auth/token/refresh/`:

```javascript
// Ler o csrftoken do cookie (não-HttpOnly, acessível por JS)
function getCsrfToken() {
    return document.cookie
        .split('; ')
        .find(row => row.startsWith('csrftoken='))
        ?.split('=')[1];
}

// Renovar access token
const response = await fetch('/auth/token/refresh/', {
    method: 'POST',
    credentials: 'include',
    headers: {
        'X-CSRFToken': getCsrfToken(),
    },
});
```

**Interceptor Axios com CSRF:**

```javascript
axios.interceptors.response.use(
    response => response,
    async error => {
        if (error.response?.status === 401 && !error.config._retry) {
            error.config._retry = true;
            try {
                const refreshResponse = await axios.post('/auth/token/refresh/', {}, {
                    withCredentials: true,
                    headers: { 'X-CSRFToken': getCsrfToken() },
                });
                const newToken = refreshResponse.data.access_token;
                sessionStorage.setItem('access_token', newToken);
                error.config.headers['Authorization'] = `Bearer ${newToken}`;
                return axios(error.config);
            } catch {
                window.location.href = '/auth/login';
            }
        }
        return Promise.reject(error);
    }
);
```

---

## Comportamento dos Alertas

### Email de Reuse Detectado

```
ALERTA DE SEGURANÇA — Reuse de Refresh Token Detectado

Usuário:    joao.silva (ID: 42)
Email:      joao@empresa.com
IP:         203.0.113.55
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...
Horário:    2026-06-08 03:15:00 UTC

Score de anomalia: 1.00 (IP: 0.8, Horário: 0.2)
Risco alto: Sim

O que aconteceu:
Um refresh token já rotacionado foi usado novamente...
```

### Email de Rate Limit

```
ALERTA DE SEGURANÇA — Rate Limit Excedido

Usuário: joao.silva (ID: 42)
IP:      203.0.113.55
Ação:    refresh
Horário: 2026-06-08 14:30:00 UTC
```

---

## Comportamento de Erros do Refresh

| Situação | Status | Mensagem |
|----------|--------|----------|
| Header X-CSRFToken ausente | 403 | "CSRF token inválido ou ausente." |
| Sem cookie `refresh_token` | 401 | "Refresh token não encontrado." |
| Token inválido/expirado | 401 | "Refresh token inválido ou expirado." |
| Reuse detectado | 401 | "Token inválido. Faça login novamente." |
| Token revogado | 401 | "Refresh token foi revogado." |
| Rate limit excedido | 429 | "Muitas tentativas. Tente novamente mais tarde." |

---

## Próximas fases (roadmap)

### v2.0.0
- [ ] Device secret com prova de posse (PKCE-like)
- [ ] E2E asymmetric binding (Ed25519)
- [ ] MFA obrigatório ao detectar anomalia ou reuse
- [ ] Sessões simultâneas configuráveis por usuário
- [ ] GeoIP para anomaly scoring (país/região)
