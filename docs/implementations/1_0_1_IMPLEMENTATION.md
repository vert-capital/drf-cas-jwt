# DRF CAS JWT 1.0.1 - Token Refresh Endpoint + Admin

## O que foi implementado

### ✅ 1. Endpoint de renovação de tokens (`CasTokenRefreshView`)

Novo endpoint `POST /auth/token/refresh/` que implementa rotação segura de refresh tokens:

1. Lê `refresh_token` do cookie HttpOnly (enviado automaticamente pelo navegador)
2. Valida assinatura e expiração via SimpleJWT
3. Aplica **rate limiting** por usuário + IP
4. Executa **detecção de reuse** via `detect_and_revoke_reuse()`
5. Verifica que o token ainda está ativo (não foi revogado por logout)
6. Rotaciona: marca old_jti como `rotated_at`, gera novo RefreshToken
7. Cria novo `RefreshTokenFamily` com `parent_jti` rastreado
8. Atualiza registro `Token` com novo jti + hash do novo access_token
9. Loga evento `REFRESH` com IP e user_agent
10. Retorna `access_token` em JSON + novo cookie HttpOnly com `refresh_token`

### ✅ 2. IP e user_agent no log de reuse detection

`detect_and_revoke_reuse()` agora aceita `ip` e `user_agent` opcionais.
O evento `REUSE_DETECTED` passa esses dados para o `TokenAuditLog`, permitindo rastrear
o IP de quem tentou usar o token capturado.

### ✅ 3. Admin dashboard atualizado

`admin.py` reescrito para v1.0.1:
- **Removido** `DeviceAdmin` (Device model foi removido na v1.0.0)
- **Atualizado** `TokenAdmin`: campos relevantes (user, ip, jti, deleted_at), search e filtros
- **Adicionado** `RefreshTokenFamilyAdmin`: visualizar rotações e revogações
- **Adicionado** `TokenAuditLogAdmin`: audit trail completo com filtros por evento, razão e data

### ✅ 4. Versão bumped

`setup.cfg` e `setup.py` atualizados de `1.0.0` → `1.0.1`

---

## Arquivos modificados

| Arquivo | Mudança |
|---------|---------|
| `setup.cfg` | `version = 1.0.1` |
| `setup.py` | `version="1.0.1"` |
| `drf_cas_jwt/views.py` | ✨ Adicionado `CasTokenRefreshView`; imports limpos |
| `drf_cas_jwt/refresh_utils.py` | 🔄 `detect_and_revoke_reuse` aceita `ip` e `user_agent` |
| `drf_cas_jwt/admin.py` | 🔄 Removido Device; adicionado RefreshTokenFamily + TokenAuditLog |

---

## Como usar

### 1. Registrar URL

```python
# urls.py
from drf_cas_jwt.views import CasLogin, CasLogout, CasTokenRefreshView

urlpatterns = [
    path("auth/login", CasLogin.as_view(), name="cas-jwt-login"),
    path("auth/logout", CasLogout.as_view(), name="cas-jwt-logout"),
    path("auth/token/refresh/", CasTokenRefreshView.as_view(), name="cas-jwt-refresh"),
]
```

### 2. Cliente (frontend)

**Renovar access token expirado:**
```javascript
// Refresh token enviado automaticamente via cookie
const response = await fetch('/auth/token/refresh/', {
    method: 'POST',
    credentials: 'include',  // Necessário para enviar cookies
});

if (response.ok) {
    const data = await response.json();
    sessionStorage.setItem('access_token', data.access_token);
} else if (response.status === 401) {
    // Token revogado ou reuse detectado - redirecionar para login
    window.location.href = '/auth/login';
} else if (response.status === 429) {
    // Rate limit - exibir mensagem de aguarde
    console.error('Muitas tentativas. Tente novamente em breve.');
}
```

**Interceptor automático (Axios):**
```javascript
// Interceptor para renovar token quando access_token expirar
axios.interceptors.response.use(
    response => response,
    async error => {
        if (error.response?.status === 401 && !error.config._retry) {
            error.config._retry = true;
            try {
                const refreshResponse = await axios.post('/auth/token/refresh/', {}, {
                    withCredentials: true
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

## Admin Dashboard

Acessar em `http://localhost:8000/admin/`:

### Token
- Visualizar tokens ativos e soft-deletados
- Filtrar por `deleted_at` (ativo vs. deletado)
- Buscar por usuário, IP ou jti

### RefreshTokenFamily
- Monitorar rotações de refresh tokens
- Identificar tokens revogados (`revoked_at` preenchido)
- Rastrear cadeia de rotações via `parent_jti`

### TokenAuditLog
- Audit trail completo de LOGIN, LOGOUT, REFRESH, REUSE_DETECTED
- Filtrar por evento, razão, data
- Buscar por usuário, IP ou user_agent
- Hierarquia de datas para navegação temporal

---

## Comportamento de Erros

| Situação | Status | Mensagem |
|----------|--------|----------|
| Sem cookie `refresh_token` | 401 | "Refresh token não encontrado." |
| Token inválido/expirado | 401 | "Refresh token inválido ou expirado." |
| Reuse detectado (token capturado) | 401 | "Token inválido. Faça login novamente." |
| Token revogado manualmente (logout) | 401 | "Refresh token foi revogado." |
| Rate limit excedido | 429 | "Muitas tentativas. Tente novamente mais tarde." |

---

## Audit Log Melhorado

O evento `REUSE_DETECTED` agora inclui IP e user_agent do **atacante**:

```python
# Antes (v1.0.0): IP vazio no log de reuse
TokenAuditLog(
    event='REUSE_DETECTED',
    reason='token_reuse',
    ip='',  # Sem info
    user_agent='',
)

# Depois (v1.0.1): IP do cliente que tentou o replay
TokenAuditLog(
    event='REUSE_DETECTED',
    reason='token_reuse',
    ip='203.0.113.55',  # IP do atacante!
    user_agent='Mozilla/5.0 ...',
)
```

Isso permite investigar de onde veio o ataque de replay.

---

## Próximas fases (roadmap)

### v1.1.0
- [ ] Anomaly scoring (mudança brusca de IP, geolocalização, horário)
- [ ] Email alerts em REUSE_DETECTED
- [ ] Rate limit com Redis (high-traffic)

### v1.2.0
- [ ] CSRF protection melhorada

### v2.0.0
- [ ] Device secret (prova de posse)
- [ ] E2E asymmetric binding (Ed25519)
- [ ] MFA no reuse ou anomalia
