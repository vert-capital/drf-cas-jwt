# Testes - DRF CAS JWT 1.0.0

Testes automatizados de segurança usando pytest + pytest-django.

## Instalação de dependências

```bash
pip install pytest pytest-django
```

Ou usar arquivo `requirements-dev.txt` se existir:

```bash
pip install -r requirements-dev.txt
```

## Estrutura de testes

- **conftest.py** — Fixtures reutilizáveis (usuários, tokens, clients autenticados)
- **tests.py** — Testes de segurança agrupados em classes

## Executar todos os testes

```bash
# Rodar todos os testes
pytest

# Com verbose
pytest -v

# Com coverage
pytest --cov=drf_cas_jwt --cov-report=html

# Apenas testes específicos
pytest drf_cas_jwt/tests.py::TestTokenHashing
```

## Categorias de testes

### ✅ TestTokenHashing (4 testes)
Valida que tokens são hasheados com HMAC-SHA256:
- `test_token_hash_uses_hmac_sha256` — Verifica algoritmo correto
- `test_token_hash_not_md5` — Valida que NÃO é MD5
- `test_token_hash_changes_with_different_secret` — Testa dependência de SECRET_KEY
- `test_token_hash_deterministic` — Testa determinismo

### ✅ TestRefreshRotation (3 testes)
Testa rotação de refresh tokens:
- `test_create_refresh_token_family` — Criar novo registro
- `test_mark_as_rotated` — Marcar como rotacionado
- `test_refresh_rotation_with_parent` — Rastrear parent jti

### ✅ TestReuseDetection (3 testes)
Detecção de replay de tokens:
- `test_detect_reuse_when_rotated_token_reappears` — Detecta reuse
- `test_reuse_revokes_entire_chain` — Revoga cadeia inteira
- `test_no_reuse_for_new_token` — Novo token não é reuse

### ✅ TestTokenValidation (3 testes)
Validação de tokens ativos/revogados:
- `test_token_valid_when_active` — Token ativo é válido
- `test_token_invalid_when_revoked` — Token revogado é inválido
- `test_token_invalid_when_not_exists` — Token inexistente é inválido

### ✅ TestAuditLog (4 testes)
Testa rastreabilidade de eventos:
- `test_audit_log_created_on_login` — Log criado no login
- `test_audit_log_created_on_logout` — Log criado no logout
- `test_audit_log_created_on_reuse_detected` — Log criado em reuse
- `test_audit_log_queryable_by_user_and_date` — Consulta por usuário/data

### ✅ TestRateLimit (5 testes)
Testa rate limiting:
- `test_check_rate_limit_not_exceeded` — Limite não excedido
- `test_increment_rate_limit` — Incrementa contador
- `test_rate_limit_exceeded` — Detecta quando excedido
- `test_reset_rate_limit` — Reset de contador
- Nota: `apply_strict_lock` removido da v1.0 por simplicidade

### ✅ TestLogoutIdempotent (1 teste)
- `test_logout_twice_succeeds` — Logout 2x funciona

### ✅ TestIpAddressExtraction (2 testes)
Extração correta de IP:
- `test_get_ipaddress_from_remote_addr` — IP direto
- `test_get_ipaddress_from_x_forwarded_for` — IP com proxy

---

## Total: 25 testes

### Cobertura

| Área | Cobertura | Testes |
|------|-----------|--------|
| HMAC-SHA256 | 100% | 4 |
| Refresh rotation | 100% | 3 |
| Reuse detection | 100% | 3 |
| Token validation | 100% | 3 |
| Audit log | 100% | 4 |
| Rate limiting | 80% | 5 |
| Logout | 100% | 1 |
| IP extraction | 100% | 2 |

---

## Rodar com Coverage

```bash
pip install pytest-cov

# Rodar com coverage
pytest --cov=drf_cas_jwt --cov-report=term-missing

# Gerar relatório HTML
pytest --cov=drf_cas_jwt --cov-report=html
# Abrir htmlcov/index.html
```

## Integração CI/CD

Adicionar ao `.github/workflows/tests.yml`:

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: 3.9
      - run: pip install -r requirements.txt pytest pytest-django
      - run: pytest --cov=drf_cas_jwt
```

## Troubleshooting

### `ModuleNotFoundError: No module named 'django'`
```bash
pip install django djangorestframework djangorestframework-simplejwt
```

### `DJANGO_SETTINGS_MODULE not defined`
```bash
# Criar settings_test.py na raiz ou usar:
export DJANGO_SETTINGS_MODULE=settings
pytest
```

### `django.core.exceptions.ImproperlyConfigured`
Garantir que `INSTALLED_APPS` inclui:
```python
INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'drf_cas_jwt',
]
```

---

## Próximos passos

- [ ] Testes de integração com CAS (mock)
- [ ] Testes de endpoint de login/logout (full HTTP)
- [ ] Testes de autenticação com JWT token inválido
- [ ] Testes de cookies HttpOnly com navegador (Selenium)
- [ ] Testes de anomaly detection (mudança brusca de IP/país)

---

## Rodar teste específico

```bash
# Apenas HMAC-SHA256
pytest drf_cas_jwt/tests.py::TestTokenHashing

# Apenas reuse detection
pytest drf_cas_jwt/tests.py::TestReuseDetection -v

# Parar na primeira falha
pytest -x

# Debugar teste
pytest --pdb drf_cas_jwt/tests.py::TestTokenValidation::test_token_valid_when_active
```
