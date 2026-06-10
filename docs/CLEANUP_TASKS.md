# Limpeza de Tokens - Tasks Agendadas

Documentação para configurar limpeza automática de tokens expirados via Django-RQ ou Django-Q2.

## Por que limpar tokens expirados?

- **Banco de dados mais limpo**: Remove registros inúteis (soft-deleted há >30 dias)
- **Melhor performance**: Menos registros = queries mais rápidas
- **Conformidade**: Políticas de retenção de dados (LGPD, GDPR)
- **Segurança**: Remove tokens revogados por reuse detection

## Tasks Disponíveis

### 1. `cleanup_expired_tokens()` (Completo)
Remove TUDO que está expirado:
- Tokens soft-deletados há >30 dias
- RefreshTokenFamily revogadas há >30 dias
- TokenAuditLog com >90 dias

**Uso**: Limpeza semanal ou mensal

```python
from drf_cas_jwt.tasks import cleanup_expired_tokens

result = cleanup_expired_tokens()
# {
#     'deleted_tokens': 150,
#     'deleted_refresh_families': 200,
#     'deleted_audit_logs': 500,
#     'timestamp': '2026-06-08T10:30:00Z'
# }
```

### 2. `cleanup_soft_deleted_tokens()`
Remove APENAS tokens soft-deletados:

```python
from drf_cas_jwt.tasks import cleanup_soft_deleted_tokens

result = cleanup_soft_deleted_tokens()
# {'deleted_tokens': 150, 'timestamp': '...'}
```

### 3. `cleanup_revoked_refresh_tokens()`
Remove APENAS RefreshTokenFamily revogadas:

```python
from drf_cas_jwt.tasks import cleanup_revoked_refresh_tokens

result = cleanup_revoked_refresh_tokens()
# {'deleted_refresh_tokens': 200, 'timestamp': '...'}
```

### 4. `cleanup_old_audit_logs()`
Remove APENAS TokenAuditLog antigos:

```python
from drf_cas_jwt.tasks import cleanup_old_audit_logs

result = cleanup_old_audit_logs()
# {'deleted_audit_logs': 500, 'timestamp': '...'}
```

---

## Configuração Django-RQ (Recomendado)

**Instalação**:
```bash
pip install django-rq redis
```

**settings.py**:
```python
RQ_QUEUES = {
    'default': {
        'HOST': 'localhost',
        'PORT': 6379,
        'DB': 0,
    },
    'maintenance': {
        'HOST': 'localhost',
        'PORT': 6379,
        'DB': 0,
    }
}

# Configuração de limpeza
DRF_CAS_JWT_CLEANUP_DAYS = 30
DRF_CAS_JWT_AUDIT_RETENTION_DAYS = 90
```

**Agendar com Cron (via `django-crontab`)**:

Instalar:
```bash
pip install django-crontab
```

**settings.py**:
```python
INSTALLED_APPS = [
    ...,
    'django_rq',
    'django_crontab',
]

CRONJOBS = [
    # Executar limpeza todos os dias às 2:00 AM
    ('0 2 * * *', 'drf_cas_jwt.tasks.cleanup_expired_tokens', '>> /var/log/drf_cas_jwt_cleanup.log'),
    
    # Ou separado por frequência:
    ('0 2 * * 0', 'drf_cas_jwt.tasks.cleanup_expired_tokens'),       # Semanal
    ('0 3 * * *', 'drf_cas_jwt.tasks.cleanup_old_audit_logs'),       # Diário
]
```

**Comando**:
```bash
# Instalar crontab
python manage.py crontab add

# Remover
python manage.py crontab remove

# Listar
python manage.py crontab show
```

---

## Configuração Django-Q2

**Instalação**:
```bash
pip install django-q2
```

**settings.py**:
```python
INSTALLED_APPS = [
    ...,
    'django_q',
]

Q_CLUSTER = {
    'name': 'myproject',
    'workers': 4,
    'timeout': 500,
    'retry': 600,
    'catch_up': False,
    'orm': 'default',  # Usar Django ORM
    
    # Schedules
    'schedule_attempts': 0,
}

# Configuração de limpeza
DRF_CAS_JWT_CLEANUP_DAYS = 30
DRF_CAS_JWT_AUDIT_RETENTION_DAYS = 90
```

**Arquivo: `tasks.py` no seu projeto (exemplo)**:
```python
# myproject/tasks.py
def schedule_token_cleanup():
    from django_q.models import Schedule
    from django_q.tasks import schedule
    
    # Limpeza completa diariamente às 2:00 AM
    schedule(
        'drf_cas_jwt.tasks.cleanup_expired_tokens',
        schedule_type='daily',
        repeat=1,
        next_run=timezone.now().replace(hour=2, minute=0, second=0)
    )
    
    # Audit logs diariamente às 3:00 AM
    schedule(
        'drf_cas_jwt.tasks.cleanup_old_audit_logs',
        schedule_type='daily',
        repeat=1,
        next_run=timezone.now().replace(hour=3, minute=0, second=0)
    )
```

**Comando**:
```bash
# Iniciar cluster
python manage.py qcluster

# Monitor em tempo real
python manage.py qmonitor

# Listar schedules
python manage.py qdel -s
```

---

## Configuração Django-Q2 (Alternativa: via `django_admin`)**

**Painel Admin**:
```python
# myproject/urls.py
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('django-q/', include('django_q.urls')),  # Painel de agendamento
]
```

Acessar `http://localhost:8000/admin/django_q/schedule/` para criar schedules via UI.

---

## Executar Manualmente

**Django Shell**:
```bash
python manage.py shell
```

```python
from drf_cas_jwt.tasks import cleanup_expired_tokens

# Executar manualmente
result = cleanup_expired_tokens()
print(result)
# {'deleted_tokens': 150, 'deleted_refresh_families': 200, ...}
```

**Management Command** (Opcional):

Criar `drf_cas_jwt/management/commands/cleanup_tokens.py`:
```python
from django.core.management.base import BaseCommand
from drf_cas_jwt.tasks import cleanup_expired_tokens

class Command(BaseCommand):
    help = 'Cleanup expired tokens'

    def handle(self, *args, **options):
        result = cleanup_expired_tokens()
        self.stdout.write(
            self.style.SUCCESS(f"Cleaned: {result}")
        )
```

Executar:
```bash
python manage.py cleanup_tokens
```

---

## Comparação: Django-RQ vs Django-Q2

| Feature | Django-RQ | Django-Q2 |
|---------|-----------|-----------|
| **Fila** | Redis | Redis/ORM/Disque |
| **Scheduling** | crontab + django-crontab | Built-in |
| **Admin** | Básico | Dashboard completo |
| **Performance** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Curva aprendizado** | Fácil | Médio |
| **Recomendado** | ✅ | ✅ |

---

## Recomendação de Frequência

```yaml
cleanup_expired_tokens():          # Completo
  Frequência: Semanal (segunda-feira 2:00 AM)
  
cleanup_soft_deleted_tokens():     # Tokens
  Frequência: 2x por semana
  
cleanup_revoked_refresh_tokens():  # Refresh tokens
  Frequência: Diária
  
cleanup_old_audit_logs():          # Audit
  Frequência: Semanal (retenção 90 dias)
```

---

## Monitoramento e Logs

**Logging em settings.py**:
```python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': '/var/log/drf_cas_jwt.log',
        },
    },
    'loggers': {
        'drf_cas_jwt': {
            'handlers': ['file'],
            'level': 'INFO',
        },
    },
}
```

**Adicionar logging nas tasks**:
```python
import logging

logger = logging.getLogger('drf_cas_jwt')

def cleanup_expired_tokens():
    logger.info("Iniciando limpeza de tokens...")
    # ...
    logger.info(f"Limpeza completa: {result}")
    return result
```

---

## Troubleshooting

### Redis não conecta
```bash
# Testar conexão Redis
redis-cli ping
# PONG

# Ou via Python
import redis
r = redis.Redis(host='localhost', port=6379, db=0)
r.ping()  # True
```

### Tasks não executam
```bash
# Django-RQ: Verificar worker
python manage.py rqworker

# Django-Q2: Verificar cluster
python manage.py qcluster

# Verificar logs
tail -f /var/log/drf_cas_jwt.log
```

### Schedules não aparecem
```python
# Django-Q2: Sincronizar ORM
python manage.py migrate django_q

# Listar schedules
from django_q.models import Schedule
Schedule.objects.all()
```

---

## Próximas Melhorias (v1.1.0+)

- [ ] Email notificação ao detectar reuse (antes de revogar)
- [ ] Métricas Prometheus para tokens/refresh/audit
- [ ] Dashboard de saúde (Redis, DB, tasks rodando)
- [ ] Backup automático de audit logs antes de deletar
- [ ] API para forçar cleanup manual (/api/admin/cleanup/)
