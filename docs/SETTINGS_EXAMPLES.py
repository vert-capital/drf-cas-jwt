"""
Exemplos de configuração para Django-RQ e Django-Q2.

Copie a configuração apropriada para seu settings.py.
"""

# ============================================================================
# EXEMPLO 1: Django-RQ + django-crontab
# ============================================================================

DJANGO_RQ_EXAMPLE_SETTINGS = """
# settings.py

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'rest_framework',
    'rest_framework_simplejwt',
    'drf_cas_jwt',

    # Agendamento
    'django_rq',
    'django_crontab',
]

# Redis para RQ
RQ_QUEUES = {
    'default': {
        'HOST': 'localhost',
        'PORT': 6379,
        'DB': 0,
    },
    'maintenance': {
        'HOST': 'localhost',
        'PORT': 6379,
        'DB': 1,
    }
}

# Configuração de limpeza (30 dias para soft-deleted, 90 para audit)
DRF_CAS_JWT_CLEANUP_DAYS = 30
DRF_CAS_JWT_AUDIT_RETENTION_DAYS = 90

# Crontab: Agendar limpeza
CRONJOBS = [
    # Limpeza completa diariamente às 2:00 AM
    ('0 2 * * *', 'drf_cas_jwt.tasks.cleanup_expired_tokens', '>> /var/log/drf_cas_jwt_cleanup.log'),

    # OU separado por tipo:
    ('0 2 * * 0', 'drf_cas_jwt.tasks.cleanup_expired_tokens'),       # Semanal (domingo)
    ('0 3 * * *', 'drf_cas_jwt.tasks.cleanup_old_audit_logs'),       # Diário
    ('30 2 * * *', 'drf_cas_jwt.tasks.cleanup_revoked_refresh_tokens'),  # Diário 2:30 AM
]
"""

# ============================================================================
# EXEMPLO 2: Django-Q2
# ============================================================================

DJANGO_Q2_EXAMPLE_SETTINGS = """
# settings.py

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'rest_framework',
    'rest_framework_simplejwt',
    'drf_cas_jwt',

    # Agendamento
    'django_q',
]

# Configuração Django-Q2
Q_CLUSTER = {
    'name': 'drf_cas_jwt',
    'workers': 4,
    'timeout': 500,
    'retry': 600,
    'catch_up': False,
    'orm': 'default',  # Usar Django ORM
    'ack_failures': True,
    'poll': 500,
}

# Configuração de limpeza (30 dias para soft-deleted, 90 para audit)
DRF_CAS_JWT_CLEANUP_DAYS = 30
DRF_CAS_JWT_AUDIT_RETENTION_DAYS = 90
"""

# ============================================================================
# EXEMPLO 3: Celery (Alternativa)
# ============================================================================

CELERY_EXAMPLE_SETTINGS = """
# settings.py

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'rest_framework',
    'rest_framework_simplejwt',
    'drf_cas_jwt',

    # Task queue
    'celery',
]

# Celery
CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/1'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'UTC'

# Celery Beat Schedule
from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    'cleanup-expired-tokens-daily': {
        'task': 'drf_cas_jwt.tasks.cleanup_expired_tokens',
        'schedule': crontab(hour=2, minute=0),  # 2:00 AM
    },
    'cleanup-audit-logs-daily': {
        'task': 'drf_cas_jwt.tasks.cleanup_old_audit_logs',
        'schedule': crontab(hour=3, minute=0),  # 3:00 AM
    },
}

# Configuração de limpeza
DRF_CAS_JWT_CLEANUP_DAYS = 30
DRF_CAS_JWT_AUDIT_RETENTION_DAYS = 90
"""

# ============================================================================
# EXEMPLO 4: Celery Tasks (celery.py)
# ============================================================================

CELERY_TASKS_EXAMPLE = """
# myproject/celery.py

import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')

app = Celery('myproject')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

# Tasks
@app.task(bind=True)
def cleanup_tokens_task(self):
    from drf_cas_jwt.tasks import cleanup_expired_tokens
    return cleanup_expired_tokens()
"""

# ============================================================================
# EXEMPLO 5: Logging (Todos)
# ============================================================================

LOGGING_EXAMPLE_SETTINGS = """
# settings.py

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/drf_cas_jwt.log',
            'maxBytes': 1024 * 1024 * 10,  # 10MB
            'backupCount': 5,
            'formatter': 'verbose',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'drf_cas_jwt': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': False,
        },
        'django_rq': {
            'handlers': ['file'],
            'level': 'INFO',
        },
        'django_q': {
            'handlers': ['file'],
            'level': 'INFO',
        },
    },
}
"""
