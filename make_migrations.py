import django
from django.conf import settings
from django.core.management import call_command

# 1. Configuração mínima do banco de dados (falso) e registro do seu app
settings.configure(
    INSTALLED_APPS=[
        "django.contrib.contenttypes",  # Obrigatório para o funcionamento do 'auth'
        "django.contrib.auth",
        "drf_cas_jwt",  # Substitua pelo nome da pasta do seu app
    ],
    DATABASES={
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": ":memory:",  # Usa banco em memória apenas para carregar o Django
        }
    },
)

# 2. Inicializa o Django
django.setup()

# 3. Executa o comando de migração focando apenas no seu app
if __name__ == "__main__":
    call_command("makemigrations", "drf_cas_jwt")
