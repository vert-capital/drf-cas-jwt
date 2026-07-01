import hmac
import hashlib

from rest_framework_simplejwt.settings import api_settings as simplejwt_settings
from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import Token


class CasJwtAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # Fallback: se não há Authorization header, tenta ler o access_token do cookie
        if not request.META.get(simplejwt_settings.AUTH_HEADER_NAME) and 'access_token' in request.COOKIES:
            token = request.COOKIES['access_token']
            header_types = simplejwt_settings.AUTH_HEADER_TYPES
            if len(header_types) == 1:
                header_type = header_types[0]
            elif len(header_types) < 1:
                header_type = "Bearer"
            else:
                header_type = header_types[0]  # Default para o primeiro tipo definido

            request.META[simplejwt_settings.AUTH_HEADER_NAME] = f'{header_type} {token}'

        authenticate = super(JWTAuthentication, self).authenticate(request)
        if not authenticate:
            return None
        user = authenticate[0]
        validated_token = authenticate[1]

        # Hash do token com HMAC-SHA256
        from django.conf import settings
        server_secret = settings.SECRET_KEY
        token_hash = hmac.new(
            server_secret.encode(),
            str(validated_token).encode(),
            hashlib.sha256
        ).hexdigest()

        # Validar que existe registro de token persistido
        token_record = Token.objects.filter(
            user=user,
            token=token_hash
        ).first()

        if not token_record:
            # Token não encontrado, pode ter sido revogado ou expirado
            return None

        return user, validated_token
