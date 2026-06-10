import hmac
import hashlib

from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.settings import api_settings as simplejwt_settings


from .models import Token


class CasJwtAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # Fallback: se não há Authorization header, tenta ler o access_token do cookie
        if not request.META.get(simplejwt_settings.AUTH_HEADER_NAME) and 'access_token' in request.COOKIES:
            token = request.COOKIES['access_token']
            request.META[simplejwt_settings.AUTH_HEADER_NAME] = f'Bearer {token}'

        authenticate = super().authenticate(request)
        if not authenticate:
            raise AuthenticationFailed(
                _("Token Not Valid"),
                code="bad_authorization_header",
            )
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
            raise AuthenticationFailed(
                _("Token Not Valid"),
                code="bad_authorization_header",
            )

        return user, validated_token
