import hmac
import hashlib

from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.settings import api_settings as simplejwt_settings
from rest_framework_simplejwt.exceptions import AuthenticationFailed
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
        if "access_token" not in request.COOKIES and getattr(request._request, 'user', None):
            # Get the session-based user from the underlying HttpRequest object
            user = getattr(request._request, 'user', None)

            # Unauthenticated, CSRF validation not required
            if not user or not user.is_active:
                return None

            self.enforce_csrf(request)

            # CSRF passed with authenticated user
            return (user, None)

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

    def enforce_csrf(self, request):
        """
        Enforce CSRF validation for session based authentication.
        """
        from rest_framework import exceptions
        from rest_framework.authentication import CSRFCheck

        def dummy_get_response(request):  # pragma: no cover
            return None

        check = CSRFCheck(dummy_get_response)
        # populates request.META['CSRF_COOKIE'], which is used in process_view()
        check.process_request(request)
        reason = check.process_view(request, None, (), {})
        if reason:
            # CSRF failed, bail with explicit error message
            raise exceptions.PermissionDenied('CSRF Failed: %s' % reason)
