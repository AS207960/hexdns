from rest_framework import authentication
from rest_framework import exceptions
from django.contrib.auth import get_user_model
import django_keycloak_auth.clients
import keycloak
import dataclasses


class BearerAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return None
        if not token.startswith("Bearer "):
            return None

        token = token[len("Bearer "):]

        try:
            claims = django_keycloak_auth.clients.verify_token(token)
        except keycloak.exceptions.KeycloakClientError:
            raise exceptions.AuthenticationFailed('Invalid token')

        user = get_user_model().objects.filter(username=claims["sub"]).first()
        if not user:
            raise exceptions.AuthenticationFailed('Nonexistent user')

        return user, OAuthToken(token=token)


class SessionAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        user = getattr(request._request, 'user', None)
        if not user or not user.is_active:
            return None
        self.enforce_csrf(request)
        token = django_keycloak_auth.clients.get_active_access_token(user.oidc_profile)
        return user, OAuthToken(token=token)

    def enforce_csrf(self, request):
        check = authentication.CSRFCheck()
        check.process_request(request)
        reason = check.process_view(request, None, (), {})
        if reason:
            raise exceptions.PermissionDenied('CSRF Failed: %s' % reason)


@dataclasses.dataclass
class OAuthToken:
    token: str
