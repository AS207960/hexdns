from rest_framework import permissions
from as207960_utils.api import auth


def zone_keycloak(pre_filtered=False):
    class ZoneKeycloak(permissions.BasePermission):
        def has_permission(self, request, view):
            if not isinstance(request.auth, auth.OAuthToken):
                return False

            return True

        def has_object_permission(self, request, view, obj):
            if pre_filtered:
                return True

            if not isinstance(request.auth, auth.OAuthToken):
                return False

            if request.method == "OPTIONS":
                return True
            elif request.method in ("GET", "HEAD"):
                return obj.zone.has_scope(request.auth.token, 'view')
            elif request.method in ("PUT", "PATCH", "DELETE"):
                return obj.zone.has_scope(request.auth.token, 'edit')

    return ZoneKeycloak
