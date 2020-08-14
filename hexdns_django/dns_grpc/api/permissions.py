from rest_framework import permissions
from . import auth


def keycloak(db_class, pre_filtered=False):
    class Keycloak(permissions.BasePermission):
        def has_permission(self, request, view):
            if not isinstance(request.auth, auth.OAuthToken):
                return False

            if request.method == "POST":
                return db_class.has_class_scope(request.auth.token, 'create')
            else:
                return True

        def has_object_permission(self, request, view, obj):
            if pre_filtered:
                return True

            if not isinstance(request.auth, auth.OAuthToken):
                return False

            if request.method == "OPTIONS":
                return True
            elif request.method in ("GET", "HEAD"):
                return obj.has_scope(request.auth.token, 'view')
            elif request.method in ("PUT", "PATCH"):
                return obj.has_scope(request.auth.token, 'edit')
            elif request.method == "DELETE":
                return obj.has_scope(request.auth.token, 'delete')

    return Keycloak


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
