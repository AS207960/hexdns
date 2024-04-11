import json
import typing

from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, HttpResponseBadRequest
import django_keycloak_auth
import requests
import jose.jwt
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect, get_object_or_404, render, reverse
from django.conf import settings
from django.utils import timezone
import dateutil.parser
import datetime
import hmac
from .. import models, forms


def oauth_login(request, scopes: typing.List[str], redirect_uri: typing.Optional[str]):
    state = models.GoogleState(user=request.user.account)

    if redirect_uri:
        state.redirect_uri = settings.EXTERNAL_URL_BASE + redirect_uri

    state.save()
    request.session["google_state_id"] = state.id

    redirect_uri = settings.EXTERNAL_URL_BASE + reverse('google_oauth_callback')

    return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?response_type=code&"
                    f"client_id={settings.GOOGLE_CLIENT_ID}&scope={' '.join(scopes)}&"
                    f"redirect_uri={redirect_uri}&state={str(state.state)}&"
                    f"access_type=offline&include_granted_scopes=true")


@login_required
def oauth_callback(request):
    if "code" not in request.GET or "state" not in request.GET:
        return HttpResponseBadRequest()

    if "google_state_id" not in request.session:
        return oauth_login(request, [], request.path)

    state = models.GoogleState.objects.filter(id=request.session["google_state_id"]).first()
    if not state:
        return oauth_login(request, [], None)

    if request.GET["state"] != str(state.state):
        return HttpResponseBadRequest()

    r = requests.post("https://oauth2.googleapis.com/token", data={
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "code": request.GET["code"],
        "redirect_uri": settings.EXTERNAL_URL_BASE + request.path,
        "grant_type": "authorization_code",
    }, headers={
        "Accept": "application/json"
    })
    if r.status_code != 200:
        return HttpResponseBadRequest()

    if state:
        state.delete()

    r_data = r.json()
    now = timezone.now()
    access_token = r_data.get("access_token")
    access_token_expires_in = datetime.timedelta(seconds=int(r_data.get("expires_in"))) if r_data.get("expires_in") else None
    access_token_expires_at = now + access_token_expires_in if access_token_expires_in else None
    refresh_token = r_data.get("refresh_token")
    refresh_token_expires_in = datetime.timedelta(seconds=int(r_data.get("refresh_token_expires_in"))) if r_data.get("refresh_token_expires_in") else None
    refresh_token_expires_at = now + refresh_token_expires_in if refresh_token_expires_in else None

    installation = models.GoogleInstallation.objects.filter(user=request.user.account).first()
    if not installation:
        installation = models.GoogleInstallation(
            user=request.user.account,
        )

    installation.access_token = access_token
    installation.access_token_expires_at = access_token_expires_at
    installation.refresh_token = refresh_token
    installation.refresh_token_expires_at = refresh_token_expires_at
    installation.scopes = r_data.get("scope")
    installation.save()

    if state and state.redirect_uri:
        return redirect(state.redirect_uri)
    else:
        return redirect("zones")


def verify_google_scopes(scopes):
    def decorator(inner):
        def wrapper(request, *args, **kwargs):
            installation = models.GoogleInstallation.objects.filter(user=request.user.account).first()

            if not installation:
                return oauth_login(request, scopes, request.path)

            in_scopes = installation.scopes.split(" ") if installation.scopes else []
            for s in scopes:
                if s not in in_scopes:
                    return oauth_login(request, scopes, request.path)

            now = timezone.now()
            if installation.access_token:
                if (installation.access_token_expires_at and installation.access_token_expires_at > now) or \
                        (not installation.access_token_expires_at):
                    return inner(request, installation.access_token, *args, **kwargs)

            if installation.refresh_token_expires_at and installation.refresh_token_expires_at > now:
                return oauth_login(request, scopes, request.path)

            r = requests.post("https://oauth2.googleapis.com/token", data={
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "grant_type": "refresh_token",
                "refresh_token": installation.refresh_token
            }, headers={
                "Accept": "application/json"
            })
            if r.status_code != 200:
                return oauth_login(request, scopes, request.path)

            r_data = r.json()
            access_token = r_data.get("access_token")
            access_token_expires_in = datetime.timedelta(seconds=int(r_data.get("expires_in"))) if r_data.get(
                "expires_in") else None
            access_token_expires_at = now + access_token_expires_in if access_token_expires_in else None
            installation.access_token = access_token
            installation.access_token_expires_at = access_token_expires_at
            installation.save()

            return inner(request, installation.access_token, *args, **kwargs)

        return wrapper

    return decorator


@login_required
@verify_google_scopes(["https://www.googleapis.com/auth/siteverification.verify_only"])
def verify_zone_google(request, google_token, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    zone_obj = get_object_or_404(models.DNSZone, id=zone_id)

    if not zone_obj.has_scope(access_token, 'edit'):
        raise PermissionDenied()

    site = {
        "type": "INET_DOMAIN",
        "identifier": zone_obj.idna_label
    }

    r = requests.post(f"https://www.googleapis.com/siteVerification/v1/token?access_token={google_token}", json={
        "verificationMethod": "DNS_TXT",
        "site": site
    })
    r.raise_for_status()
    r_data = r.json()
    token = r_data["token"]

    record = zone_obj.txtrecord_set.get_or_create(data=token)[0]
    record.save()

    r = requests.post(
        f"https://www.googleapis.com/siteVerification/v1/webResource"
        f"?verificationMethod=DNS_TXT&access_token={google_token}", json={
            "site": site
        }
    )

    if r.status_code == 200:
        request.session["zone_notice"] = "Great! Your domain is now verified with Google."
    else:
        request.session["zone_notice"] = "Oh no! That didn't quite work. " \
                                         "Please try again later to allow DNS updates to propagate."

    return redirect('edit_zone', zone_obj.id)


