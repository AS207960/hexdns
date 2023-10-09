import urllib.parse

import django_keycloak_auth.clients
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render, reverse

from .. import forms, models, tasks, utils


@login_required
def szones(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zones = models.SecondaryDNSZone.get_object_list(access_token)
    no_subscription = len(user_zones) != 0 and not request.user.account.subscription_id
    subscription_inactive = len(user_zones) != 0 and not request.user.account.subscription_active

    return render(request, "dns_grpc/szone/szones.html", {
        "zones": user_zones,
        "account": request.user.account,
        "no_subscription": no_subscription,
        "subscription_inactive": subscription_inactive
    })


@login_required
def create_szone(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)

    if not models.SecondaryDNSZone.has_class_scope(access_token, 'create'):
        raise PermissionDenied

    if request.method == "POST":
        form = forms.SecondaryZoneForm(request.POST)
        if form.is_valid():
            zone_root_txt = form.cleaned_data['zone_root'].lower()
            primary_server = form.cleaned_data['primary_server'].lower()
            zone_error = utils.valid_zone(zone_root_txt)
            if zone_error:
                form.errors['zone_root'] = (zone_error,)
            else:
                status, extra = utils.log_usage(
                    request.user, extra=1, redirect_uri=settings.EXTERNAL_URL_BASE + reverse('szones'),
                    can_reject=True, off_session=False
                )
                if status == "error":
                    form.errors['__all__'] = (extra,)
                else:
                    zone_obj = models.SecondaryDNSZone(
                        zone_root=zone_root_txt,
                        user=request.user,
                        primary=primary_server
                    )
                    zone_obj.save()
                    tasks.add_szone.delay(zone_obj.id)

                    if status == "redirect":
                        return redirect(extra)
                    return redirect('edit_szone', zone_obj.id)
    else:
        form = forms.SecondaryZoneForm()

    return render(request, "dns_grpc/fzone/create_zone.html", {
        "form": form
    })


@login_required
def view_szone(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.SecondaryDNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'view'):
        raise PermissionDenied

    if user_zone.get_user() == request.user:
        sharing_data = {
            "referrer": settings.OIDC_CLIENT_ID,
            "referrer_uri": request.build_absolute_uri()
        }
        sharing_data_uri = urllib.parse.urlencode(sharing_data)
        sharing_uri = f"{settings.KEYCLOAK_SERVER_URL}/auth/realms/{settings.KEYCLOAK_REALM}/account/?{sharing_data_uri}" \
                      f"#/resource/{user_zone.resource_id}"
    else:
        sharing_uri = None

    return render(
        request,
        "dns_grpc/szone/szone.html",
        {
            "zone": user_zone,
            "sharing_uri": sharing_uri,
        }
    )


@login_required
def edit_szone(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.SecondaryDNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        form = forms.SecondaryZoneForm(request.POST, initial={
            "zone_root": user_zone.zone_root,
            "primary_server": user_zone.primary
        })
        form.fields['zone_root'].disabled = True
        if form.is_valid():
            primary_server = form.cleaned_data['primary_server'].lower()
            user_zone.primary = primary_server
            user_zone.save()
            return redirect('view_szone', user_zone.id)
    else:
        form = forms.SecondaryZoneForm(initial={
            "zone_root": user_zone.zone_root,
            "primary_server": user_zone.primary
        })
        form.fields['zone_root'].disabled = True

    return render(request, "dns_grpc/szone/edit_szone.html", {
        "form": form
    })


@login_required
def delete_szone(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.SecondaryDNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'delete'):
        raise PermissionDenied

    if request.method == "POST" and request.POST.get("delete") == "true":
        status, extra = utils.log_usage(
            user_zone.get_user(), extra=-1 if user_zone.charged else 0, redirect_uri=settings.EXTERNAL_URL_BASE + reverse('szones'),
            can_reject=True, off_session=False
        )
        if status == "error":
            return render(request, "dns_grpc/szone/delete_szone.html", {
                "zone": user_zone,
                "error": extra
            })
        else:
            user_zone.delete()
            tasks.update_catalog.delay()
            if status == "redirect":
                return redirect(extra)
            return redirect('szones')
    else:
        return render(request, "dns_grpc/szone/delete_szone.html", {
            "zone": user_zone
        })
