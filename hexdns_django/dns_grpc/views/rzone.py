import ipaddress
import urllib.parse

import django_keycloak_auth.clients
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .. import forms, models, tasks, utils


@login_required
def rzones(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zones = models.ReverseDNSZone.get_object_list(access_token)

    return render(request, "dns_grpc/rzone/rzones.html", {"zones": user_zones})


@login_required
def edit_rzone(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.ReverseDNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    zone_network = ipaddress.ip_network(
        (user_zone.zone_root_address, user_zone.zone_root_prefix)
    )
    zone_name = tasks.network_to_apra(zone_network)
    dnssec_digest, dnssec_tag = utils.make_zone_digest(zone_name.label)

    if user_zone.get_user() == request.user:
        sharing_data = {
            "referrer": settings.OIDC_CLIENT_ID,
            "referrer_uri": request.build_absolute_uri()
        }
        sharing_data_uri = urllib.parse.urlencode(sharing_data)
        sharing_uri = f"{settings.KEYCLOAK_SERVER_URL}/auth/realms/{settings.KEYCLOAK_REALM}/account/resource/" \
                      f"{user_zone.resource_id}?{sharing_data_uri}"
    else:
        sharing_uri = None

    return render(
        request,
        "dns_grpc/rzone/rzone.html",
        {
            "zone": user_zone,
            "dnssec_tag": dnssec_tag,
            "dnssec_digest": dnssec_digest,
            "sharing_uri": sharing_uri
        }
    )


@login_required
def create_r_ptr_record(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.ReverseDNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.ReversePTRRecordForm(
            request.POST, instance=models.PTRRecord(zone=user_zone)
        )
        if record_form.is_valid():
            record_form.save()
            user_zone.last_modified = timezone.now()
            user_zone.save()
            return redirect("edit_rzone", user_zone.id)
    else:
        record_form = forms.ReversePTRRecordForm()

    return render(
        request,
        "dns_grpc/fzone/edit_record.html",
        {"title": "Create PTR record", "form": record_form, },
    )


@login_required
def edit_r_ptr_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.PTRRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.ReversePTRRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_rzone", user_record.zone.id)
    else:
        record_form = forms.ReversePTRRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/fzone/edit_record.html",
        {"title": "Edit PTR record", "form": record_form, },
    )


@login_required
def delete_r_ptr_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.PTRRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_rzone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/rzone/delete_rrecord.html",
        {"title": "Delete PTR record", "record": user_record},
    )


@login_required
def create_r_ns_record(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.ReverseDNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.ReverseNSRecordForm(
            request.POST, instance=models.ReverseNSRecord(zone=user_zone)
        )
        if record_form.is_valid():
            record_form.save()
            user_zone.last_modified = timezone.now()
            user_zone.save()
            return redirect("edit_rzone", user_zone.id)
    else:
        record_form = forms.ReverseNSRecordForm()

    return render(
        request,
        "dns_grpc/fzone/edit_record.html",
        {"title": "Create NS record", "form": record_form, },
    )


@login_required
def edit_r_ns_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.ReverseNSRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.ReverseNSRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_rzone", user_record.zone.id)
    else:
        record_form = forms.ReverseNSRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/fzone/edit_record.html",
        {"title": "Edit NS record", "form": record_form, },
    )


@login_required
def delete_r_ns_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.ReverseNSRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_rzone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/rzone/delete_rrecord.html",
        {"title": "Delete NS record", "record": user_record},
    )
