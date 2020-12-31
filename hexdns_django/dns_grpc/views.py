import base64
import hashlib
import ipaddress
import secrets
import urllib.parse
import uuid

import django_keycloak_auth.clients
import dnslib
import jwt
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render, reverse
from django.utils import timezone
from django.utils.safestring import mark_safe
from django.views.decorators.csrf import csrf_exempt
from publicsuffixlist import PublicSuffixList

from . import forms, grpc, models

psl = PublicSuffixList()


def get_feedback_url(description: str, reference: str):
    if settings.FEEDBACK_URL == "none":
        return None
    access_token = django_keycloak_auth.clients.get_access_token()
    r = requests.post(f"{settings.FEEDBACK_URL}/api/feedback_request/", json={
        "description": description,
        "action_reference": reference
    }, headers={
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    })
    r.raise_for_status()
    data = r.json()
    return data["public_url"]


def make_zone_digest(zone_name: str):
    buffer = dnslib.DNSBuffer()
    nums = settings.DNSSEC_PUBKEY.public_numbers()
    rd = dnslib.DNSKEY(
        257,
        3,
        13,
        nums.x.to_bytes(32, byteorder="big") + nums.y.to_bytes(32, byteorder="big"),
    )
    buffer.encode_name(dnslib.DNSLabel(zone_name))
    rd.pack(buffer)
    digest = hashlib.sha256(buffer.data).hexdigest()
    tag = grpc.make_key_tag(settings.DNSSEC_PUBKEY, flags=257)
    return digest, tag


def log_usage(user, extra=0, can_reject=True, off_session=True, redirect_uri=None):
    client_token = django_keycloak_auth.clients.get_access_token()
    resources = django_keycloak_auth.clients.get_uma_client().resource_set_list(client_token, owner=user.username)
    user_zone_count = models.DNSZone.objects.filter(resource_id__in=resources, charged=True).count() \
                      + models.SecondaryDNSZone.objects.filter(resource_id__in=resources, charged=True).count() \
                      + models.ReverseDNSZone.objects.filter(resource_id__in=resources, charged=True).count() \
                      + extra
    if not user.account.subscription_id:
        r = requests.post(f"{settings.BILLING_URL}/subscribe_user/{user.username}/", json={
            "plan_id": settings.BILLING_PLAN_ID,
            "initial_usage": user_zone_count,
            "can_reject": can_reject,
            "off_session": off_session,
            "redirect_uri": redirect_uri
        }, headers={
            "Authorization": f"Bearer {client_token}"
        })
        data = r.json()
        if r.status_code in (200, 302):
            user.account.subscription_id = data["id"]
            user.account.subscription_active = False
            user.account.save()
            if r.status_code == 302:
                return "redirect", data["redirect_uri"]
            elif r.status_code == 200:
                return "ok", None
        else:
            return "error", 'There was an unexpected error'
    else:
        r = requests.post(
            f"{settings.BILLING_URL}/log_usage/{user.account.subscription_id}/", json={
                "usage": user_zone_count,
                "can_reject": can_reject,
                "off_session": off_session,
                "redirect_uri": redirect_uri
            }, headers={
                "Authorization": f"Bearer {client_token}"
            }
        )
        data = r.json()
        if r.status_code in (200, 302):
            if r.status_code == 302:
                return "redirect", data["redirect_uri"]
            elif r.status_code == 200:
                return "ok", None
        else:
            return "error", 'There was an unexpected error'


@login_required
def zones(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zones = models.DNSZone.get_object_list(access_token)

    return render(request, "dns_grpc/zones.html", {
        "zones": user_zones,
        "account": request.user.account
    })


@login_required
def rzones(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zones = models.ReverseDNSZone.get_object_list(access_token)

    return render(request, "dns_grpc/rzones.html", {"zones": user_zones})


@login_required
def szones(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zones = models.SecondaryDNSZone.get_object_list(access_token)

    return render(request, "dns_grpc/szones.html", {"zones": user_zones})


def valid_zone(zone_root_txt):
    zone_root = dnslib.DNSLabel(zone_root_txt)
    other_zones = list(models.DNSZone.objects.all()) + list(models.SecondaryDNSZone.objects.all())
    if not psl.is_private(zone_root_txt):
        return "Zone not a publicly registrable domain"
    else:
        for zone in other_zones:
            other_zone_root = dnslib.DNSLabel(zone.zone_root.lower())
            if zone_root.matchSuffix(other_zone_root):
                return "Same or more generic zone already exists"


@login_required
def create_zone(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)

    if not models.DNSZone.has_class_scope(access_token, 'create'):
        raise PermissionDenied

    if request.method == "POST":
        form = forms.ZoneForm(request.POST)
        if form.is_valid():
            zone_root_txt = form.cleaned_data['zone_root'].lower()
            zone_error = valid_zone(zone_root_txt)
            if zone_error:
                form.errors['zone_root'] = (zone_error,)
            else:
                status, extra = log_usage(
                    request.user, extra=1, redirect_uri=settings.EXTERNAL_URL_BASE + reverse('zones'),
                    can_reject=True, off_session=False
                )
                if status == "error":
                    form.errors['__all__'] = (extra,)
                else:
                    priv_key = ec.generate_private_key(curve=ec.SECP256R1, backend=default_backend())
                    priv_key_bytes = priv_key.private_bytes(
                        encoding=Encoding.PEM,
                        format=PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=NoEncryption()
                    ).decode()
                    zone_obj = models.DNSZone(
                        zone_root=zone_root_txt,
                        last_modified=timezone.now(),
                        user=request.user,
                        zsk_private=priv_key_bytes
                    )
                    zone_obj.save()
                    if status == "redirect":
                        return redirect(extra)
                    return redirect('edit_zone', zone_obj.id)
    else:
        form = forms.ZoneForm()

    return render(request, "dns_grpc/create_zone.html", {
        "form": form
    })


@login_required
def create_domains_zone(request):
    client_token = django_keycloak_auth.clients.get_access_token()
    referrer = request.META.get("HTTP_REFERER")
    referrer = referrer if referrer else reverse('zones')

    try:
        domain_token = jwt.decode(
            request.GET.get("domain_token"), settings.DOMAINS_JWT_PUB, issuer='urn:as207960:domains',
            audience='urn:as207960:hexdns', options={'require': ['exp', 'iss', 'sub', 'domain']}, algorithms='ES384'
        )
    except jwt.exceptions.InvalidTokenError as e:
        return render(request, "dns_grpc/error.html", {
            "error": str(e),
            "back_url": referrer
        })

    if request.user.username != domain_token["sub"]:
        return render(request, "dns_grpc/error.html", {
            "error": "Token not for this user",
            "back_url": referrer
        })

    existing_zone = models.DNSZone.objects.filter(zone_root=domain_token["domain"]).first()
    if existing_zone:
        return redirect('edit_zone', existing_zone.id)

    zone_root = domain_token["domain"].lower()
    zone_error = valid_zone(zone_root)
    if zone_error:
        return render(request, "dns_grpc/error.html", {
            "error": zone_error,
            "back_url": referrer
        })

    r = requests.post(
        f"{settings.DOMAINS_URL}/api/internal/domains/{domain_token['domain_id']}/set_dns/",
        headers={
            "Authorization": f"Bearer {client_token}"
        }
    )
    r.raise_for_status()

    priv_key = ec.generate_private_key(curve=ec.SECP256R1, backend=default_backend())
    priv_key_bytes = priv_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    ).decode()
    zone_obj = models.DNSZone(
        zone_root=domain_token["domain"],
        last_modified=timezone.now(),
        user=request.user,
        zsk_private=priv_key_bytes,
        charged=False
    )
    zone_obj.save()
    return redirect('edit_zone', zone_obj.id)


@login_required
def create_domain_zone_list(request):
    client_token = django_keycloak_auth.clients.get_access_token()
    r = requests.get(
        f"{settings.DOMAINS_URL}/api/internal/domains/{request.user.username}/all",
        headers={
            "Authorization": f"Bearer {client_token}"
        }
    )
    r.raise_for_status()
    data = r.json()

    domains = []
    for domain in data["domains"]:
        zone_error = valid_zone(domain["domain"])
        domain["error"] = zone_error
        domains.append(domain)

    return render(request, "dns_grpc/domain_zones.html", {
        "domains": domains
    })


@login_required
def edit_zone(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    dnssec_digest, dnssec_tag = make_zone_digest(user_zone.zone_root)
    sharing_data = {
        "referrer": settings.OIDC_CLIENT_ID,
        "referrer_uri": request.build_absolute_uri()
    }
    sharing_data_uri = urllib.parse.urlencode(sharing_data)
    sharing_uri = f"{settings.KEYCLOAK_SERVER_URL}/auth/realms/{settings.KEYCLOAK_REALM}/account/resource/" \
                  f"{user_zone.resource_id}?{sharing_data_uri}"

    return render(
        request,
        "dns_grpc/zone.html",
        {
            "zone": user_zone,
            "dnssec_tag": dnssec_tag,
            "dnssec_digest": dnssec_digest,
            "sharing_uri": sharing_uri
        },
    )


@login_required
def delete_zone(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'delete'):
        raise PermissionDenied

    if request.method == "POST" and request.POST.get("delete") == "true":
        status, extra = log_usage(
            request.user, extra=-1, redirect_uri=settings.EXTERNAL_URL_BASE + reverse('zones'),
            can_reject=True, off_session=False
        )
        if status == "error":
            return render(request, "dns_grpc/delete_zone.html", {
                "zone": user_zone,
                "error": extra
            })
        else:
            user_zone.delete()
            if status == "redirect":
                return redirect(extra)
            return redirect('zones')
    else:
        return render(request, "dns_grpc/delete_zone.html", {
            "zone": user_zone
        })


@login_required
def edit_zone_tsig(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    return render(
        request,
        "dns_grpc/zone_tsig.html",
        {"zone": user_zone, },
    )


@login_required
def edit_rzone(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.ReverseDNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    zone_network = ipaddress.ip_network(
        (user_zone.zone_root_address, user_zone.zone_root_prefix)
    )
    zone_name = grpc.network_to_apra(zone_network)
    dnssec_digest, dnssec_tag = make_zone_digest(zone_name.label)
    sharing_data = {
        "referrer": settings.OIDC_CLIENT_ID,
        "referrer_uri": request.build_absolute_uri()
    }
    sharing_data_uri = urllib.parse.urlencode(sharing_data)
    sharing_uri = f"{settings.KEYCLOAK_SERVER_URL}/auth/realms/{settings.KEYCLOAK_REALM}/account/resource/" \
                  f"{user_zone.resource_id}?{sharing_data_uri}"

    return render(
        request,
        "dns_grpc/rzone.html",
        {
            "zone": user_zone,
            "dnssec_tag": dnssec_tag,
            "dnssec_digest": dnssec_digest,
            "sharing_uri": sharing_uri
        }
    )


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
            zone_error = valid_zone(zone_root_txt)
            if zone_error:
                form.errors['zone_root'] = (zone_error,)
            else:
                status, extra = log_usage(
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

                    if status == "redirect":
                        return redirect(extra)
                    return redirect('edit_szone', zone_obj.id)
    else:
        form = forms.SecondaryZoneForm()

    return render(request, "dns_grpc/create_zone.html", {
        "form": form
    })


@login_required
def view_szone(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.SecondaryDNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'view'):
        raise PermissionDenied

    sharing_data = {
        "referrer": settings.OIDC_CLIENT_ID,
        "referrer_uri": request.build_absolute_uri()
    }
    sharing_data_uri = urllib.parse.urlencode(sharing_data)
    sharing_uri = f"{settings.KEYCLOAK_SERVER_URL}/auth/realms/{settings.KEYCLOAK_REALM}/account/resource/" \
                  f"{user_zone.resource_id}?{sharing_data_uri}"

    return render(
        request,
        "dns_grpc/szone.html",
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

    return render(request, "dns_grpc/edit_szone.html", {
        "form": form
    })


@login_required
def delete_szone(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.SecondaryDNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'delete'):
        raise PermissionDenied

    if request.method == "POST" and request.POST.get("delete") == "true":
        status, extra = log_usage(
            request.user, extra=-1, redirect_uri=settings.EXTERNAL_URL_BASE + reverse('szones'),
            can_reject=True, off_session=False
        )
        if status == "error":
            return render(request, "dns_grpc/delete_szone.html", {
                "zone": user_zone,
                "error": extra
            })
        else:
            user_zone.delete()
            if status == "redirect":
                return redirect(extra)
            return redirect('szones')
    else:
        return render(request, "dns_grpc/delete_szone.html", {
            "zone": user_zone
        })


@login_required
def create_address_record(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.AddressRecordForm(request.POST, instance=models.AddressRecord(zone=user_zone))
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.AddressRecordForm(instance=models.AddressRecord(zone=user_zone))

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create address record", "form": record_form, },
    )


@login_required
def edit_address_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.AddressRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.AddressRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.AddressRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit address record", "form": record_form, },
    )


@login_required
def delete_address_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.AddressRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete address record", "record": user_record, },
    )


@login_required
def create_dynamic_address_record(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.DynamicAddressRecordForm(request.POST, instance=models.DynamicAddressRecord(zone=user_zone))
        del record_form.fields['id']
        del record_form.fields['password']
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            instance.password = secrets.token_hex(32)
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.DynamicAddressRecordForm(instance=models.DynamicAddressRecord(zone=user_zone))
        del record_form.fields['id']
        del record_form.fields['password']

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create dynamic address record", "form": record_form},
    )


@login_required
def edit_dynamic_address_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.DynamicAddressRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.DynamicAddressRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.DynamicAddressRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit dynamic address record", "form": record_form},
    )


@login_required
def delete_dynamic_address_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.DynamicAddressRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete dynamic address record", "record": user_record},
    )


@login_required
def create_aname_record(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.ANAMERecordForm(request.POST, instance=models.ANAMERecord(zone=user_zone))
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.ANAMERecordForm(instance=models.ANAMERecord(zone=user_zone))

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create ANAME record", "form": record_form, },
    )


@login_required
def edit_aname_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.ANAMERecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.ANAMERecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.ANAMERecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit ANAME record", "form": record_form, },
    )


@login_required
def delete_aname_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.ANAMERecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete ANAME record", "record": user_record, },
    )


@login_required
def create_cname_record(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.CNAMERecordForm(request.POST, instance=models.CNAMERecord(zone=user_zone))
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.CNAMERecordForm(instance=models.CNAMERecord(zone=user_zone))

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create CNAME record", "form": record_form, },
    )


@login_required
def edit_cname_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.CNAMERecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.CNAMERecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.CNAMERecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit CNAME record", "form": record_form, },
    )


@login_required
def delete_cname_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.CNAMERecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete CNAME record", "record": user_record, },
    )


@login_required
def create_mx_record(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.MXRecordForm(request.POST, instance=models.MXRecord(zone=user_zone))
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.MXRecordForm(instance=models.MXRecord(zone=user_zone))

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create MX record", "form": record_form, },
    )


@login_required
def edit_mx_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.MXRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.MXRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.MXRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit MX record", "form": record_form, },
    )


@login_required
def delete_mx_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.MXRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete MX record", "record": user_record, },
    )


@login_required
def create_ns_record(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.NSRecordForm(request.POST, instance=models.NSRecord(zone=user_zone))
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.NSRecordForm(instance=models.NSRecord(zone=user_zone))

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create NS record", "form": record_form, },
    )


@login_required
def edit_ns_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.NSRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.NSRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.NSRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit NS record", "form": record_form, },
    )


@login_required
def delete_ns_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.NSRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete NS record", "record": user_record, },
    )


@login_required
def create_txt_record(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.TXTRecordForm(request.POST, instance=models.TXTRecord(zone=user_zone))
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.TXTRecordForm(instance=models.TXTRecord(zone=user_zone))

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create TXT record", "form": record_form, },
    )


@login_required
def edit_txt_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.TXTRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.TXTRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.TXTRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit TXT record", "form": record_form, },
    )


@login_required
def delete_txt_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.TXTRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete TXT record", "record": user_record, },
    )


@login_required
def create_srv_record(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.SRVRecordForm(request.POST, instance=models.SRVRecord(zone=user_zone))
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.SRVRecordForm(instance=models.SRVRecord(zone=user_zone))

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create SRV record", "form": record_form, },
    )


@login_required
def edit_srv_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.SRVRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.SRVRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.SRVRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit SRV record", "form": record_form, },
    )


@login_required
def delete_srv_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.SRVRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete SRV record", "record": user_record, },
    )


@login_required
def create_caa_record(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.CAARecordForm(request.POST, instance=models.CAARecord(zone=user_zone))
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.CAARecordForm(instance=models.CAARecord(zone=user_zone))

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create CAA record", "form": record_form, },
    )


@login_required
def edit_caa_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.CAARecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.CAARecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.CAARecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit CAA record", "form": record_form, },
    )


@login_required
def delete_caa_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.CAARecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete CAA record", "record": user_record, },
    )


@login_required
def create_naptr_record(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.NAPTRRecordForm(request.POST, instance=models.NAPTRRecord(zone=user_zone))
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.NAPTRRecordForm(instance=models.NAPTRRecord(zone=user_zone))

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create NAPTR record", "form": record_form, },
    )


@login_required
def edit_naptr_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.NAPTRRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.NAPTRRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.NAPTRRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit NAPTR record", "form": record_form, },
    )


@login_required
def delete_naptr_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.NAPTRRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete NAPTR record", "record": user_record, },
    )


@login_required
def create_sshfp_record(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.SSHFPRecordForm(request.POST, instance=models.SSHFPRecord(zone=user_zone))
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.SSHFPRecordForm(instance=models.DynamicAddressRecord(zone=user_zone))

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create SSHFP record", "form": record_form, },
    )


@login_required
def edit_sshfp_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.SSHFPRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.SSHFPRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.SSHFPRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit SSHFP record", "form": record_form, },
    )


@login_required
def delete_sshfp_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.SSHFPRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete SSHFP record", "record": user_record, },
    )


@login_required
def create_ds_record(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.DSRecordForm(request.POST, instance=models.DSRecord(zone=user_zone))
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.DSRecordForm(instance=models.DSRecord(zone=user_zone))

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create DS record", "form": record_form, },
    )


@login_required
def edit_ds_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.DSRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.DSRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.DSRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit DS record", "form": record_form, },
    )


@login_required
def delete_ds_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.DSRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete DS record", "record": user_record, },
    )


@login_required
def create_loc_record(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.LOCRecordForm(request.POST, instance=models.LOCRecord(zone=user_zone))
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.LOCRecordForm(instance=models.LOCRecord(zone=user_zone))

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create LOC record", "form": record_form, },
    )


@login_required
def edit_loc_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.LOCRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.LOCRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.LOCRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit LOC record", "form": record_form, },
    )


@login_required
def delete_loc_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.LOCRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete LOC record", "record": user_record, },
    )


@login_required
def create_hinfo_record(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.HINFORecordForm(request.POST, instance=models.HINFORecord(zone=user_zone))
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.HINFORecordForm(instance=models.HINFORecord(zone=user_zone))

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create HINFO record", "form": record_form, },
    )


@login_required
def edit_hinfo_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.HINFORecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.HINFORecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.HINFORecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit HINFO record", "form": record_form, },
    )


@login_required
def delete_hinfo_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.HINFORecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete HINFO record", "record": user_record, },
    )


@login_required
def create_rp_record(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.RPRecordForm(request.POST, instance=models.RPRecord(zone=user_zone))
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.RPRecordForm(instance=models.RPRecord(zone=user_zone))

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create RP record", "form": record_form, },
    )


@login_required
def edit_rp_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.RPRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.RPRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.RPRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit RP record", "form": record_form, },
    )


@login_required
def delete_rp_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.RPRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete RP record", "record": user_record, },
    )


@login_required
def create_zone_secret(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.UpdateSecretForm(request.POST, instance=models.DNSZoneUpdateSecrets(zone=user_zone))
        del record_form.fields['id']
        if record_form.is_valid():
            record_form.save()
            return redirect("edit_zone_secrets", user_zone.id)
    else:
        record_form = forms.UpdateSecretForm(instance=models.DNSZoneUpdateSecrets(zone=user_zone))
        del record_form.fields['id']

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create update secret", "form": record_form, },
    )


@login_required
def edit_zone_secret(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.DNSZoneUpdateSecrets, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.UpdateSecretForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.save()
            return redirect("edit_zone_secrets", user_record.zone.id)
    else:
        record_form = forms.UpdateSecretForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit update secret", "form": record_form, },
    )


@login_required
def delete_zone_secret(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.DNSZoneUpdateSecrets, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.delete()
            return redirect("edit_zone_secrets", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete update secret", "record": user_record, },
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
        "dns_grpc/edit_record.html",
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
        "dns_grpc/edit_record.html",
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
        "dns_grpc/delete_rrecord.html",
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
        "dns_grpc/edit_record.html",
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
        "dns_grpc/edit_record.html",
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
        "dns_grpc/delete_rrecord.html",
        {"title": "Delete NS record", "record": user_record},
    )


@login_required
def import_zone_file(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    zone_obj = get_object_or_404(models.DNSZone, id=zone_id)

    if not zone_obj.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        import_form = forms.ZoneImportForm(request.POST)
        if import_form.is_valid():
            zone_data = import_form.cleaned_data["zone_data"]
            suffix = dnslib.DNSLabel(zone_obj.zone_root)
            p = dnslib.ZoneParser(zone_data, origin=suffix)
            try:
                records = list(p)
            except (dnslib.DNSError, ValueError) as e:
                import_form.errors["zone_data"] = (f"Invalid zone file: {str(e)}",)
            else:
                for record in records:
                    if record.rclass != dnslib.CLASS.IN:
                        continue
                    record_name = record.rname.stripSuffix(suffix)
                    if len(record_name.label) == 0:
                        record_name = dnslib.DNSLabel("@")
                    if record.rtype == dnslib.QTYPE.A:
                        r = models.AddressRecord.from_rr(record, zone_obj)
                        r.save()
                    elif record.rtype == dnslib.QTYPE.AAAA:
                        r = models.AddressRecord.from_rr(record, zone_obj)
                        r.save()
                    elif record.rtype == dnslib.QTYPE.CNAME:
                        r = models.CNAMERecord.from_rr(record, zone_obj)
                        r.save()
                    elif record.rtype == dnslib.QTYPE.MX:
                        r = models.MXRecord.from_rr(record, zone_obj)
                        r.save()
                    elif record.rtype == dnslib.QTYPE.NS and record_name != "@":
                        r = models.NSRecord.from_rr(record, zone_obj)
                        r.save()
                    elif record.rtype == dnslib.QTYPE.TXT:
                        r = models.TXTRecord.from_rr(record, zone_obj)
                        r.save()
                    elif record.rtype == dnslib.QTYPE.SRV:
                        r = models.SRVRecord.from_rr(record, zone_obj)
                        r.save()
                    elif record.rtype == dnslib.QTYPE.CAA:
                        r = models.CAARecord.from_rr(record, zone_obj)
                        r.save()
                    elif record.rtype == dnslib.QTYPE.NAPTR:
                        r = models.NAPTRRecord.from_rr(record, zone_obj)
                        r.save()
                return redirect('edit_zone', zone_id)
    else:
        import_form = forms.ZoneImportForm()

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Zone file import", "form": import_form},
    )


@login_required
def generate_dmarc(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    zone_obj = get_object_or_404(models.DNSZone, id=zone_id)

    if not zone_obj.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        gen_form = forms.DMARCForm(request.POST)
        if gen_form.is_valid():
            dmarc_data = f"v=DMARC1; p={gen_form.cleaned_data['policy']}"
            if gen_form.cleaned_data['subdomain_policy']:
                dmarc_data += f"; sp={gen_form.cleaned_data['subdomain_policy']}"
            if gen_form.cleaned_data['percentage']:
                dmarc_data += f"; pct={gen_form.cleaned_data['percentage']}"
            if gen_form.cleaned_data['dkim_alignment']:
                dmarc_data += f"; adkim={gen_form.cleaned_data['dkim_alignment']}"
            if gen_form.cleaned_data['spf_alignment']:
                dmarc_data += f"; aspf={gen_form.cleaned_data['spf_alignment']}"
            if gen_form.cleaned_data['report_interval']:
                dmarc_data += f"; ri={gen_form.cleaned_data['report_interval']}"
            if gen_form.cleaned_data['aggregate_feedback']:
                dmarc_data += f"; rua={gen_form.cleaned_data['aggregate_feedback']}"
            if gen_form.cleaned_data['failure_feedback']:
                dmarc_data += f"; ruf={gen_form.cleaned_data['failure_feedback']}"

            r = models.TXTRecord(
                zone=zone_obj,
                data=dmarc_data,
                ttl=86400,
                record_name="_dmarc"
            )
            r.save()
            return redirect('edit_zone', zone_id)
    else:
        gen_form = forms.DMARCForm()

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "DMARC Generate", "form": gen_form},
    )


@login_required
def setup_gsuite(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    zone_obj = get_object_or_404(models.DNSZone, id=zone_id)

    if not zone_obj.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST" and request.POST.get("setup") == "true":
        zone_obj.mxrecord_set.filter(record_name="@").delete()
        for r in (
                ("aspmx.l.google.com", 1),
                ("alt1.aspmx.l.google.com", 5),
                ("alt2.aspmx.l.google.com", 5),
                ("alt3.aspmx.l.google.com", 10),
                ("alt4.aspmx.l.google.com", 10),
        ):
            mx = models.MXRecord(
                zone=zone_obj,
                record_name="@",
                ttl=3600,
                exchange=r[0],
                priority=r[1]
            )
            mx.save()
        return redirect('edit_zone', zone_obj.id)

    return render(
        request,
        "dns_grpc/setup_gsuite.html",
        {"zone": zone_obj},
    )


@login_required
def setup_github_pages(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    zone_obj = get_object_or_404(models.DNSZone, id=zone_id)

    if not zone_obj.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        gen_form = forms.GithubPagesForm(request.POST)
        if gen_form.is_valid():
            zone_obj.addressrecord_set.filter(record_name=gen_form.cleaned_data['record_name']).delete()
            for a in (
                    "185.199.108.153",
                    "185.199.109.153",
                    "185.199.110.153",
                    "185.199.111.153"
            ):
                addr = models.AddressRecord(
                    zone=zone_obj,
                    address=a,
                    record_name=gen_form.cleaned_data['record_name'],
                    ttl=3600,
                )
                addr.save()
            return redirect('edit_zone', zone_obj.id)
    else:
        gen_form = forms.GithubPagesForm()

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Setup for GitHub Pages", "form": gen_form},
    )


def get_ip(request):
    net64_net = ipaddress.IPv6Network("2a0d:1a40:7900:6::/80")
    addr = ipaddress.ip_address(request.META['REMOTE_ADDR'])
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if addr in net64_net:
            addr = ipaddress.IPv4Address(addr._ip & 0xFFFFFFFF)
    return addr


def get_header_auth(request):
    auth_header = request.META.get('HTTP_AUTHORIZATION')
    if not auth_header:
        return None
    encoded_credentials = auth_header.split(' ', 1)
    if len(encoded_credentials) != 2:
        return None
    if encoded_credentials[0] != "Basic":
        return None
    decoded_credentials = base64.b64decode(encoded_credentials[1]).decode("utf-8").split(':', 1)
    if len(decoded_credentials) != 2:
        return None
    return decoded_credentials[0], decoded_credentials[1]


def check_ip(request):
    return HttpResponse(get_ip(request), content_type="text/plain")


@csrf_exempt
def update_ip(request):
    auth = get_header_auth(request)
    if not auth:
        return HttpResponseBadRequest()

    username, password = auth

    try:
        obj_id = uuid.UUID(username)
    except ValueError:
        return HttpResponseBadRequest("nohost")

    dyn_obj = get_object_or_404(models.DynamicAddressRecord, id=obj_id)
    if dyn_obj.password != password:
        return HttpResponseForbidden("badauth")

    if request.method == "POST":
        data = request.POST
    else:
        data = request.GET

    hostname = data.get("hostname")
    myip = data.get("myip")

    if hostname != f"{dyn_obj.record_name}.{dyn_obj.zone.zone_root}":
        if not (dyn_obj.record_name == "@" and hostname == dyn_obj.zone.zone_root):
            return HttpResponseBadRequest("nohost")

    client_ip = get_ip(request)
    if myip:
        try:
            client_ip = ipaddress.ip_address(myip)
        except ValueError:
            return HttpResponseBadRequest()

    if isinstance(client_ip, ipaddress.IPv4Address):
        if str(client_ip) == dyn_obj.current_ipv4:
            return HttpResponse(f"nochg {dyn_obj.current_ipv4}")
        dyn_obj.current_ipv4 = str(client_ip)
    elif isinstance(client_ip, ipaddress.IPv6Address):
        if str(client_ip) == dyn_obj.current_ipv6:
            return HttpResponse(f"nochg {dyn_obj.current_ipv4}")
        dyn_obj.current_ipv6 = str(client_ip)

    dyn_obj.zone.last_modified = timezone.now()
    dyn_obj.save()
    dyn_obj.zone.save()

    return HttpResponse(f"good {client_ip}")
