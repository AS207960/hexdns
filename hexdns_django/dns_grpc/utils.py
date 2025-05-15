import typing
import dnslib
import hashlib
import publicsuffixlist
import django_keycloak_auth.clients
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from dns_grpc import models, tasks
from django.conf import settings

psl = publicsuffixlist.PublicSuffixList()


def get_priv_key_bytes():
    priv_key = ec.generate_private_key(curve=ec.SECP256R1, backend=default_backend())
    priv_key_bytes = priv_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    ).decode()
    return priv_key_bytes


def get_priv_key_ed25519_bytes():
    priv_key = ed25519.Ed25519PrivateKey.generate()
    priv_key_bytes = priv_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    ).decode()
    return priv_key_bytes


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
        if r.status_code in (200, 302):
            data = r.json()
            user.account.subscription_id = data["id"]
            user.account.subscription_active = True
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
        if r.status_code in (200, 302):
            if r.status_code == 302:
                data = r.json()
                return "redirect", data["redirect_uri"]
            elif r.status_code == 200:
                return "ok", None
        else:
            return "error", 'There was an unexpected error'


def get_dnskey():
    nums = settings.DNSSEC_PUBKEY.public_numbers()
    return dnslib.DNSKEY(
        257,
        3,
        13,
        nums.x.to_bytes(32, byteorder="big") + nums.y.to_bytes(32, byteorder="big"),
    )


def make_zone_digest(zone_name: typing.Union[str, dnslib.DNSLabel]):
    if not isinstance(zone_name, dnslib.DNSLabel):
        zone_name = dnslib.DNSLabel(zone_name)
    buffer = dnslib.DNSBuffer()
    rd = get_dnskey()
    buffer.encode_name(zone_name)
    rd.pack(buffer)
    digest = hashlib.sha256(buffer.data).hexdigest()
    tag = tasks.make_key_tag(settings.DNSSEC_PUBKEY, flags=257)
    return digest, tag


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
