import base64
import binascii
import json
import dataclasses
import typing
import urllib.parse
import cryptography.exceptions
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric
import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.hazmat.primitives.hashes
import dnslib
import django.core.files.storage
from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse

import dns_grpc.models

@dataclasses.dataclass
class SyncConnectState:
    zone_id: str
    host: typing.Optional[str] = None
    redirect: typing.Optional[str] = None
    state: typing.Optional[str] = None
    additional_provider_name: typing.Optional[str] = None
    additional_service_name: typing.Optional[str] = None
    group_ids: typing.List[str] = dataclasses.field(default_factory=list)


def domain_settings(request, domain: str):
    zone_obj = get_object_or_404(dns_grpc.models.DNSZone, zone_root=domain)

    out = {
        "providerId": "glauca.digital",
        "providerName": "AS207960 Cyfyngedig",
        "providerDisplayName": "Glauca Digital",
        "urlSyncUX": f"{settings.EXTERNAL_URL_BASE}/connect/sync",
        "urlAsyncUX": None,
        "urlAPI": f"{settings.EXTERNAL_URL_BASE}/connect/api",
        "urlControlPanel": settings.EXTERNAL_URL_BASE + reverse("edit_zone", args=[zone_obj.id]),
        "nameServers": [
            "ns1.as207960.net",
            "ns2.as207960.net",
            "ns3.as207960.net",
            "ns4.as207960.net",
        ]
    }
    return HttpResponse(json.dumps(out), content_type="application/json")

def get_template(provider_id: str, service_id: str):
    if " " in service_id or "." in service_id:
        return None

    if " " in provider_id:
        return None

    template_storage = django.core.files.storage.storages["connect-templates"]
    template_file_name = f"{provider_id}.{service_id}.json"

    if not template_storage.exists(template_file_name):
        return None

    with template_storage.open(template_file_name) as f:
        template = json.load(f)

    return template


def check_template(request, provider_id: str, service_id: str):
    if not (template := get_template(provider_id, service_id)):
        return HttpResponse(status=404)

    return HttpResponse(json.dumps({
        "version": template["version"],
    }), content_type="application/json")


def make_redirect(redirect_uri: str, error_code: str, state: typing.Optional[str]):
    parsed_redirect = urllib.parse.urlparse(redirect_uri)
    query = urllib.parse.parse_qs(parsed_redirect.query)

    if state:
        query["state"] = [state]

    query["error"] = [error_code]

    redirect_uri = urllib.parse.urlunparse((
        parsed_redirect.scheme,
        parsed_redirect.netloc,
        parsed_redirect.path,
        parsed_redirect.params,
        urllib.parse.urlencode(query, doseq=True),
        parsed_redirect.fragment
    ))

    return redirect(redirect_uri)


def parse_keys(keys: typing.List[bytes]):
    try:
        keys = list(map(
            lambda k: k.decode("utf-8"),
            keys
        ))
    except UnicodeDecodeError:
        return None

    keys = [k.split(",") for k in keys]
    keys_dict = []
    for k in keys:
        key_dict = {}
        for d in k:
            d = d.split("=", 1)
            key_dict[d[0]] = d[1]
        keys_dict.append(key_dict)

    if not all(
        k["a"] == keys_dict[0]["a"]
        for k in keys_dict
    ):
        return None

    algorithm = keys_dict[0]["a"]
    if algorithm != "RS256":
        return None

    keys_dict.sort(key=lambda k: k["p"])
    try:
        key_data = [base64.b64decode(k["d"]) for k in keys_dict]
    except binascii.Error:
        return None

    key_data = b"".join(key_data)

    try:
        return cryptography.hazmat.primitives.serialization.load_der_public_key(
            key_data
        )
    except ValueError:
        return None

def verify_signature(key, request, signature) -> bool:
    signed_data = request.META['QUERY_STRING'].rsplit("&sig=", 1)[0]
    try:
        signature = base64.b64decode(signature)
    except binascii.Error:
        return False

    try:
        key.verify(
            signature,
            signed_data.encode("utf-8"),
            cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
            cryptography.hazmat.primitives.hashes.SHA256()
        )
    except cryptography.exceptions.InvalidSignature:
        return False

def sync_apply(request, provider_id: str, service_id: str):
    if not (template := get_template(provider_id, service_id)):
        return render(request, "dns_grpc/error.html", {
            "error": "Template not found",
        }, status=404)

    if template.get("syncBlock", False):
        return render(request, "dns_grpc/error.html", {
            "error": "This template cannot be used with the sync flow",
        }, status=400)

    if "domain" not in request.GET:
        return render(request, "dns_grpc/error.html", {
            "error": "Missing domain parameter",
        }, status=400)

    signed_request = False
    signature = None
    key_label = None
    if "signature" in request.GET or "key" in request.GET:
        signature = request.GET.get("signature")
        if not signature:
            return render(request, "dns_grpc/error.html", {
                "error": "Missing signature",
            }, status=400)
        del request.GET["signature"]
        key_label = request.GET.get("key")
        if not key_label:
            return render(request, "dns_grpc/error.html", {
                "error": "Missing signature key",
            }, status=400)
        del request.GET["key"]

    if signature:
        if not (d := template.get("syncPubKeyDomain")):
            return render(request, "dns_grpc/error.html", {
                "error": "Template does not support signed requests",
            }, status=400)

        label = f"{key_label}.{d}"
        question = dnslib.DNSRecord(q=dnslib.DNSQuestion(label, dnslib.QTYPE.TXT))
        res_pkt = question.send(
            settings.RESOLVER_ADDR, port=settings.RESOLVER_PORT,
            ipv6=settings.RESOLVER_IPV6, tcp=False, timeout=5
        )
        res = dnslib.DNSRecord.parse(res_pkt)
        if res.header.rcode != dnslib.RCODE.NOERROR:
            return render(request, "dns_grpc/error.html", {
                "error": "Unable to retrieve service provider public key",
            }, status=400)
        provider_keys = list(map(
            lambda r: b"".join(r.rdata.data),
            filter(
                lambda r: r.rtype == dnslib.QTYPE.TXT and r.rclass == dnslib.CLASS.IN,
                res.rr
            )
        ))
        if not provider_keys:
            return render(request, "dns_grpc/error.html", {
                "error": "Unable to retrieve service provider public key"
            }, status=400)

        provider_public_key = parse_keys(provider_keys)
        if not provider_public_key:
            return render(request, "dns_grpc/error.html", {
                "error": "Unable to parse service provider public key"
            }, status=400)

        if not verify_signature(provider_public_key, request, signature):
            return render(request, "dns_grpc/error.html", {
                "error": "Invalid request signature"
            }, status=403)

        signed_request = True

    if not signed_request and "syncPubKeyDomain" in template:
        return render(request, "dns_grpc/error.html", {
            "error": "Template requires signed requests",
        }, status=403)

    redirect_uri = None
    if "redirect_uri" in request.GET:
        redirect_uri = request.GET["redirect_uri"]
        del request.GET["redirect_uri"]

        try:
            parsed_redirect = urllib.parse.urlparse(redirect_uri)
        except ValueError:
            return HttpResponse(status=400)

        if parsed_redirect.scheme not in ["http", "https"]:
            return HttpResponse(status=400)

        if not signed_request:
            redirect_domains = template.get("syncRedirectDomains", "").split(",")
            if parsed_redirect.hostname not in redirect_domains:
                return HttpResponse(status=400)

    domain = request.GET["domain"]
    del request.GET["domain"]
    zone_obj = dns_grpc.models.DNSZone.objects.filter(zone_root=domain).first()

    if not zone_obj:
        if redirect_uri:
            return make_redirect(
                redirect_uri, error_code="invalid_request",
                state=request.GET.get("state")
            )
        else:
            return HttpResponse(status=404)

    state = SyncConnectState(zone_id=zone_obj.id)

    if "host" in request.GET:
        state.host = request.GET["host"]
        del request.GET["host"]

    if "state" in request.GET:
        state.state = request.GET["state"]
        del request.GET["state"]

    if "providerName" in request.GET:
        state.additional_provider_name = request.GET["providerName"]
        del request.GET["providerName"]

    if "serviceName" in request.GET:
        state.additional_service_name = request.GET["serviceName"]
        del request.GET["serviceName"]

    if "groupId" in request.GET:
        group_id = request.GET["groupId"]
        state.group_ids = group_id.split(",")
        del request.GET["groupId"]

    print(state)

    return HttpResponse("")