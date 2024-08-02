import json
import dataclasses
import typing
import urllib.parse
from audioop import error

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
        "providerName": "Glauca Digital",
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


def sync_apply(request, provider_id: str, service_id: str):
    if not (template := get_template(provider_id, service_id)):
        return HttpResponse(status=404)

    if "domain" not in request.GET:
        return HttpResponse(status=400)

    signature = None
    key_label = None
    if "signature" in request.GET or "key" in request.GET:
        signature = request.GET.get("signature")
        if not signature:
            return HttpResponse(status=400)
        del request.GET["signature"]
        key_label = request.GET.get("key")
        if not key_label:
            return HttpResponse(status=400)
        del request.GET["key"]

    if key_label:
        if not (d := template.get("syncPubKeyDomain")):
            return HttpResponse(status=400)

        label = f"{key_label}.{d}"
        question = dnslib.DNSRecord(q=dnslib.DNSQuestion(label, dnslib.QTYPE.TXT))
        res_pkt = question.send(
            settings.RESOLVER_ADDR, port=settings.RESOLVER_PORT,
            ipv6=settings.RESOLVER_IPV6, tcp=False, timeout=5
        )
        res = dnslib.DNSRecord.parse(res_pkt)
        provider_keys = list(filter(
            lambda r: r.rtype == dnslib.QTYPE.TXT and r.rclass == dnslib.CLASS.IN,
            res.rr
        ))

        if not provider_keys:
            return HttpResponse(status=400)

        # TODO: Verify signature

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

        # TODO: allow any if request is signed
        if parsed_redirect.hostname != template.get("syncRedirectDomain"):
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