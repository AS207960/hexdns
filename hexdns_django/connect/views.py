import base64
import binascii
import json
import dataclasses
import typing
import urllib.parse
import ipaddress

import cryptography.exceptions
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric
import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.hazmat.primitives.hashes
import dnslib
import django.core.files.storage
import django_keycloak_auth.clients
from django.http import HttpResponse
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render, reverse

import dns_grpc.models

@dataclasses.dataclass
class Record:
    label: str
    type: str
    ttl: int
    data: dict

@dataclasses.dataclass
class SyncConnectState:
    zone_id: str
    template: dict
    records_to_install: typing.List[Record] = dataclasses.field(default_factory=list)
    records_to_delete: typing.Set[typing.Tuple[str, str]] = dataclasses.field(default_factory=set)
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

    f = template_storage.open(template_file_name)

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
        return True
    except cryptography.exceptions.InvalidSignature:
        return False

def sync_apply(request, provider_id: str, service_id: str):
    if "sync_connect_state" in request.session:
        del request.session["sync_connect_state"]

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

    query_params = dict(request.GET)

    signed_request = False
    signature = None
    key_label = None
    if "signature" in query_params or "key" in query_params:
        signature = query_params.get("sig")
        if not signature or len(signature) != 1:
            return render(request, "dns_grpc/error.html", {
                "error": "Missing signature",
            }, status=400)
        del query_params["sig"]
        signature = signature[0]
        key_label = query_params.get("key")
        if not key_label or len(key_label) != 1:
            return render(request, "dns_grpc/error.html", {
                "error": "Missing signature key",
            }, status=400)
        del query_params["key"]
        key_label = key_label[0]

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
    if "redirect_uri" in query_params:
        redirect_uri = query_params["redirect_uri"]
        if len(redirect_uri) != 1:
            return render(request, "dns_grpc/error.html", {
                "error": "Invalid redirect URL",
            }, status=400)
        redirect_uri = redirect_uri[0]
        del query_params["redirect_uri"]

        try:
            parsed_redirect = urllib.parse.urlparse(redirect_uri)
        except ValueError:
            return render(request, "dns_grpc/error.html", {
                "error": "Invalid redirect URL",
            }, status=400)

        if parsed_redirect.scheme not in ["http", "https"]:
            return render(request, "dns_grpc/error.html", {
                "error": "Invalid redirect URL",
            }, status=400)

        if not signed_request:
            redirect_domains = template.get("syncRedirectDomains", "").split(",")
            if parsed_redirect.hostname not in redirect_domains:
                return render(request, "dns_grpc/error.html", {
                    "error": "Invalid redirect URL",
                }, status=400)

    domain = query_params["domain"]
    if len(domain) != 1:
        return render(request, "dns_grpc/error.html", {
            "error": "Invalid domain",
        }, status=400)
    domain = domain[0]
    del query_params["domain"]
    zone_obj: typing.Optional[dns_grpc.models.DNSZone] = \
        dns_grpc.models.DNSZone.objects.filter(zone_root=domain).first()

    if not zone_obj:
        if redirect_uri:
            qs_state = query_params.get("state")
            if qs_state:
                if len(qs_state) == 1:
                    qs_state = qs_state[0]
                else:
                    return render(request, "dns_grpc/error.html", {
                        "error": "Invalid state",
                    }, status=400)

            return make_redirect(
                redirect_uri, error_code="invalid_request", state=qs_state
            )
        else:
            return HttpResponse(status=404)

    state = SyncConnectState(zone_id=zone_obj.id, template=template)

    if "host" in query_params:
        qs_host = query_params["host"]
        if len(qs_host) != 1:
            return render(request, "dns_grpc/error.html", {
                "error": "Invalid host",
            }, status=400)

        del query_params["host"]

    if "state" in query_params:
        qs_state = query_params["state"]
        if len(qs_state) != 1:
            return render(request, "dns_grpc/error.html", {
                "error": "Invalid state",
            }, status=400)
        state.state = qs_state[0]
        del query_params["state"]

    if "providerName" in query_params:
        qs_additional_provider_name = query_params["providerName"]
        if len(qs_additional_provider_name) != 1:
            return render(request, "dns_grpc/error.html", {
                "error": "Invalid providerName",
            }, status=400)
        state.additional_provider_name = qs_additional_provider_name[0]
        del query_params["providerName"]

    if "serviceName" in query_params:
        qs_additional_service_name = query_params["serviceName"]
        if len(qs_additional_service_name) != 1:
            return render(request, "dns_grpc/error.html", {
                "error": "Invalid serviceName",
            }, status=400)
        state.additional_service_name = qs_additional_service_name[0]
        del query_params["serviceName"]

    if "groupId" in query_params:
        group_id = query_params["groupId"]
        if len(group_id) != 1:
            return render(request, "dns_grpc/error.html", {
                "error": "Invalid groupId",
            }, status=400)
        state.group_ids = group_id[0].split(",")
        del query_params["groupId"]

    if redirect_uri:
        state.redirect = redirect_uri

    params = {}
    for k, v in query_params.items():
        if len(v) != 1:
            return render(request, "dns_grpc/error.html", {
                "error": f"Invalid parameters",
            }, status=400)
        params[k] = v[0]

    records_to_install = []
    records_to_delete = set()
    variables = dict(**params)
    variables["host"] = state.host
    variables["domain"] = zone_obj.zone_root
    variables["fqdn"] = f"{variables['host']}.{variables['domain']}" if state.host else variables["domain"]

    for record in state.template["records"]:
        if state.group_ids and record.get("groupId") not in state.group_ids:
            continue
        try:
            record_host = apply_variables(record["host"], variables)
            if record_host.endswith("."):
                if not record_host[:-1].endswith(zone_obj.zone_root):
                    continue
                else:
                    record_host = record_host[:-(len(zone_obj.zone_root) + 1)]
                    if not record_host:
                        record_host = "@"

            record_ttl = int(record.get("ttl", 86400))
            if record["type"] in ("A", "AAAA"):
                for r in zone_obj.addressrecord_set.filter(
                        record_name=record_host
                ):
                    records_to_delete.add(("addr", r.id))
                for r in zone_obj.dynamicaddressrecord_set.filter(
                        record_name=record_host
                ):
                    records_to_delete.add(("dyn_addr", r.id))
                for r in zone_obj.anamerecord_set.filter(
                        record_name=record_host
                ):
                    records_to_delete.add(("aname", r.id))
                for r in zone_obj.redirectrecord_set.filter(
                        record_name=record_host
                ):
                    records_to_delete.add(("redirect", r.id))
                for r in zone_obj.githubpagesrecord_set.filter(
                        record_name=record_host
                ):
                    records_to_delete.add(("github_pages", r.id))

            if record["type"] == "A":
                record_data = {
                    "address": ipaddress.IPv4Address(
                        apply_variables(record["pointsTo"], variables)
                    )
                }
            elif record["type"] == "AAAA":
                record_data = {
                    "address": ipaddress.IPv6Address(
                        apply_variables(record["pointsTo"], variables)
                    )
                }
            elif record["type"] == "CNAME":
                if not state.host and record_host == "@":
                    continue
                record_data = {
                    "cname": apply_variables(record["pointsTo"], variables)
                }
                conflict_all(zone_obj, record_host, records_to_delete)
            elif record["type"] == "MX":
                record_data = {
                    "priority": int(record["priority"]),
                    "exchange": apply_variables(record["pointsTo"], variables)
                }
                for r in zone_obj.mxrecord_set.filter(
                        record_name=record_host
                ):
                    records_to_delete.add(("mx", r.id))
            elif record["type"] == "TXT":
                record_data = {
                    "text": apply_variables(record["data"], variables)
                }
                conflict_mode = record.get("txtConflictMatchingMode", "None")
                if conflict_mode == "None":
                    pass
                elif conflict_mode == "All":
                    for r in zone_obj.txtrecord_set.filter(
                            record_name=record_host
                    ):
                        records_to_delete.add(("txt", r.id))
                elif conflict_mode == "Prefix":
                    for r in zone_obj.txtrecord_set.filter(
                            record_name=record_host
                    ):
                        if r.data.startswith(record_data["txtConflictMatchingPrefix"]):
                            records_to_delete.add(("txt", r.id))
            elif record["type"] == "SRV":
                record_data = {
                    "priority": int(record["priority"]),
                    "weight": int(record["weight"]),
                    "port": int(record["port"]),
                    "target": apply_variables(record["target"], variables)
                }
                for r in zone_obj.srvrecord_set.filter(
                        record_name=record_host
                ):
                    records_to_delete.add(("srv", r.id))
            elif record["type"] == "NS":
                record_data = {
                    "ns": apply_variables(record["pointsTo"], variables)
                }
                conflict_all(zone_obj, record_host, records_to_delete)
            elif record["type"] == "SPFM":
                record_data = {
                    "new_spf": combine_spf(zone_obj, record_host, apply_variables(record["spfRules"], variables))
                }
                for r in zone_obj.txtrecord_set.filter(
                        record_name=record_host
                ):
                    if r.data.startswith("v=spf1"):
                        records_to_delete.add(("txt", r.id))
            else:
                continue

            records_to_install.append(Record(
                label=record_host,
                type=record["type"],
                ttl=record_ttl,
                data=record_data
            ))
        except (ValueError, IndexError):
            continue

    state.records_to_install = records_to_install
    state.records_to_delete = records_to_delete

    request.session["sync_connect_state"] = dataclasses.asdict(state)

    return redirect("connect_apply_zone")


def apply_variables(string, variables):
    for k, v in variables.items():
        if v:
            string = string.replace(f"%{k}%", v)
    return string

def combine_spf(zone_obj: dns_grpc.models.DNSZone, record_host: str, spf_rules: str) -> str:
    current_rules = set()
    for r in zone_obj.txtrecord_set.filter(
            record_name=record_host
    ):
        if r.data.startswith("v=spf1"):
            spf_txt = r.data.removeprefix("v=spf1 ")
            parts = spf_txt.split(" ")
            for p in parts:
                if p.endswith("all"):
                    continue
                if p:
                    current_rules.add(p)

    for r in spf_rules.split(" "):
        if r:
            current_rules.add(r)

    new_rules = " ".join(list(current_rules))
    return f"v=spf1 {new_rules} ~all"


def conflict_all(zone_obj: dns_grpc.models.DNSZone, record_host: str, records_to_delete: set):
    for r in zone_obj.addressrecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("addr", r.id))
    for r in zone_obj.dynamicaddressrecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("dyn_addr", r.id))
    for r in zone_obj.anamerecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("aname", r.id))
    for r in zone_obj.cnamerecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("cname", r.id))
    for r in zone_obj.redirectrecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("redirect", r.id))
    for r in zone_obj.mxrecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("mx", r.id))
    for r in zone_obj.nsrecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("ns", r.id))
    for r in zone_obj.txtrecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("txt", r.id))
    for r in zone_obj.srvrecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("srv", r.id))
    for r in zone_obj.caarecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("caa", r.id))
    for r in zone_obj.naptrrecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("naptr", r.id))
    for r in zone_obj.sshfprecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("sshfp", r.id))
    for r in zone_obj.dsrecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("ds", r.id))
    for r in zone_obj.dnskeyrecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("dnskey", r.id))
    for r in zone_obj.locrecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("loc", r.id))
    for r in zone_obj.hinforecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("hinfo", r.id))
    for r in zone_obj.rprecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("rp", r.id))
    for r in zone_obj.httpsrecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("https", r.id))
    for r in zone_obj.tlsarecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("tlsa", r.id))
    for r in zone_obj.githubpagesrecord_set.filter(
            record_name=record_host
    ):
        records_to_delete.add(("github_pages", r.id))

def make_redirect_uri(state: SyncConnectState, error: typing.Optional[str]) -> typing.Optional[str]:
    if not state.redirect:
        return None

    parsed_redirect = urllib.parse.urlparse(state.redirect)
    query = urllib.parse.parse_qs(parsed_redirect.query)

    if state.state:
        query["state"] = [state.state]

    if error:
        query["error"] = [error]

    redirect_uri = urllib.parse.urlunparse((
        parsed_redirect.scheme,
        parsed_redirect.netloc,
        parsed_redirect.path,
        parsed_redirect.params,
        urllib.parse.urlencode(query, doseq=True),
        parsed_redirect.fragment
    ))

    return redirect_uri

def apply_updates(zone: dns_grpc.models.DNSZone, state: SyncConnectState):
    for record in state.records_to_install:
        if isinstance(record, dict):
            record = Record(**record)
        if record.type == "A":
            zone.addressrecord_set.create(
                record_name=record.label,
                address=record.data["address"],
                ttl=record.ttl
            )
        elif record.type == "AAAA":
            zone.addressrecord_set.create(
                record_name=record.label,
                address=record.data["address"],
                ttl=record.ttl
            )
        elif record.type == "CNAME":
            zone.cnamerecord_set.create(
                record_name=record.label,
                cname=record.data["cname"],
                ttl=record.ttl
            )
        elif record.type == "MX":
            zone.mxrecord_set.create(
                record_name=record.label,
                priority=record.data["priority"],
                exchange=record.data["exchange"],
                ttl=record.ttl
            )
        elif record.type == "TXT":
            zone.txtrecord_set.create(
                record_name=record.label,
                data=record.data["text"],
                ttl=record.ttl
            )
        elif record.type == "SPFM":
            zone.txtrecord_set.create(
                record_name=record.label,
                data=record.data["new_spf"],
                ttl=record.ttl
            )
        elif record.type == "SRV":
            zone.srvrecord_set.create(
                record_name=record.label,
                priority=record.data["priority"],
                weight=record.data["weight"],
                port=record.data["port"],
                target=record.data["target"],
                ttl=record.ttl
            )
        elif record.type == "NS":
            zone.nsrecord_set.create(
                record_name=record.label,
                ns=record.data["ns"],
                ttl=record.ttl
            )

    for d in state.records_to_delete:
        if d[0] == "addr":
            zone.addressrecord_set.get(id=d[1]).delete()
        elif d[0] == "dyn_addr":
            zone.dynamicaddressrecord_set.get(id=d[1]).delete()
        elif d[0] == "aname":
            zone.anamerecord_set.get(id=d[1]).delete()
        elif d[0] == "cname":
            zone.cnamerecord_set.get(id=d[1]).delete()
        elif d[0] == "redirect":
            zone.redirectrecord_set.get(id=d[1]).delete()
        elif d[0] == "mx":
            zone.mxrecord_set.get(id=d[1]).delete()
        elif d[0] == "ns":
            zone.nsrecord_set.get(id=d[1]).delete()
        elif d[0] == "txt":
            zone.txtrecord_set.get(id=d[1]).delete()
        elif d[0] == "srv":
            zone.srvrecord_set.get(id=d[1]).delete()
        elif d[0] == "caa":
            zone.caarecord_set.get(id=d[1]).delete()
        elif d[0] == "naptr":
            zone.naptrrecord_set.get(id=d[1]).delete()
        elif d[0] == "sshfp":
            zone.sshfprecord_set.get(id=d[1]).delete()
        elif d[0] == "ds":
            zone.dsrecord_set.get(id=d[1]).delete()
        elif d[0] == "dnskey":
            zone.dnskeyrecord_set.get(id=d[1]).delete()
        elif d[0] == "loc":
            zone.locrecord_set.get(id=d[1]).delete()
        elif d[0] == "hinfo":
            zone.hinforecord_set.get(id=d[1]).delete()
        elif d[0] == "rp":
            zone.rprecord_set.get(id=d[1]).delete()
        elif d[0] == "https":
            zone.httpsrecord_set.get(id=d[1]).delete()
        elif d[0] == "tlsa":
            zone.tlsarecord_set.get(id=d[1]).delete()
        elif d[0] == "github_pages":
            zone.githubpagesrecord_set.get(id=d[1]).delete()


@login_required
def apply_zone(request):
    if "sync_connect_state" not in request.session:
        return HttpResponse(status=400)

    state = SyncConnectState(**request.session["sync_connect_state"])

    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_zone = get_object_or_404(dns_grpc.models.DNSZone, id=state.zone_id)

    if not user_zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if request.method == "POST":
        if request.POST["action"] == "apply":
            apply_updates(user_zone, state)
            if "sync_connect_state" in request.session:
                del request.session["sync_connect_state"]
            if r := make_redirect_uri(state, None):
                return redirect(r)
            else:
                return render(request, "connect/done.html", {})
        elif request.POST["action"] == "cancel":
            if "sync_connect_state" in request.session:
                del request.session["sync_connect_state"]
            if r := make_redirect_uri(state, "access_denied"):
                return redirect(r)
            else:
                return render(request, "connect/done.html", {})
        else:
            if "sync_connect_state" in request.session:
                del request.session["sync_connect_state"]
            if r := make_redirect_uri(state, "server_error"):
                return redirect(r)
            else:
                return render(request, "connect/done.html", {})
    else:
        to_delete = []
        for d in state.records_to_delete:
            if d[0] == "addr":
                to_delete.append(str(user_zone.addressrecord_set.get(id=d[1])))
            elif d[0] == "dyn_addr":
                to_delete.append(str(user_zone.dynamicaddressrecord_set.get(id=d[1])))
            elif d[0] == "aname":
                to_delete.append(str(user_zone.anamerecord_set.get(id=d[1])))
            elif d[0] == "cname":
                to_delete.append(str(user_zone.cnamerecord_set.get(id=d[1])))
            elif d[0] == "redirect":
                to_delete.append(str(user_zone.redirectrecord_set.get(id=d[1])))
            elif d[0] == "mx":
                to_delete.append(str(user_zone.mxrecord_set.get(id=d[1])))
            elif d[0] == "ns":
                to_delete.append(str(user_zone.nsrecord_set.get(id=d[1])))
            elif d[0] == "txt":
                to_delete.append(str(user_zone.txtrecord_set.get(id=d[1])))
            elif d[0] == "srv":
                to_delete.append(str(user_zone.srvrecord_set.get(id=d[1])))
            elif d[0] == "caa":
                to_delete.append(str(user_zone.caarecord_set.get(id=d[1])))
            elif d[0] == "naptr":
                to_delete.append(str(user_zone.naptrrecord_set.get(id=d[1])))
            elif d[0] == "sshfp":
                to_delete.append(str(user_zone.sshfprecord_set.get(id=d[1])))
            elif d[0] == "ds":
                to_delete.append(str(user_zone.dsrecord_set.get(id=d[1])))
            elif d[0] == "dnskey":
                to_delete.append(str(user_zone.dnskeyrecord_set.get(id=d[1])))
            elif d[0] == "loc":
                to_delete.append(str(user_zone.locrecord_set.get(id=d[1])))
            elif d[0] == "hinfo":
                to_delete.append(str(user_zone.hinforecord_set.get(id=d[1])))
            elif d[0] == "rp":
                to_delete.append(str(user_zone.rprecord_set.get(id=d[1])))
            elif d[0] == "https":
                to_delete.append(str(user_zone.httpsrecord_set.get(id=d[1])))
            elif d[0] == "tlsa":
                to_delete.append(str(user_zone.tlsarecord_set.get(id=d[1])))
            elif d[0] == "github_pages":
                to_delete.append(str(user_zone.githubpagesrecord_set.get(id=d[1])))

        return render(request, "connect/apply_template.html", {
            "zone": user_zone,
            "template": state.template,
            "records_to_install": state.records_to_install,
            "records_to_delete": to_delete,
        })