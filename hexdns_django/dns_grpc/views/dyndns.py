import ipaddress
import base64
import uuid
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
from .. import models


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
