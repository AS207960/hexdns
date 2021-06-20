import dnslib
import datetime
import django

django.setup()

from . import models, grpc


def application(environ: dict, start_response):
    headers = [
        ("Server", "HexDNS Redirect Server")
    ]

    host = environ.get("HTTP_HOST")

    if not host:
        start_response("404 Not Found", headers)
        return []

    host_parts = host.split(":", 1)
    host_dns_label = dnslib.DNSLabel(host_parts[0])
    zone, record_name = grpc.DnsServiceServicer.find_zone(host_dns_label)

    if not zone:
        start_response("404 Not Found", headers)
        return []

    redirect_record = grpc.DnsServiceServicer.find_records(models.RedirectRecord, record_name, zone).first()
    if not redirect_record:
        start_response("404 Not Found", headers)
        return []

    headers.append(("Location", redirect_record.target))

    now = datetime.datetime.utcnow()
    expiry = now + datetime.timedelta(seconds=redirect_record.ttl)
    headers.append(("Date", now.strftime("%a, %d %b %Y %H:%M:%S GMT")))
    headers.append(("Expires", expiry.strftime("%a, %d %b %Y %H:%M:%S GMT")))

    start_response("308 Permanent Redirect", headers)
    return []
