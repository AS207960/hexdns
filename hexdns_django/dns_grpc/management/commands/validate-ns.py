from django.core.management.base import BaseCommand
from django.conf import settings
from dns_grpc import models
import dnslib

WANTED_NS = [dnslib.DNSLabel('ns1.as207960.net'), dnslib.DNSLabel('ns2.as207960.net')]


class Command(BaseCommand):
    help = 'Checks that every zone is pointed to us'

    def handle(self, *args, **options):
        for zone in models.DNSZone.objects.all():
            try:
                question = dnslib.DNSRecord.question(zone.zone_root, "NS")
                res_pkt = question.send(settings.RESOLVER_ADDR, port=settings.RESOLVER_PORT, ipv6=True, tcp=True)
                res = dnslib.DNSRecord.parse(res_pkt)
            except dnslib.DNSError as e:
                print(f"Cant validate {zone}: {e}")
                continue

            if res.header.rcode == dnslib.RCODE.NXDOMAIN:
                print(f"{zone} does not exist")
                if zone.active:
                    print(f"Setting {zone} to inactive")
                    zone.active = False
                    zone.save()
                continue
            elif res.header.rcode != dnslib.RCODE.NOERROR:
                print(f"Error response querying {zone}")
                continue

            rr = list(map(
                lambda r: r.rdata.label,
                filter(lambda r: r.rtype == dnslib.QTYPE.NS and r.rclass == dnslib.CLASS.IN, res.rr)
            ))
            is_valid = all(ns in rr for ns in WANTED_NS)

            if is_valid:
                print(f"{zone} is valid")
                if not zone.active:
                    print(f"Setting {zone} to active")
                    zone.active = True
                    zone.save()
            else:
                print(f"{zone} is invalid")
                if zone.active:
                    print(f"Setting {zone} to inactive")
                    zone.active = False
                    zone.save()
