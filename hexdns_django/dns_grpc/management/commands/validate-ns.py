from django.core.management.base import BaseCommand
from django.conf import settings
from dns_grpc import models
import random
import dnslib

WANTED_NS = [dnslib.DNSLabel('ns1.as207960.net'), dnslib.DNSLabel('ns2.as207960.net')]


def lookup_ns(label, server, port=53):
    question = dnslib.DNSRecord(q=dnslib.DNSQuestion(label, dnslib.QTYPE.NS))
    res_pkt = question.send(server, port=port, ipv6=True, tcp=False)
    res = dnslib.DNSRecord.parse(res_pkt)

    name_servers = list(
        filter(
            lambda r: r.rtype == dnslib.QTYPE.NS and r.rclass == dnslib.CLASS.IN,
            res.auth if len(res.auth) > 0 else res.rr
        )
    )
    if not name_servers:
        return None
    return name_servers


def query_authoritative_ns(domain):
    dns_name = dnslib.DNSLabel(domain)
    ns = lookup_ns(".", settings.RESOLVER_ADDR, port=settings.RESOLVER_PORT)

    last = False
    depth = 1
    while not last:
        cur_dns_name = dnslib.DNSLabel(dns_name.label[-depth:])

        use_ns = random.choice(ns)
        ns = lookup_ns(cur_dns_name, str(use_ns.rdata.label))

        if not ns:
            return None

        if use_ns.rname == dns_name:
            break

        depth += 1

    return ns


class Command(BaseCommand):
    help = 'Checks that every zone is pointed to us'

    def handle(self, *args, **options):
        for zone in models.DNSZone.objects.all():
            try:
                ns = query_authoritative_ns(zone.zone_root)
            except dnslib.DNSError as e:
                print(f"Cant validate {zone}: {e}")
                continue

            if not ns:
                print(f"{zone} does not exist")
                if zone.active:
                    print(f"Setting {zone} to inactive")
                    zone.active = False
                    zone.save()
                continue

            is_valid = all(any(rr.rdata.label == wns for rr in ns) for wns in WANTED_NS)

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
