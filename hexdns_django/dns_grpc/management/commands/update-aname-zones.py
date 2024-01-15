from django.core.management.base import BaseCommand
from django.conf import settings
from django.db import transaction
from dns_grpc import models, tasks
import dnslib
import socket
import struct


class Command(BaseCommand):
    help = "Update caches and zone files for ANAME records"

    def handle(self, *args, **options):
        for zone in models.DNSZone.objects.all():
            zone_root = dnslib.DNSLabel(zone.zone_root)
            updated = False

            for record in zone.anamerecord_set.all():
                alias_label = dnslib.DNSLabel(record.alias)

                if not alias_label.matchSuffix(zone_root):
                    question_a = dnslib.DNSRecord(q=dnslib.DNSQuestion(record.alias, dnslib.QTYPE.A))
                    question_aaaa = dnslib.DNSRecord(q=dnslib.DNSQuestion(record.alias, dnslib.QTYPE.AAAA))
                    try:
                        res_pkt_a = question_a.send(
                            settings.RESOLVER_NO_DNS64_ADDR, port=settings.RESOLVER_NO_DNS64_PORT,
                            ipv6=settings.RESOLVER_NO_DNS64_IPV6, tcp=True, timeout=30
                        )
                        res_pkt_aaaa = question_aaaa.send(
                            settings.RESOLVER_NO_DNS64_ADDR, port=settings.RESOLVER_NO_DNS64_PORT,
                            ipv6=settings.RESOLVER_NO_DNS64_IPV6, tcp=True, timeout=30
                        )
                    except socket.timeout:
                        print(f"Failed to get address for {record.alias}: timeout")
                        continue
                    except struct.error as e:
                        print(f"Failed to get address for {record.alias}: invalid response ({e})")
                        continue
                    res_a = dnslib.DNSRecord.parse(res_pkt_a)
                    res_aaaa = dnslib.DNSRecord.parse(res_pkt_aaaa)

                    with transaction.atomic():
                        record.cached.all().delete()
                        for rr in res_a.rr:
                            if rr.rtype == dnslib.QTYPE.A:
                                models.ANAMERecordCache(record=record, address=str(rr.rdata)).save()
                        for rr in res_aaaa.rr:
                            if rr.rtype == dnslib.QTYPE.AAAA:
                                models.ANAMERecordCache(record=record, address=str(rr.rdata)).save()

                    updated = True

            if updated:
                tasks.update_fzone.delay(zone.id)

        tasks.update_catalog.delay()
