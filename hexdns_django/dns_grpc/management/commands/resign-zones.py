from django.core.management.base import BaseCommand
from dns_grpc import models, tasks, apps
import ipaddress
import dnslib


class Command(BaseCommand):
    help = "Force DNSSEC resigning of all zones"

    def handle(self, *args, **options):
        pika_client = apps.PikaClient()
        labels = []

        for zone in models.DNSZone.objects.all():
            labels.append(dnslib.DNSLabel(zone.zone_root))

        for zone in models.ReverseDNSZone.objects.all():
            zone_network = ipaddress.ip_network(
                (zone.zone_root_address, zone.zone_root_prefix)
            )
            zone_root = tasks.network_to_apra(zone_network)
            labels.append(zone_root)

        def pub(channel):
            channel.exchange_declare(exchange='hexdns_primary_resign', exchange_type='fanout', durable=True)

            for label in labels:
                channel.basic_publish(exchange='hexdns_primary_resign', routing_key='', body=str(label).encode())

        pika_client.get_channel(pub)
