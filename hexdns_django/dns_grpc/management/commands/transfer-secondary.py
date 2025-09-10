from django.core.management.base import BaseCommand
from dns_grpc import models, tasks


class Command(BaseCommand):
    help = 'Updates records from primary name servers'

    def handle(self, *args, **options):
        for zone in models.SecondaryDNSZone.objects.all():
            tasks.sync_secondary.delay(zone.id)