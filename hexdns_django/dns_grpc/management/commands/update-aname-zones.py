from django.core.management.base import BaseCommand
from dns_grpc import models, tasks


class Command(BaseCommand):
    help = "Force an update of any zones using ANAME records"

    def handle(self, *args, **options):
        for zone in models.DNSZone.objects.filter():
            if zone.anamerecord_set.count() > 0:
                tasks.update_fzone.delay(zone.id)

        tasks.update_catalog.delay()
