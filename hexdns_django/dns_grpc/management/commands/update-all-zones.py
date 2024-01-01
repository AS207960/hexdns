from django.core.management.base import BaseCommand
from django.utils import timezone
from dns_grpc import models, tasks


class Command(BaseCommand):
    help = "DNSSEC resigning of all zones that haven't been signed in 7 days"

    def handle(self, *args, **options):
        now = timezone.now()
        last_resign_cutoff = now - timezone.timedelta(days=1)

        for zone in models.DNSZone.objects.filter(
            last_resign__lt=last_resign_cutoff
        ):
            tasks.update_fzone.delay(zone.id)

        for zone in models.ReverseDNSZone.objects.filter(
            last_resign__lt=last_resign_cutoff
        ):
            tasks.update_rzone.delay(zone.id)
