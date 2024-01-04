from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db.models import Q
from dns_grpc import models, tasks


class Command(BaseCommand):
    help = "DNSSEC resigning of all zones that haven't been signed in 7 days"

    def handle(self, *args, **options):
        now = timezone.now()
        last_resign_cutoff = now - timezone.timedelta(days=1)

        for zone in models.DNSZone.objects.filter(
            Q(last_resign__lt=last_resign_cutoff) | Q(last_resign__isnull=True)
        ):
            print(f"Updating forward zone {zone.zone_root} - {zone.id}")
            tasks.update_fzone.delay(zone.id)

        for zone in models.ReverseDNSZone.objects.filter(
            Q(last_resign__lt=last_resign_cutoff) | Q(last_resign__isnull=True)
        ):
            print(f"Updating reverse zone {zone.zone_root_address}/{zone.zone_root_prefix} - {zone.id}")
            tasks.update_rzone.delay(zone.id)
