from django.core.management.base import BaseCommand

from ... import models


class Command(BaseCommand):
    help = "Synchronises model instances to keycloak resources"
    requires_migrations_checks = True

    def handle(self, *args, **options):

        for zone in models.DNSZone.objects.all():
            zone.save()
        for zone in models.ReverseDNSZone.objects.all():
            zone.save()
        for zone in models.SecondaryDNSZone.objects.all():
            zone.save()
