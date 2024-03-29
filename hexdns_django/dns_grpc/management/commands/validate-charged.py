from django.core.management.base import BaseCommand
from django.conf import settings
import django_keycloak_auth.clients
from dns_grpc import models
import requests
import requests.exceptions
import keycloak.exceptions
import dns_grpc.utils


class Command(BaseCommand):
    help = 'Checks that every non charged zone is accessible by the user'

    def handle(self, *args, **options):
        user_zones = {}

        for zone in models.DNSZone.objects.all():
            try:
                user = zone.get_user()
            except (models.Account.DoesNotExist, keycloak.exceptions.KeycloakClientError, requests.exceptions.RequestException):
                continue

            if user.username not in user_zones:
                user_zones[user.username] = {
                    "user": user,
                    "zones": [zone]
                }
            else:
                user_zones[user.username]["zones"].append(zone)

        for user, data in user_zones.items():
            client_token = django_keycloak_auth.clients.get_access_token()
            r = requests.put(f"{settings.DOMAINS_URL}/api/internal/domains/{user}/", json={
                "domains": list(map(lambda z: {
                    "domain": z.zone_root
                }, data["zones"]))
            }, headers={
                "Authorization": f"Bearer {client_token}"
            })
            if r.status_code == 404:
                for zone in data["zones"]:
                    if not zone.charged:
                        print(f"Setting {zone.zone_root} to charged")
                        zone.charged = True
                        zone.save()
                continue

            r.raise_for_status()
            rdata = r.json()
            domains = {}
            for domain in rdata["domains"]:
                domains[domain["domain"]] = domain["access"]

            for zone in data["zones"]:
                if zone.zone_root in domains:
                    if not domains[zone.zone_root] and not zone.charged:
                        print(f"Setting {zone.zone_root} to charged")
                        zone.charged = True
                        zone.save()
                    elif domains[zone.zone_root] and zone.charged:
                        print(f"Setting {zone.zone_root} to uncharged")
                        zone.charged = False
                        zone.save()

            dns_grpc.utils.log_usage(data["user"], off_session=True)
