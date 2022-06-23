from django.core.management.base import BaseCommand
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
)
from cryptography.hazmat.primitives.serialization import load_pem_private_key, PrivateFormat, Encoding, NoEncryption
from dns_grpc import models, views, tasks
import tempfile
import subprocess
import dnslib
import datetime
import ipaddress


class Command(BaseCommand):
    help = "Import DNSSEC keys into Knot's data store"

    def add_arguments(self, parser):
        parser.add_argument('db_path', type=str)

    def get_priv_key_bytes(self, zone):
        if zone.zsk_private:
            priv_key = load_pem_private_key(
                zone.zsk_private.encode(),
                password=None,
                backend=default_backend(),
            )
            if not issubclass(type(priv_key), EllipticCurvePrivateKey):
                raise Exception("Only EC private keys supported")

            return priv_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

        return None

    def handle(self, *args, **options):
        db_path = options["db_path"]
        ts = int(datetime.datetime.now().timestamp())

        for zone in models.DNSZone.objects.all():
            priv_key = self.get_priv_key_bytes(zone)
            if priv_key:
                with tempfile.NamedTemporaryFile(mode="wb") as f:
                    f.write(priv_key)
                    f.flush()
                    subprocess.call([
                        "keymgr", "-d", db_path, str(dnslib.DNSLabel(zone.zone_root)), "import-pem", f.name, "zsk=yes",
                        f"active={ts}", f"ready={ts}"
                    ])

        for zone in models.ReverseDNSZone.objects.all():
            priv_key = self.get_priv_key_bytes(zone)
            if priv_key:
                zone_network = ipaddress.ip_network(
                    (zone.zone_root_address, zone.zone_root_prefix)
                )
                zone_root = tasks.network_to_apra(zone_network)

                with tempfile.NamedTemporaryFile(mode="wb") as f:
                    f.write(priv_key)
                    f.flush()
                    subprocess.call([
                        "keymgr", "-d", db_path, str(zone_root), "import-pem", f.name, "zsk=yes",
                        f"active={ts}", f"ready={ts}"
                    ])