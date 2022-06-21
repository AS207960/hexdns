from django.core.management.base import BaseCommand
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
)
from cryptography.hazmat.primitives.serialization import load_pem_private_key, PrivateFormat, Encoding, NoEncryption
from dns_grpc import models, views
import tempfile
import subprocess
import dnslib


class Command(BaseCommand):
    help = "Import DNSSEC keys into Knot's data store"

    def add_arguments(self, parser):
        parser.add_argument('db_path', type=str)

    def handle(self, *args, **options):
        db_path = options["db_path"]

        for zone in models.DNSZone.objects.all():
            if zone.zsk_private:
                priv_key = load_pem_private_key(
                    zone.zsk_private.encode(),
                    password=None,
                    backend=default_backend(),
                )
                if not issubclass(type(priv_key), EllipticCurvePrivateKey):
                    raise Exception("Only EC private keys supported")

                priv_key = priv_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

                with tempfile.NamedTemporaryFile(mode="wb") as f:
                    f.write(priv_key)
                    f.flush()
                    subprocess.call([
                        "keymgr", "-d", db_path, str(dnslib.DNSLabel(zone.zone_root)), "import-pem", f.name, "zsk=yes",
                    ])