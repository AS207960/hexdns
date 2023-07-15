from celery import shared_task
from django.conf import settings
from . import models, apps, utils
import dnslib
import base64
import ipaddress
import hashlib
import typing
import time
import re
import idna
import string
import requests.exceptions
import keycloak.exceptions
import os
import tempfile
import storages.backends.s3boto3
import django.core.files.base
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey,
)

NAMESERVERS = ["ns1.as207960.net.", "ns2.as207960.net."]
IP_NETWORK = typing.Union[ipaddress.IPv6Network, ipaddress.IPv4Network]
IP_ADDR = typing.Union[ipaddress.IPv6Address, ipaddress.IPv4Address]

pika_client = apps.PikaClient()


class ZoneStorage(storages.backends.s3boto3.S3Boto3Storage):
    bucket_name = settings.ZONE_STORAGE_BUCKET


def network_to_apra(network: IP_NETWORK) -> dnslib.DNSLabel:
    if type(network) == ipaddress.IPv6Network:
        return dnslib.DNSLabel(
            list(
                map(
                    lambda l: l.encode(),
                    list(
                        reversed(
                            network.network_address.exploded.replace(":", "")[
                            : (network.prefixlen + 3) // 4
                            ]
                        )
                    )
                    + ["ip6", "arpa"],
                )
            )
        )
    elif type(network) == ipaddress.IPv4Network:
        return dnslib.DNSLabel(
            list(
                map(
                    lambda l: l.encode(),
                    list(
                        reversed(
                            network.network_address.exploded.split(".")[
                            : (network.prefixlen + 7) // 8
                            ]
                        )
                    )
                    + ["in-addr", "arpa"],
                )
            )
        )


def address_to_apra(address: IP_ADDR) -> dnslib.DNSLabel:
    if type(address) == ipaddress.IPv6Address:
        return dnslib.DNSLabel(
            list(
                map(
                    lambda l: l.encode(),
                    list(reversed(address.exploded.replace(":", ""))) + ["ip6", "arpa"],
                )
            )
        )
    elif type(address) == ipaddress.IPv4Address:
        return dnslib.DNSLabel(
            list(
                map(
                    lambda l: l.encode(),
                    list(reversed(address.exploded.split("."))) + ["in-addr", "arpa"],
                )
            )
        )


def make_key_tag(public_key: EllipticCurvePublicKey, flags=256):
    buffer = dnslib.DNSBuffer()
    nums = public_key.public_numbers()
    rd = dnslib.DNSKEY(
        flags,
        3,
        13,
        nums.x.to_bytes(32, byteorder="big") + nums.y.to_bytes(32, byteorder="big"),
    )
    rd.pack(buffer)
    tag = 0
    for i in range(len(buffer.data) // 2):
        tag += (buffer.data[2 * i] << 8) + buffer.data[2 * i + 1]
    if len(buffer.data) % 2 != 0:
        tag += buffer.data[len(buffer.data) - 1] << 8
    tag += (tag >> 16) & 0xFFFF
    tag = tag & 0xFFFF
    return tag


def encode_str(data):
    return "".join(c if ord(c) < 128 else "".join(f'\\{b}' for b in c.encode()) for c in data.replace("\"", "\\\""))


def dd_to_dms(dd: float) -> typing.Tuple[int, int, float]:
    d1 = int(dd)
    m1 = int((dd - d1) * 60)
    s1 = round(abs((dd - d1 - m1 / 60) * 3600), 3)
    return abs(d1), abs(m1), s1


def generate_zone_header(zone, zone_root):
    if hasattr(zone, "custom_ns") and zone.custom_ns.count():
        primary_ns = dnslib.DNSLabel(zone.custom_ns.first().nameserver)
    else:
        primary_ns = NAMESERVERS[0]

    zone_file = f"$ORIGIN {zone_root}\n"
    zone_file += f"@ 86400 IN SOA {primary_ns} noc.as207960.net. {int(time.time())} " \
                 f"86400 3600 86400 3600\n"

    if hasattr(zone, "custom_ns") and zone.custom_ns.count():
        for ns in zone.custom_ns.all():
            zone_file += f"@ 86400 IN NS {dnslib.DNSLabel(ns.nameserver)}\n"
    else:
        for ns in NAMESERVERS:
            zone_file += f"@ 86400 IN NS {ns}\n"

    if zone.cds_disable:
        zone_file += "@ 86400 IN CDS 0 0 0 00\n"
        zone_file += "@ 86400 IN CDNSKEY 0 3 0 AA==\n"
    else:
        digest, tag = utils.make_zone_digest(zone_root)
        dnskey_bytes = utils.get_dnskey().key

        zone_file += f"@ 86400 IN CDS {tag} 13 2 {digest}\n"

        for cds in zone.additional_cds.all():
            zone_file += f"; Additional CDS {cds.id}\n"
            zone_file += f"@ 86400 IN CDS {cds.key_tag} {cds.algorithm} {cds.digest_type} {cds.digest}\n"

        zone_file += f"@ 86400 IN CDNSKEY 257 3 13 {base64.b64encode(dnskey_bytes).decode()}\n"

        for cdnskey in zone.additional_cdnskey.all():
            zone_file += f"; Additional CDNSKEY {cdnskey.id}\n"
            zone_file += f"@ 86400 IN CDNSKEY {cdnskey.flags} {cdnskey.protocol} {cdnskey.algorithm} " \
                         f"{cdnskey.public_key}\n"

    return zone_file


def generate_fzone(zone: "models.DNSZone"):
    zone_root = dnslib.DNSLabel(zone.zone_root)
    zone_file = generate_zone_header(zone, zone_root)

    rzones = set()
    for record in zone.addressrecord_set.all():
        record_name = record.idna_label
        if record_name:
            zone_file += f"; Address record {record.id}\n"
            address = ipaddress.ip_address(record.address)
            if type(address) == ipaddress.IPv4Address:
                zone_file += f"{record_name} {record.ttl} IN A {address}\n"
            elif type(address) == ipaddress.IPv6Address:
                zone_file += f"{record_name} {record.ttl} IN AAAA {address}\n"

            if record.auto_reverse:
                for rzone in models.ReverseDNSZone.objects.raw(
                    "SELECT * FROM dns_grpc_reversednszone WHERE ("
                    "inet %s << CAST("
                    "(string_to_array(zone_root_address::string, '/')[1] || '/'"
                    " || zone_root_prefix) AS inet))",
                    [str(address)]
                ):
                    rzones.add(rzone.id)

    for rzone in rzones:
        update_rzone.delay(rzone)

    for record in zone.dynamicaddressrecord_set.all():
        record_name = record.idna_label
        if record_name:
            zone_file += f"; Dynamic address record {record.id}\n"
            if record.current_ipv4:
                zone_file += f"{record_name} {record.ttl} IN A {record.current_ipv4}\n"
            if record.current_ipv6:
                zone_file += f"{record_name} {record.ttl} IN AAAA {record.current_ipv6}\n"

    for record in zone.anamerecord_set.all():
        record_name = record.idna_label
        if record_name:
            zone_file += f"; ANAME record {record.id}\n"
            alias_label = dnslib.DNSLabel(record.alias)

            if alias_label.matchSuffix(zone_root):
                own_record_name = alias_label.stripSuffix(zone_root)
                search_name = ".".join(map(lambda n: n.decode(), own_record_name.label))
                own_records = zone.addressrecord_set.filter(record_name=search_name)
                for r in own_records:
                    address = ipaddress.ip_address(r.address)
                    if type(address) == ipaddress.IPv4Address:
                        zone_file += f"{record_name} {record.ttl} IN A {address}\n"
                    elif type(address) == ipaddress.IPv6Address:
                        zone_file += f"{record_name} {record.ttl} IN AAAA {address}\n"
            else:
                for r in record.cached.all():
                    address = ipaddress.ip_address(r.address)
                    if type(address) == ipaddress.IPv4Address:
                        zone_file += f"{record_name} {record.ttl} IN A {address}\n"
                    elif type(address) == ipaddress.IPv6Address:
                        zone_file += f"{record_name} {record.ttl} IN AAAA {address}\n"

    for record in zone.githubpagesrecord_set.all():
        record_name = record.idna_label
        if record_name:
            zone_file += f"; Github pages record {record.id}\n"
            zone_file += f"{record_name} {record.ttl} IN A 185.199.108.153\n"
            zone_file += f"{record_name} {record.ttl} IN A 185.199.109.153\n"
            zone_file += f"{record_name} {record.ttl} IN A 185.199.110.153\n"
            zone_file += f"{record_name} {record.ttl} IN A 185.199.111.153\n"
            zone_file += f"{record_name} {record.ttl} IN AAAA 2606:50c0:8000::153\n"
            zone_file += f"{record_name} {record.ttl} IN AAAA 2606:50c0:8001::153\n"
            zone_file += f"{record_name} {record.ttl} IN AAAA 2606:50c0:8002::153\n"
            zone_file += f"{record_name} {record.ttl} IN AAAA 2606:50c0:8003::153\n"

    for record in zone.cnamerecord_set.all():
        record_name = record.idna_label
        if record_name:
            if record.alias == "@":
                alias = zone_root
            else:
                try:
                    alias = dnslib.DNSLabel(idna.encode(record.alias, uts46=True))
                except idna.IDNAError:
                    if all(ord(c) < 127 and c in string.printable for c in record.alias):
                        alias = dnslib.DNSLabel(record.alias)
                    else:
                        continue

            zone_file += f"; CNAME record {record.id}\n"
            zone_file += f"{record_name} {record.ttl} IN CNAME {alias}\n"

    for record in zone.redirectrecord_set.all():
        record_name = record.idna_label
        if record_name:
            zone_file += f"; Redirect record {record.id}\n"
            zone_file += f"{record_name} {record.ttl} IN A 45.129.95.254\n"
            zone_file += f"{record_name} {record.ttl} IN AAAA 2a0e:1cc1:1::1:7\n"
            zone_file += f"{record_name} {record.ttl} IN CAA 0 iodef \"mailto:noc@as207960.net\"\n"
            zone_file += f"{record_name} {record.ttl} IN CAA 0 issue \"pki.goog\"\n"
            zone_file += f"{record_name} {record.ttl} IN CAA 0 issue \"letsencrypt.org\"\n"

    for record in zone.mxrecord_set.all():
        record_name = record.idna_label
        if record_name:
            zone_file += f"; MX record {record.id}\n"
            zone_file += f"{record_name} {record.ttl} IN MX {record.priority} {dnslib.DNSLabel(record.exchange)}\n"

    for record in zone.nsrecord_set.all():
        record_name = record.idna_label
        if record_name:
            zone_file += f"; NS record {record.id}\n"
            zone_file += f"{record_name} {record.ttl} IN NS {dnslib.DNSLabel(record.nameserver)}\n"

    for record in zone.txtrecord_set.all():
        record_name = record.idna_label
        if record_name:
            zone_file += f"; TXT record {record.id}\n"
            zone_file += f"{record_name} {record.ttl} IN TXT \"{encode_str(record.data)}\"\n"

    for record in zone.srvrecord_set.all():
        record_name = record.idna_label
        if record_name:
            zone_file += f"; SRV record {record.id}\n"
            zone_file += f"{record_name} {record.ttl} IN SRV {record.priority} {record.weight} {record.port} " \
                         f"{dnslib.DNSLabel(record.target)}\n"

    for record in zone.caarecord_set.all():
        record_name = record.idna_label
        if record_name:
            zone_file += f"; CAA record {record.id}\n"
            zone_file += f"{record_name} {record.ttl} IN CAA {record.flag} \"{encode_str(record.tag)}\" " \
                         f"\"{encode_str(record.value)}\"\n"

    for record in zone.naptrrecord_set.all():
        record_name = record.idna_label
        if record_name:
            zone_file += f"; NAPTR record {record.id}\n"
            zone_file += f"{record_name} {record.ttl} IN NAPTR {record.order} {record.preference} " \
                         f"\"{encode_str(record.flags)}\" \"{encode_str(record.service)}\" " \
                         f"\"{encode_str(record.regexp) if record.regexp else ''}\" " \
                         f"{dnslib.DNSLabel(record.replacement)}\n"

    for record in zone.sshfprecord_set.all():
        record_name = record.idna_label
        if record_name:
            pubkey = record.key
            if pubkey.key_type == b"ssh-rsa":
                algo_num = 1
            elif pubkey.key_type == b"ssh-dsa":
                algo_num = 2
            elif pubkey.key_type.startswith(b"ecdsa-sha"):
                algo_num = 3
            elif pubkey.key_type == b"ssh-ed25519":
                algo_num = 4
            else:
                continue

            zone_file += f"; SSHFP record {record.id}\n"
            zone_file += f"{record_name} {record.ttl} IN SSHFP {algo_num} 1 " \
                         f"{hashlib.sha1(pubkey._decoded_key).hexdigest()}\n"
            zone_file += f"{record_name} {record.ttl} IN SSHFP {algo_num} 2 " \
                         f"{hashlib.sha256(pubkey._decoded_key).hexdigest()}\n"

    for record in zone.dsrecord_set.all():
        record_name = record.idna_label
        if record_name:
            zone_file += f"; DS record {record.id}\n"
            zone_file += f"{record_name} {record.ttl} IN DS {record.key_tag} {record.algorithm} " \
                         f"{record.digest_type} {record.digest}\n"

    for record in zone.locrecord_set.all():
        record_name = record.idna_label
        if record_name:
            d1, m1, s1 = dd_to_dms(record.latitude)
            d2, m2, s2 = dd_to_dms(record.longitude)
            ns = "S" if record.latitude < 0 else "N"
            ew = "W" if record.longitude < 0 else "E"

            zone_file += f"; LOC record {record.id}\n"
            zone_file += f"{record_name} {record.ttl} IN LOC {d1} {m1} {s1} {ns} {d2} {m2} {s2} {ew} " \
                         f"{record.altitude}m {record.size}m {record.hp}m {record.vp}m\n"

    for record in zone.hinforecord_set.all():
        record_name = record.idna_label
        if record_name:
            zone_file += f"; HINFO record {record.id}\n"
            zone_file += f"{record_name} {record.ttl} IN HINFO \"{encode_str(record.cpu)}\" " \
                         f"\"{encode_str(record.os)}\"\n"

    for record in zone.rprecord_set.all():
        record_name = record.idna_label
        if record_name:
            zone_file += f"; RP record {record.id}\n"
            zone_file += f"{record_name} {record.ttl} IN RP {dnslib.DNSLabel(record.mailbox)} " \
                         f"{dnslib.DNSLabel(record.txt)}\n"

    for record in zone.httpsrecord_set.all():
        svcb_record = record.svcb_record
        buf = dnslib.DNSBuffer()
        svcb_record.pack(buf)
        data = bytes(buf.data)
        zone_file += f"; HTTPS record {record.id}\n"
        zone_file += f"{record.svcb_record_name} {record.ttl} IN TYPE65 \# {len(data)} {data.hex()}\n"

    for record in zone.dhcidrecord_set.all():
        record_name = record.idna_label
        if record_name:
            zone_file += f"; DHCID record {record.id}\n"
            zone_file += f"{record_name} {record.ttl} IN DHCID {base64.b64encode(record.data).decode()}\n"

    return zone_file


def generate_rzone(zone: "models.ReverseDNSZone"):
    zone_network = ipaddress.ip_network(
        (zone.zone_root_address, zone.zone_root_prefix)
    )
    zone_root = network_to_apra(zone_network)
    zone_file = generate_zone_header(zone, zone_root)
    account = zone.get_user().account.id

    for record in zone.ptrrecord_set.all():
        zone_file += f"; PTR record {record.id}\n"
        zone_file += f"{address_to_apra(ipaddress.ip_address(record.record_address))} {record.ttl} IN PTR " \
                     f"{dnslib.DNSLabel(record.pointer)}\n"

    for record in zone.reversensrecord_set.all():
        zone_file += f"; NS record {record.id}\n"
        zone_file += f"{record.record_prefix}.{zone_root} {record.ttl} IN NS " \
                     f"{dnslib.DNSLabel(record.nameserver)}\n"

    zones = {}
    for record in models.AddressRecord.objects.raw(
            "SELECT * FROM dns_grpc_addressrecord WHERE (auto_reverse AND address << inet %s)",
            [str(zone_network)]
    ):
        if record.zone.id in zones:
            account2 = zones[record.zone.id]
        else:
            account2 = record.zone.get_user().account.id
            zones[record.zone.id] = account2
        if account2 == account:
            zone_ptr = dnslib.DNSLabel(f"{record.record_name}.{record.zone.zone_root}")
            zone_file += f"; Address record {record.id}\n"
            zone_file += f"{address_to_apra(ipaddress.ip_address(record.address))} {record.ttl} IN PTR {zone_ptr}\n"

    return zone_file


def generate_szone(zone: "models.SecondaryDNSZone"):
    zone_root = dnslib.DNSLabel(zone.zone_root)
    zone_file = f"$ORIGIN {zone_root}\n"

    for record in zone.secondarydnszonerecord_set.all():
        zone_file += f"; Record {record.id}\n"
        zone_file += f"{record.record_text}\n"

    return zone_file


def write_zone_file(zone_contents: str, zone_name: str):
    zone_storage = ZoneStorage()
    zone_storage.save(
        f"{zone_name}zone", django.core.files.base.ContentFile(zone_contents.encode())
    )
    

def send_reload_message(label: dnslib.DNSLabel):
    global pika_client

    def pub(channel):
        channel.exchange_declare(exchange='hexdns_primary_reload', exchange_type='fanout', durable=True)
        channel.basic_publish(exchange='hexdns_primary_reload', routing_key='', body=str(label).encode())

    pika_client.get_channel(pub)


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def add_fzone(zone_id: str):
    try:
        zone = models.DNSZone.objects.get(id=zone_id)
    except models.DNSZone.DoesNotExist:
        return

    pattern = re.compile("^[a-zA-Z0-9-.]+$")
    if pattern.match(zone.zone_root):
        zone_root = dnslib.DNSLabel(zone.zone_root)
        zone_file = generate_fzone(zone)
        write_zone_file(zone_file, str(zone_root))
        update_catalog.delay()


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def update_fzone(zone_id: str):
    try:
        zone = models.DNSZone.objects.get(id=zone_id)
    except models.DNSZone.DoesNotExist:
        return

    pattern = re.compile("^[a-zA-Z0-9-.]+$")
    if pattern.match(zone.zone_root):
        zone_root = dnslib.DNSLabel(zone.zone_root)
        zone_file = generate_fzone(zone)
        write_zone_file(zone_file, str(zone_root))
        send_reload_message(zone_root)


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def add_rzone(zone_id: str):
    try:
        zone = models.ReverseDNSZone.objects.get(id=zone_id)
    except models.ReverseDNSZone.DoesNotExist:
        return

    zone_file = generate_rzone(zone)
    zone_network = ipaddress.ip_network(
        (zone.zone_root_address, zone.zone_root_prefix)
    )
    zone_root = network_to_apra(zone_network)
    write_zone_file(zone_file, str(zone_root))
    update_catalog.delay()


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def update_rzone(zone_id: str):
    try:
        zone = models.ReverseDNSZone.objects.get(id=zone_id)
    except models.ReverseDNSZone.DoesNotExist:
        return

    zone_file = generate_rzone(zone)
    zone_network = ipaddress.ip_network(
        (zone.zone_root_address, zone.zone_root_prefix)
    )
    zone_root = network_to_apra(zone_network)
    write_zone_file(zone_file, str(zone_root))
    send_reload_message(zone_root)


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def add_szone(zone_id: str):
    try:
        zone = models.SecondaryDNSZone.objects.get(id=zone_id)
    except models.SecondaryDNSZone.DoesNotExist:
        return

    zone_root = dnslib.DNSLabel(zone.zone_root)
    zone_file = generate_szone(zone)
    write_zone_file(zone_file, str(zone_root))
    update_catalog.delay()


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def update_szone(zone_id: str):
    try:
        zone = models.SecondaryDNSZone.objects.get(id=zone_id)
    except models.SecondaryDNSZone.DoesNotExist:
        return

    zone_root = dnslib.DNSLabel(zone.zone_root)
    zone_file = generate_szone(zone)
    write_zone_file(zone_file, str(zone_root))
    send_reload_message(zone_root)


def is_active(zone):
    try:
        user = zone.get_user()
        if not user:
           return True
        return user.account.subscription_active
    except models.Account.DoesNotExist:
        return False
    except (keycloak.exceptions.KeycloakClientError, requests.exceptions.RequestException):
        return True


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def update_signal_zones():
    pattern = re.compile("^[a-zA-Z0-9-.]+$")

    for ns in NAMESERVERS:
        zone_root = dnslib.DNSLabel(f"_signal.{ns}")

        zone_file = f"$ORIGIN {zone_root}\n"
        zone_file += f"@ 86400 IN SOA {NAMESERVERS[0]} noc.as207960.net. {int(time.time())} " \
                     f"86400 3600 3600000 3600\n"

        for ns2 in NAMESERVERS:
            zone_file += f"@ 86400 IN NS {ns2}\n"

        for zone in models.DNSZone.objects.all():
            if pattern.match(zone.zone_root):
                cds_zone_root = dnslib.DNSLabel(zone.zone_root)
                zone_file += f"; Zone {zone.id}\n"

                if zone.cds_disable:
                    zone_file += f"_dsboot.{str(cds_zone_root)}_signal 86400 IN CDS 0 0 0 00\n"
                    zone_file += f"_dsboot.{str(cds_zone_root)}_signal 86400 IN CDNSKEY 0 3 0 AA==\n"
                else:
                    digest, tag = utils.make_zone_digest(zone.zone_root)
                    dnskey_bytes = utils.get_dnskey().key

                    zone_file += f"_dsboot.{str(cds_zone_root)}_signal 86400 IN CDS {tag} 13 2 {digest}\n"

                    for cds in zone.additional_cds.all():
                        zone_file += f"; Additional CDS {cds.id}\n"
                        zone_file += f"_dsboot.{str(cds_zone_root)}_signal 86400 IN CDS {cds.key_tag} {cds.algorithm} {cds.digest_type} {cds.digest}\n"

                    zone_file += f"_dsboot.{str(cds_zone_root)}_signal 86400 IN CDNSKEY 257 3 13 {base64.b64encode(dnskey_bytes).decode()}\n"

                    for cdnskey in zone.additional_cdnskey.all():
                        zone_file += f"; Additional CDNSKEY {cdnskey.id}\n"
                        zone_file += f"_dsboot.{str(cds_zone_root)}_signal 86400 IN CDNSKEY {cdnskey.flags} {cdnskey.protocol} {cdnskey.algorithm} " \
                                     f"{cdnskey.public_key}\n"

        write_zone_file(zone_file, str(zone_root))
        send_reload_message(zone_root)


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def update_catalog():
    zone_file = "$ORIGIN catalog.dns.as207960.ltd.uk.\n"
    zone_file += f"@ 0 IN SOA invalid. noc.as207960.net {int(time.time())} 3600 600 2147483646 0\n"
    zone_file += "@ 0 IN NS invalid.\n"
    zone_file += "version 0 IN TXT \"2\"\n"

    for i, ns in enumerate(NAMESERVERS):
        zone_file += f"signal{i}.zones 0 IN PTR _signal.{ns}\n"
        zone_file += f"group.signal{i}.zones 0 IN TXT \"zone\"\n"

    pattern = re.compile("^[a-zA-Z0-9-.]+$")

    for zone in models.DNSZone.objects.all():
        if pattern.match(zone.zone_root):
            zone_root = dnslib.DNSLabel(zone.zone_root)
            if is_active(zone):
                zone_file += f"{zone.id}.zones 0 IN PTR {zone_root}\n"
                if zone.cds_disable:
                    zone_file += f"group.{zone.id}.zones 0 IN TXT \"zone-cds-disable\"\n"
                else:
                    zone_file += f"group.{zone.id}.zones 0 IN TXT \"zone\"\n"

    for zone in models.ReverseDNSZone.objects.all():
        zone_network = ipaddress.ip_network(
            (zone.zone_root_address, zone.zone_root_prefix)
        )
        zone_root = network_to_apra(zone_network)
        if is_active(zone):
            zone_file += f"{zone.id}.zones 0 IN PTR {zone_root}\n"
            if zone.cds_disable:
                zone_file += f"group.{zone.id}.zones 0 IN TXT \"zone-cds-disable\"\n"
            else:
                zone_file += f"group.{zone.id}.zones 0 IN TXT \"zone\"\n"

    for zone in models.SecondaryDNSZone.objects.all():
        if pattern.match(zone.zone_root):
            zone_root = dnslib.DNSLabel(zone.zone_root)
            if is_active(zone):
                zone_file += f"{zone.id}.zones 0 IN PTR {zone_root}\n"
                zone_file += f"group.{zone.id}.zones 0 IN TXT \"zone-secondary\"\n"

    write_zone_file(zone_file, "catalog.")
    send_reload_message(dnslib.DNSLabel("catalog.dns.as207960.ltd.uk."))

    update_signal_zones.delay()
