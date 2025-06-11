from celery import shared_task
from django.conf import settings
from django.utils import timezone
from django.template.loader import render_to_string
from . import models, apps, utils, netnod, emails
import dnslib
import base64
import pika
import ipaddress
import hashlib
import typing
import time
import re
import idna
import string
import logging
import requests.exceptions
import keycloak.exceptions
import django.core.files.base
import django.core.files.storage

NAMESERVERS = ["ns1.as207960.net.", "ns2.as207960.net.", "ns3.as207960.net.", "ns4.as207960.net."]

pika_client = apps.PikaClient()


def make_key_tag(public_key: dnslib.DNSKEY, flags=256):
    buffer = dnslib.DNSBuffer()
    public_key.pack(buffer)
    tag = 0
    for i in range(len(buffer.data) // 2):
        tag += (buffer.data[2 * i] << 8) + buffer.data[2 * i + 1]
    if len(buffer.data) % 2 != 0:
        tag += buffer.data[len(buffer.data) - 1] << 8
    tag += (tag >> 16) & 0xFFFF
    tag = tag & 0xFFFF
    return tag


def encode_str(data):
    return "".join((c if ord(c) < 128 else "".join(f'\\{int(b)}' for b in c.encode())) for c in data.replace("\"", "\\\""))


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

    contact_email = f"{zone.id.hex()}.dns.glauca.digital."
    zone_file = f"$ORIGIN {zone_root}\n"
    zone_file += f"@ 86400 IN SOA {primary_ns} {contact_email} {int(time.time())} " \
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
        for key, digest in zip(utils.get_dnskeys(), utils.make_zone_digests(zone_root)):
            zone_file += f"@ 86400 IN CDS {digest}\n"
            zone_file += f"@ 86400 IN CDNSKEY {key}\n"

        for cds in zone.additional_cds.all():
            zone_file += f"; Additional CDS {cds.id}\n"
            zone_file += f"@ 86400 IN CDS {cds.key_tag} {cds.algorithm} {cds.digest_type} {cds.digest}\n"

        for cdnskey in zone.additional_cdnskey.all():
            zone_file += f"; Additional CDNSKEY {cdnskey.id}\n"
            zone_file += f"@ 86400 IN CDNSKEY {cdnskey.flags} {cdnskey.protocol} {cdnskey.algorithm} " \
                         f"{cdnskey.public_key}\n"

    zone_file += "_domainconnect 86400 IN CNAME domain-connect.as207960.ltd.uk.\n"

    return zone_file


def generate_fzone(zone: "models.DNSZone"):
    zone_root = dnslib.DNSLabel(zone.idna_label)
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
                    if all((ord(c) < 127 and c in string.printable) for c in record.alias):
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
            zone_file += f"{record_name} {record.ttl} IN CAA 128 issue \"pki.goog; accounturi=https://dv.acme-v02.api.pki.goog/account/s0zLRLXgH0KIRQC6RcVXcg\"\n"
            zone_file += f"{record_name} {record.ttl} IN CAA 128 issue \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/85247630\"\n"

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
            if record_name == "_domainconnect":
                continue

            zone_file += f"; TXT record {record.id}\n"
            zone_file += f"{record_name} {record.ttl} IN TXT"
            data = record.data.encode('utf-8')
            chunks = [data[i:i+255] for i in range(0, len(data), 255)]
            for chunk in chunks:
                zone_file += f" \"{encode_str(chunk.decode('utf-8'))}\""
            zone_file += "\n"

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

    for record in zone.dnskeyrecord_set.all():
        record_name = record.idna_label
        if record_name:
            zone_file += f"; DNSKEY record {record.id}\n"
            zone_file += f"{record_name} {record.ttl} IN DNSKEY {record.flags} {record.protocol} " \
                         f"{record.algorithm} {record.public_key}\n"

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
        zone_file += f"{record.svcb_record_name} {record.ttl} IN TYPE65 \\# {len(data)} {data.hex()}\n"

    for record in zone.dhcidrecord_set.all():
        record_name = record.idna_label
        if record_name:
            zone_file += f"; DHCID record {record.id}\n"
            zone_file += f"{record_name} {record.ttl} IN DHCID {base64.b64encode(record.data).decode()}\n"

    for record in zone.tlsarecord_set.all():
        record_name = record.idna_label
        if record_name:
            zone_file += f"; TLSA record {record.id}\n"
            zone_file += (f"{record_name} {record.ttl} IN TLSA {record.certificate_usage} {record.selector} "
                          f"{record.matching_type} {record.certificate_data.hex()}\n")

    return zone_file


def generate_rzone(zone: "models.ReverseDNSZone", network: typing.Union[ipaddress.IPv4Network, ipaddress.IPv6Network]):
    zone_root = models.network_to_arpa(network)
    zone_file = generate_zone_header(zone, zone_root)
    user = get_user(zone)
    account = user.account.id if user else None

    for record in zone.ptrrecord_set.all():
        addr = ipaddress.ip_address(record.record_address)
        if addr in network:
            zone_file += f"; PTR record {record.id}\n"
            zone_file += f"{models.address_to_arpa(addr)} {record.ttl} IN PTR {record.pointer_label}\n"

    for record in zone.reversensrecord_set.all():
        ns_network = ipaddress.ip_network((record.record_address, record.record_prefix))
        if ns_network.subnet_of(network):
            zone_file += f"; NS record {record.id}\n"
            ns_networks = models.reverse_zone_networks(ns_network)
            for ns_network in ns_networks:
                zone_file += f"{models.network_to_arpa(ns_network)} {record.ttl} IN NS " \
                             f"{dnslib.DNSLabel(record.nameserver)}\n"

    zones = {}
    for record in models.AddressRecord.objects.raw(
            "SELECT * FROM dns_grpc_addressrecord WHERE (auto_reverse AND address << inet %s)",
            [str(network)],
    ):
        if record.zone.id in zones:
            account2 = zones[record.zone.id]
        else:
            try:
                account2 = record.zone.get_user().account.id
                zones[record.zone.id] = account2
            except keycloak.exceptions.KeycloakClientError:
                account2 = None
        if account2 == account:
            if record.record_name == "@":
                zone_ptr = dnslib.DNSLabel(str(record.zone.zone_root))
            else:
                zone_ptr = dnslib.DNSLabel(f"{record.record_name}.{record.zone.zone_root}")
            addr = ipaddress.ip_address(record.address)
            zone_file += f"; Address record {record.id}\n"
            zone_file += f"{models.address_to_arpa(addr)} {record.ttl} IN PTR {zone_ptr}\n"

    return zone_file


def generate_szone(zone: "models.SecondaryDNSZone"):
    zone_root = dnslib.DNSLabel(zone.idna_label)
    zone_file = f"$ORIGIN {zone_root}\n"

    for record in zone.secondarydnszonerecord_set.all():
        zone_file += f"; Record {record.id}\n"
        zone_file += f"{record.record_text}\n"

    return zone_file


def write_zone_file(zone_contents: str, priv_key: typing.List[str], zone_name: str):
    zone_storage = django.core.files.storage.storages["zone-storage"]
    zone_storage.save(
        f"{zone_name}zone", django.core.files.base.ContentFile(zone_contents.encode())
    )
    if priv_key:
        zone_storage.save(
            f"{zone_name}key", django.core.files.base.ContentFile("\n\n".join(list(map(lambda k: k.strip(), priv_key))).strip().encode())
        )


def send_resign_message(label: dnslib.DNSLabel):
    global pika_client

    def pub(channel):
        channel.queue_declare(queue='hexdns_resign', durable=True)
        channel.basic_publish(
            exchange='', routing_key='hexdns_resign', body=str(label).encode(),
            properties=pika.BasicProperties(
                delivery_mode=pika.spec.PERSISTENT_DELIVERY_MODE,
                priority=0,
                expiration=str(1000 * 60 * 60 * 24)
            ),
            mandatory=True
        )

    pika_client.get_channel(pub)


def send_reload_message(label: dnslib.DNSLabel, zone_hash: str):
    global pika_client

    def pub(channel):
        channel.exchange_declare(exchange='hexdns_primary_reload', exchange_type='fanout', durable=True)
        channel.basic_publish(
            exchange='hexdns_primary_reload', routing_key='', body=f"{zone_hash}:{label}".encode(),
            properties=pika.BasicProperties(
                delivery_mode=2,
                priority=0,
                expiration=str(1000 * 60 * 60)
            )
        )

    pika_client.get_channel(pub)


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def add_fzone(zone_id: str):
    try:
        zone: models.DNSZone = models.DNSZone.objects.get(id=zone_id)
    except models.DNSZone.DoesNotExist:
        return

    pattern = re.compile("^[a-zA-Z0-9-.]+$")
    zone_name = zone.idna_label
    if zone_name and pattern.match(zone_name):
        zone_root = dnslib.DNSLabel(zone_name)
        zone_file = generate_fzone(zone)
        write_zone_file(zone_file, [zone.zsk_private or "", zone.zsk_private_ed25519 or ""], str(zone_root))
        send_resign_message(zone_root)
        zone.last_resign = timezone.now()
        zone.save()
        update_catalog.delay()


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def update_fzone(zone_id: str):
    try:
        zone: models.DNSZone = models.DNSZone.objects.get(id=zone_id)
    except models.DNSZone.DoesNotExist:
        return

    pattern = re.compile("^[a-zA-Z0-9-.]+$")
    zone_name = zone.idna_label
    if zone_name and pattern.match(zone_name):
        zone_root = dnslib.DNSLabel(zone_name)
        zone_file = generate_fzone(zone)
        write_zone_file(zone_file, [zone.zsk_private or "", zone.zsk_private_ed25519 or ""], str(zone_root))
        send_resign_message(zone_root)
        zone.last_resign = timezone.now()
        zone.save()


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def add_rzone(zone_id: str):
    try:
        zone: models.ReverseDNSZone = models.ReverseDNSZone.objects.get(id=zone_id)
    except models.ReverseDNSZone.DoesNotExist:
        return

    for network in zone.zone_networks:
        zone_file = generate_rzone(zone, network)
        zone_root = models.network_to_arpa(network)
        write_zone_file(zone_file, [zone.zsk_private or "", zone.zsk_private_ed25519 or ""], str(zone_root))
        send_resign_message(zone_root)
        zone.last_resign = timezone.now()
        zone.save()
        update_catalog.delay()


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def update_rzone(zone_id: str):
    try:
        zone: models.ReverseDNSZone = models.ReverseDNSZone.objects.get(id=zone_id)
    except models.ReverseDNSZone.DoesNotExist:
        return

    for network in zone.zone_networks:
        zone_file = generate_rzone(zone, network)
        zone_root = models.network_to_arpa(network)
        write_zone_file(zone_file, [zone.zsk_private or "", zone.zsk_private_ed25519 or ""], str(zone_root))
        send_resign_message(zone_root)
        zone.last_resign = timezone.now()
        zone.save()


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def add_szone(zone_id: str):
    try:
        zone: models.SecondaryDNSZone = models.SecondaryDNSZone.objects.get(id=zone_id)
    except models.SecondaryDNSZone.DoesNotExist:
        return

    if zone_name := zone.idna_label:
        zone_root = dnslib.DNSLabel(zone_name)
        zone_file = generate_szone(zone)
        write_zone_file(zone_file, [""], str(zone_root))
        m = hashlib.sha256()
        m.update(zone_file.encode())
        send_reload_message(zone_root, m.hexdigest())
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

    if zone_name := zone.idna_label:
        zone_root = dnslib.DNSLabel(zone_name)
        zone_file = generate_szone(zone)
        write_zone_file(zone_file, [""], str(zone_root))
        m = hashlib.sha256()
        m.update(zone_file.encode())
        send_reload_message(zone_root, m.hexdigest())


def get_user(zone):
    try:
        user = zone.get_user()
        if not user:
            return None
        return user
    except (keycloak.exceptions.KeycloakClientError, requests.exceptions.RequestException):
        return None


def is_active(user):
    if not user:
        return False

    try:
        return user.account.subscription_active
    except models.Account.DoesNotExist:
        return False


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def update_signal_zones():
    pattern = re.compile("^[a-zA-Z0-9-.]+$")
    now = int(time.time())

    zone_file_base = ""

    for zone in models.DNSZone.objects.all():
        zone_name = zone.idna_label
        if zone_name and pattern.match(zone_name):
            cds_zone_root = dnslib.DNSLabel(zone_name)
            zone_file_base += f"; Zone {zone.id}\n"
            dsboot_label = f"_dsboot.{str(cds_zone_root)[:-1]}"

            if zone.cds_disable:
                zone_file_base += f"{dsboot_label} 86400 IN CDS 0 0 0 00\n"
                zone_file_base += f"{dsboot_label} 86400 IN CDNSKEY 0 3 0 AA==\n"
            else:
                for key, digest in zip(utils.get_dnskeys(), utils.make_zone_digests(zone_name)):
                    zone_file_base += f"{dsboot_label} 86400 IN CDS {digest}\n"
                    zone_file_base += f"{dsboot_label} 86400 IN CDNSKEY {key}\n"

                for cds in zone.additional_cds.all():
                    zone_file_base += f"; Additional CDS {cds.id}\n"
                    zone_file_base += (f"{dsboot_label} 86400 IN CDS {cds.key_tag} {cds.algorithm} "
                                       f"{cds.digest_type} {cds.digest}\n")

                for cdnskey in zone.additional_cdnskey.all():
                    zone_file_base += f"; Additional CDNSKEY {cdnskey.id}\n"
                    zone_file_base += (f"{dsboot_label} 86400 IN CDNSKEY {cdnskey.flags} "
                                       f"{cdnskey.protocol} {cdnskey.algorithm} {cdnskey.public_key}\n")

    for ns in NAMESERVERS:
        zone_root = dnslib.DNSLabel(f"_signal.{ns}")

        zone_file = f"$ORIGIN {zone_root}\n"
        zone_file += f"@ 86400 IN SOA {NAMESERVERS[0]} noc.as207960.net. {now} 86400 3600 3600000 3600\n"

        for ns2 in NAMESERVERS:
            zone_file += f"@ 86400 IN NS {ns2}\n"

        zone_file += zone_file_base

        write_zone_file(zone_file, [settings.DNSSEC_SIGNAL_PRIVKEY_DATA], str(zone_root))
        send_resign_message(zone_root)


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def update_catalog():
    required_zones = ["as207960.net", "as207960.ltd.uk"]

    zone_file = "$ORIGIN catalog.dns.as207960.ltd.uk.\n"
    zone_file += f"@ 0 IN SOA invalid. noc.as207960.net {int(time.time())} 3600 600 2147483646 0\n"
    zone_file += "@ 0 IN NS invalid.\n"
    zone_file += "version 0 IN TXT \"2\"\n"

    for i, ns in enumerate(NAMESERVERS):
        zone_file += f"signal{i}.zones 0 IN PTR _signal.{ns}\n"
        zone_file += f"group.signal{i}.zones 0 IN TXT \"zone\"\n"

    for i, z in enumerate(required_zones):
        zone_file += f"required{i}.zones 0 IN PTR {z}.\n"
        zone_file += f"group.required{i}.zones 0 IN TXT \"zone\"\n"

    pattern = re.compile("^[a-zA-Z0-9-.]+$")
    netnod_active_zones = []
    netnod_inactive_zones = []

    for zone in models.DNSZone.objects.all():
        if zone_label := zone.idna_label:
            if zone_label in required_zones:
                continue
            if pattern.match(zone_label):
                zone_root = dnslib.DNSLabel(zone_label)
                owner = get_user(zone)
                if is_active(owner):
                    if zone.active:
                        netnod_active_zones.append((str(zone_root), owner.username))
                    else:
                        netnod_inactive_zones.append(str(zone_root))
                    zone_file += f"{zone.id}.zones 0 IN PTR {zone_root}\n"
                    zone_file += f"group.{zone.id}.zones 0 IN TXT \"zone\"\n"
                else:
                    netnod_inactive_zones.append(str(zone_root))

    for zone in models.ReverseDNSZone.objects.all():
        owner = get_user(zone)
        if is_active(owner):
            for i, zone_root in enumerate(zone.dns_labels):
                if zone.active:
                    netnod_active_zones.append((str(zone_root), owner.username))
                else:
                    netnod_inactive_zones.append(str(zone_root))
                zone_file += f"{zone.id}-{i}.zones 0 IN PTR {zone_root}\n"
                zone_file += f"group.{zone.id}-{i}.zones 0 IN TXT \"zone\"\n"
        else:
            for zone_root in zone.dns_labels:
                netnod_inactive_zones.append(str(zone_root))

    for zone in models.SecondaryDNSZone.objects.all():
        if zone_label := zone.idna_label:
            if pattern.match(zone_label):
                zone_root = dnslib.DNSLabel(zone_label)
                owner = get_user(zone)
                if is_active(owner):
                    if zone.active:
                        netnod_active_zones.append((str(zone_root), owner.username))
                    else:
                        netnod_inactive_zones.append(str(zone_root))
                    zone_file += f"{zone.id}.zones 0 IN PTR {zone_root}\n"
                    zone_file += f"group.{zone.id}.zones 0 IN TXT \"zone-secondary\"\n"
                else:
                    netnod_inactive_zones.append(str(zone_root))

    write_zone_file(zone_file, [""], "catalog.")
    m = hashlib.sha256()
    m.update(zone_file.encode())
    send_reload_message(dnslib.DNSLabel("catalog.dns.as207960.ltd.uk."), m.hexdigest())

    update_signal_zones.delay()
    sync_netnod_zones.delay(netnod_active_zones, netnod_inactive_zones)


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def sync_netnod_zones(
        active_zones: typing.List[typing.Tuple[str, str]],
        inactive_zones: typing.List[str],
):
    for zone_root, owner in active_zones:
        try:
            if not netnod.check_zone_registered(zone_root):
                netnod.register_zone(zone_root, owner)
        except Exception as e:
            logging.error(f"Failed to register zone {zone_root}: {e}")
            continue

    for zone_root in inactive_zones:
        try:
            if netnod.check_zone_registered(zone_root):
                netnod.deregister_zone(zone_root)
        except Exception as e:
            logging.error(f"Failed to de-register zone {zone_root}: {e}")
            continue


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def forward_soa_email(zone_id, msg_bytes):
    msg_bytes = base64.b64decode(msg_bytes)

    zone = models.DNSZone.objects.filter(soa_email_id=zone_id).first()
    if not zone:
        zone = models.ReverseDNSZone.objects.filter(soa_email_id=zone_id).first()
        if not zone:
            return

    user = zone.get_user()
    if not user:
        return

    emails.send_email(user, {
        "subject": f"Your HexDNS zone {zone}",
        "content": render_to_string("dns_email/soa_contact.html", {
            "zone": zone
        })
    }, [
        ("file", ("forwarded.eml", msg_bytes, "message/rfc822")),
    ])
