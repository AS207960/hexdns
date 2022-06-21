from celery import shared_task
from django.conf import settings
from . import models, svcb
import dnslib
import base64
import ipaddress
import hashlib
import socket
import struct
import typing
import time
import requests.exceptions
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

NAMESERVERS = ["ns1.as207960.net", "ns2.as207960.net"]
IP_NETWORK = typing.Union[ipaddress.IPv6Network, ipaddress.IPv4Network]
IP_ADDR = typing.Union[ipaddress.IPv6Address, ipaddress.IPv4Address]


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


with open(settings.DNSSEC_KEY_LOCATION, "rb") as k:
    priv_key_data = k.read()

priv_ksk = load_pem_private_key(
    priv_key_data, password=None, backend=default_backend()
)
if not issubclass(type(priv_ksk), EllipticCurvePrivateKey):
    raise Exception("Only EC private keys supported")


def encode_str(data):
    return "".join(c if ord(c) < 128 else "".join(f'\\{b}' for b in c.encode()) for c in data.replace("\"", "\\\""))


def dd_to_dms(dd: float) -> typing.Tuple[int, int, float]:
    d1 = int(dd)
    m1 = int((dd - d1) * 60)
    s1 = round(abs((dd - d1 - m1 / 60) * 3600), 3)
    return abs(d1), abs(m1), s1


def generate_zone_header(zone, zone_root):
    if hasattr(zone, "custom_ns") and zone.custom_ns.count():
        primary_ns = zone.custom_ns.first().nameserver
    else:
        primary_ns = NAMESERVERS[0]

    zone_file = f"$ORIGIN {zone_root}\n"
    zone_file += f"@ 86400 IN SOA {primary_ns} noc.as207960.net {int(zone.last_modified.timestamp())} " \
                 f"86400 3600 3600000 3600\n"

    if hasattr(zone, "custom_ns") and zone.custom_ns.count():
        for ns in zone.custom_ns.all():
            zone_file += f"@ 86400 IN NS {ns.nameserver}\n"
    else:
        for ns in NAMESERVERS:
            zone_file += f"@ 86400 IN NS {ns}\n"

    if zone.cds_disable:
        zone_file += "@ 86400 IN CDS 0 0 0 0\n"
        zone_file += "@ 86400 IN CDNSKEY 0 3 0 0\n"
    else:
        pub_key = priv_ksk.public_key()
        nums = pub_key.public_numbers()
        dnskey_bytes = nums.x.to_bytes(32, byteorder="big") + nums.y.to_bytes(32, byteorder="big")

        buffer = dnslib.DNSBuffer()
        rd = dnslib.DNSKEY(
            257,
            3,
            13,
            dnskey_bytes,
        )
        buffer.encode_name(dnslib.DNSLabel(zone_root))
        rd.pack(buffer)
        digest = hashlib.sha256(buffer.data).hexdigest()
        tag = make_key_tag(pub_key, flags=257)

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

    for record in zone.addressrecord_set.all():
        zone_file += f"; Address record {record.id}\n"
        address = ipaddress.ip_address(record.address)
        if type(address) == ipaddress.IPv4Address:
            zone_file += f"{record.record_name} {record.ttl} IN A {address}\n"
        elif type(address) == ipaddress.IPv6Address:
            zone_file += f"{record.record_name} {record.ttl} IN AAAA {address}\n"

    for record in zone.dynamicaddressrecord_set.all():
        zone_file += f"; Dynamic address record {record.id}\n"
        if record.current_ipv4:
            zone_file += f"{record.record_name} {record.ttl} IN A {record.current_ipv4}\n"
        if record.current_ipv6:
            zone_file += f"{record.record_name} {record.ttl} IN AAAA {record.current_ipv6}\n"

    for record in zone.anamerecord_set.all():
        zone_file += f"; ANAME record {record.id}\n"
        alias_label = dnslib.DNSLabel(record.alias)

        if alias_label.matchSuffix(zone_root):
            own_record_name = alias_label.stripSuffix(zone_root)
            search_name = ".".join(map(lambda n: n.decode(), own_record_name.label))
            own_records = zone.addressrecord_set.filter(record_name=search_name)
            for r in own_records:
                address = ipaddress.ip_address(r.address)
                if type(address) == ipaddress.IPv4Address:
                    zone_file += f"{record.record_name} {record.ttl} IN A {address}\n"
                elif type(address) == ipaddress.IPv6Address:
                    zone_file += f"{record.record_name} {record.ttl} IN AAAA {address}\n"
        else:
            question_a = dnslib.DNSRecord(q=dnslib.DNSQuestion(record.alias, dnslib.QTYPE.A))
            question_aaaa = dnslib.DNSRecord(q=dnslib.DNSQuestion(record.alias, dnslib.QTYPE.AAAA))
            try:
                res_pkt_a = question_a.send(
                    settings.RESOLVER_NO_DNS64_ADDR, port=settings.RESOLVER_NO_DNS64_PORT,
                    ipv6=settings.RESOLVER_NO_DNS64_IPV6, tcp=True, timeout=30
                )
                res_pkt_aaaa = question_aaaa.send(
                    settings.RESOLVER_NO_DNS64_ADDR, port=settings.RESOLVER_NO_DNS64_PORT,
                    ipv6=settings.RESOLVER_NO_DNS64_IPV6, tcp=True, timeout=30
                )
            except socket.timeout:
                raise dnslib.DNSError(f"Failed to get address for {record.alias}: timeout")
            except struct.error:
                raise dnslib.DNSError(f"Failed to get address for {record.alias}: invalid response")
            res_a = dnslib.DNSRecord.parse(res_pkt_a)
            res_aaaa = dnslib.DNSRecord.parse(res_pkt_aaaa)
            for rr in res_a.rr:
                zone_file += f"{record.record_name} {record.ttl} IN A {rr.rdata}\n"
            for rr in res_aaaa.rr:
                zone_file += f"{record.record_name} {record.ttl} IN AAAA {rr.rdata}\n"

    for record in zone.githubpagesrecord_set.all():
        zone_file += f"; Github pages record {record.id}\n"
        zone_file += f"{record.record_name} {record.ttl} IN A 185.199.108.153\n"
        zone_file += f"{record.record_name} {record.ttl} IN A 185.199.109.153\n"
        zone_file += f"{record.record_name} {record.ttl} IN A 185.199.110.153\n"
        zone_file += f"{record.record_name} {record.ttl} IN A 185.199.111.153\n"
        zone_file += f"{record.record_name} {record.ttl} IN AAAA 2606:50c0:8000::153\n"
        zone_file += f"{record.record_name} {record.ttl} IN AAAA 2606:50c0:8001::153\n"
        zone_file += f"{record.record_name} {record.ttl} IN AAAA 2606:50c0:8002::153\n"
        zone_file += f"{record.record_name} {record.ttl} IN AAAA 2606:50c0:8003::153\n"

    for record in zone.cnamerecord_set.all():
        zone_file += f"; CNAME record {record.id}\n"
        zone_file += f"{record.record_name} {record.ttl} IN A {record.alias}\n"

    for record in zone.redirectrecord_set.all():
        zone_file += f"; Redirect record {record.id}\n"
        zone_file += f"{record.record_name} {record.ttl} IN A 45.129.95.254\n"
        zone_file += f"{record.record_name} {record.ttl} IN A 2a0e:1cc1:1::1:7\n"
        zone_file += f"{record.record_name} {record.ttl} IN CAA 0 iodef \"mailto:noc@as207960.net\"\n"
        zone_file += f"{record.record_name} {record.ttl} IN CAA 0 issue \"letsencrypt.org\"\n"

    for record in zone.mxrecord_set.all():
        zone_file += f"; MX record {record.id}\n"
        zone_file += f"{record.record_name} {record.ttl} IN MX {record.priority} {record.exchange}\n"

    for record in zone.nsrecord_set.all():
        zone_file += f"; NS record {record.id}\n"
        zone_file += f"{record.record_name} {record.ttl} IN NS {record.nameserver}\n"

    for record in zone.txtrecord_set.all():
        zone_file += f"; TXT record {record.id}\n"
        zone_file += f"{record.record_name} {record.ttl} IN TXT \"{encode_str(record.data)}\"\n"

    for record in zone.srvrecord_set.all():
        zone_file += f"; SRV record {record.id}\n"
        zone_file += f"{record.record_name} {record.ttl} IN SRV {record.priority} {record.weight} {record.port} " \
                     f"{record.target}\n"

    for record in zone.caarecord_set.all():
        zone_file += f"; CAA record {record.id}\n"
        zone_file += f"{record.record_name} {record.ttl} IN CAA {record.flags} \"{encode_str(record.tag)}\" " \
                     f"\"{encode_str(record.value)}\"\n"

    for record in zone.naptrrecord_set.all():
        zone_file += f"; NAPTR record {record.id}\n"
        zone_file += f"{record.record_name} {record.ttl} IN NAPTR {record.order} {record.preference} " \
                     f"{record.flags} \"{encode_str(record.flags)}\" \"{encode_str(record.service)}\" " \
                     f"\"{encode_str(record.regexp)}\" \"{encode_str(record.replacement)}\"\n"

    for record in zone.sshfprecord_set.all():
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
        zone_file += f"{record.record_name} {record.ttl} IN SSHFP {algo_num} 1 " \
                     f"{hashlib.sha1(pubkey._decoded_key).hexdigest()}\n"
        zone_file += f"{record.record_name} {record.ttl} IN SSHFP {algo_num} 2 " \
                     f"{hashlib.sha256(pubkey._decoded_key).hexdigest()}\n"

    for record in zone.dsrecord_set.all():
        zone_file += f"; DS record {record.id}\n"
        zone_file += f"{record.record_name} {record.ttl} IN DS {record.key_tag} {record.algorithm} " \
                     f"{record.digest_type} {record.digest}\n"

    for record in zone.locrecord_set.all():
        d1, m1, s1 = dd_to_dms(record.latitude)
        d2, m2, s2 = dd_to_dms(record.longitude)
        ns = "S" if record.latitude < 0 else "N"
        ew = "W" if record.longitude < 0 else "E"

        zone_file += f"; LOC record {record.id}\n"
        zone_file += f"{record.record_name} {record.ttl} IN LOC {d1} {m1} {s1} {ns} {d2} {m2} {s2} {ew} " \
                     f"{record.altitude}m {record.size}m {record.hp}m {record.vp}m\n"

    for record in zone.hinforecord_set.all():
        zone_file += f"; HINFO record {record.id}\n"
        zone_file += f"{record.record_name} {record.ttl} IN HINFO \"{encode_str(record.cpu)}\" " \
                     f"\"{encode_str(record.os)}\"\n"

    for record in zone.rprecord_set.all():
        zone_file += f"; RP record {record.id}\n"
        zone_file += f"{record.record_name} {record.ttl} IN RP {record.mailbox} " \
                     f"\"{encode_str(record.txt)}\"\n"

    for record in zone.httpsrecord_set.all():
        data, mandatory = record.svcb_data
        params = [repr(p) for p in data.params]
        if mandatory:
            params.append(f"mandatory={','.join(svcb.SVCBParam.param_id_to_name(m) for m in mandatory)}")
        zone_file += f"; HTTPS record {record.id}\n"
        zone_file += f"{record.svcb_record_name} {record.ttl} IN HTTPS {record.priority} {record.target} " \
                     f"{' '.join(params)}\n"

    for record in zone.dhcidrecord_set.all():
        zone_file += f"; DHCID record {record.id}\n"
        zone_file += f"{record.record_name} {record.ttl} IN DHCID \"{base64.b64encode(record.data).decode()}\"\n"

    return zone_file


def generate_rzone(zone: "models.ReverseDNSZone"):
    zone_network = ipaddress.ip_network(
        (zone.zone_root_address, zone.zone_root_prefix)
    )
    zone_root = network_to_apra(zone_network)
    zone_file = generate_zone_header(zone, zone_root)
    account = zone.get_user().account

    for record in zone.ptrrecord_set.all():
        zone_file += f"; PTR record {record.id}\n"
        zone_file += f"{address_to_apra(record.record_address)} {record.ttl} IN PTR {dnslib.DNSLabel(record.pointer)}\n"

    for record in zone.reversensrecord_set.all():
        zone_file += f"; NS record {record.id}\n"
        zone_file += f"{address_to_apra(record.record_address)} {record.ttl} IN NS {dnslib.DNSLabel(record.nameserver)}\n"

    for record in models.AddressRecord.objects.raw(
            "SELECT * FROM dns_grpc_addressrecord WHERE (auto_reverse AND address << inet %s)",
            [zone_network]
    ):
        if record.zone.get_user().account == account:
            zone_ptr = dnslib.DNSLabel(f"{record.record_name}.{record.zone.zone_root}")
            zone_file += f"; Address record {record.id}\n"
            zone_file += f"{address_to_apra(record.address)} {record.ttl} IN PTR {zone_ptr}\n"

    return zone_file


def write_zone_file(zone_contents: str, zone):
    with open(f"{settings.ZONE_FILE_LOCATION}/{zone.id}.zone", "w", encoding="utf8", newline='\n') as f:
        f.write(zone_contents)


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def add_fzone(zone_id: str):
    zone = models.DNSZone.objects.get(id=zone_id)
    zone_file = generate_fzone(zone)
    write_zone_file(zone_file, zone)
    update_catalog.delay()


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def update_fzone(zone_id: str):
    zone = models.DNSZone.objects.get(id=zone_id)
    zone_file = generate_fzone(zone)
    write_zone_file(zone_file, zone)


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def add_rzone(zone_id: str):
    zone = models.ReverseDNSZone.objects.get(id=zone_id)
    zone_file = generate_rzone(zone)
    write_zone_file(zone_file, zone)
    update_catalog.delay()


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def update_rzone(zone_id: str):
    zone = models.ReverseDNSZone.objects.get(id=zone_id)
    zone_file = generate_rzone(zone)
    write_zone_file(zone_file, zone)


def is_active(zone):
    try:
        account = zone.get_user().account
        return account.subscription_active
    except requests.exceptions.RequestException:
        return False


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def update_catalog():
    zone_file = "$ORIGIN catalog.dns.as207960.ltd.uk.\n"
    zone_file += f"@ 0 IN SOA invalid. noc.as207960.net {int(time.time())} 3600 600 2147483646 0\n"
    zone_file += "@ 0 IN NS invalid.\n"
    zone_file += "version 0 IN TXT \"2\"\n"

    for zone in models.DNSZone.objects.all():
        zone_root = dnslib.DNSLabel(zone.zone_root)
        if is_active(zone):
            zone_file += f"{zone.id}.zones 0 IN PTR {zone_root}\n"

    for zone in models.ReverseDNSZone.objects.all():
        zone_network = ipaddress.ip_network(
            (zone.zone_root_address, zone.zone_root_prefix)
        )
        zone_root = grpc.network_to_apra(zone_network)
        if is_active(zone):
            zone_file += f"{zone.id}.zones 0 IN PTR {zone_root}\n"

    with open(f"{settings.ZONE_FILE_LOCATION}/catalog.zone", "w", encoding="utf8", newline='\n') as f:
        f.write(zone_file)
