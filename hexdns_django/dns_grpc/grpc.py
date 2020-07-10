from .proto import dns_pb2
from .proto import dns_pb2_grpc
from . import models
import dnslib
import ipaddress
import typing
import traceback
import struct
import hashlib
import sentry_sdk
from dnslib import QTYPE, RCODE, OPCODE
from dnslib.label import DNSLabel
from django.db.models.functions import Length
from django.db.models import Q
from django.conf import settings
from django.utils import timezone
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.serialization import load_pem_private_key

NAMESERVERS = ["ns1.as207960.net", "ns2.as207960.net"]
IP4_APRA = DNSLabel("in-addr.arpa.")
IP6_APRA = DNSLabel("ip6.arpa.")
IP_NETWORK = typing.Union[ipaddress.IPv6Network, ipaddress.IPv4Network]
IP_ADDR = typing.Union[ipaddress.IPv6Address, ipaddress.IPv4Address]


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


def network_to_apra(network: IP_NETWORK) -> DNSLabel:
    if type(network) == ipaddress.IPv6Network:
        return DNSLabel(
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
        return DNSLabel(
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


def grpc_hook(server):
    dns_pb2_grpc.add_DnsServiceServicer_to_server(DnsServiceServicer(), server)


class DnsServiceServicer(dns_pb2_grpc.DnsServiceServicer):

    def __init__(self):
        with open(settings.DNSSEC_KEY_LOCATION, "rb") as f:
            priv_key_data = f.read()

        priv_key = load_pem_private_key(
            priv_key_data, password=None, backend=default_backend()
        )
        if not issubclass(type(priv_key), EllipticCurvePrivateKey):
            raise Exception("Only EC private keys supported")

        self.priv_key = priv_key

    def is_rdns(self, qname: DNSLabel) -> bool:
        if qname.matchSuffix(IP4_APRA):
            return True
        elif qname.matchSuffix(IP6_APRA):
            return True
        else:
            return False

    def find_zone(
        self, qname: DNSLabel
    ) -> (typing.Optional[models.DNSZone], typing.Optional[DNSLabel]):
        zones = models.DNSZone.objects.filter(active=True).order_by(Length("zone_root").desc())
        for zone in zones:
            zone_root = DNSLabel(zone.zone_root)
            if qname.matchSuffix(zone_root):
                record_name = qname.stripSuffix(zone_root)
                if len(record_name.label) == 0:
                    record_name = DNSLabel("@")
                return zone, record_name
        return None, None

    def find_secondary_zone(
        self, qname: DNSLabel
    ) -> (typing.Optional[models.DNSZone], typing.Optional[DNSLabel]):
        zones = models.SecondaryDNSZone.objects.filter(active=True).order_by(Length("zone_root").desc())
        for zone in zones:
            zone_root = DNSLabel(zone.zone_root)
            if qname.matchSuffix(zone_root):
                return zone, qname
        return None, None

    def find_rzone(
        self, qname: DNSLabel
    ) -> (typing.Optional[models.ReverseDNSZone], typing.Optional[IP_ADDR]):
        is_ip6_zone = qname.matchSuffix(IP6_APRA)
        qname = (
            qname.stripSuffix(IP6_APRA)
            if is_ip6_zone
            else qname.stripSuffix(IP4_APRA)
        )

        if is_ip6_zone:
            parts = list(reversed(list(map(lambda n: n.decode(), qname.label))))
            parts += ["0"] * (32 - len(parts))
            addr = ":".join(
                ["".join(parts[n : n + 4]) for n in range(0, len(parts), 4)]
            )
        else:
            parts = list(reversed(list(map(lambda n: n.decode(), qname.label))))
            parts += ["0"] * (4 - len(parts))
            addr = ".".join(parts)
        try:
            addr = ipaddress.ip_address(addr)
        except ValueError:
            return None, None, None

        zones = models.ReverseDNSZone.objects.filter(active=True).order_by("-zone_root_prefix")
        for zone in zones:
            try:
                zone_network = ipaddress.ip_network(
                    (zone.zone_root_address, zone.zone_root_prefix)
                )
            except ValueError:
                continue

            if addr in zone_network:
                return zone, addr, zone_network

        return None, None, None

    def find_records(
        self,
        model: typing.Type[models.DNSZoneRecord],
        rname: DNSLabel,
        zone: models.DNSZone,
    ):
        search_name = ".".join(map(lambda n: n.decode(), rname.label))
        return model.objects.filter(record_name=search_name, zone=zone)

    def any_records(
        self, rname: DNSLabel, zone: models.DNSZone,
    ):
        search_name = ".".join(map(lambda n: n.decode(), rname.label))
        if models.AddressRecord.objects.filter(
            record_name=search_name, zone=zone
        ).count():
            return True
        elif models.DynamicAddressRecord.objects.filter(
            record_name=search_name, zone=zone
        ).count():
            return True
        elif models.CNAMERecord.objects.filter(
            record_name=search_name, zone=zone
        ).count():
            return True
        elif models.MXRecord.objects.filter(record_name=search_name, zone=zone).count():
            return True
        elif models.NSRecord.objects.filter(record_name=search_name, zone=zone).count():
            return True
        elif models.TXTRecord.objects.filter(
            record_name=search_name, zone=zone
        ).count():
            return True
        elif models.SRVRecord.objects.filter(
            record_name=search_name, zone=zone
        ).count():
            return True
        elif models.CAARecord.objects.filter(
            record_name=search_name, zone=zone
        ).count():
            return True
        elif models.NAPTRRecord.objects.filter(
            record_name=search_name, zone=zone
        ).count():
            return True
        elif models.SSHFPRecord.objects.filter(
            record_name=search_name, zone=zone
        ).count():
            return True
        elif models.DSRecord.objects.filter(
            record_name=search_name, zone=zone
        ).count():
            return True
        else:
            return False

    def find_reverse_records(
        self,
        model: typing.Type[models.ReverseDNSZoneRecord],
        addr: IP_ADDR,
        zone: models.ReverseDNSZone,
    ):
        return model.objects.filter(record_address=str(addr), zone=zone)

    def make_resp(self, res: typing.Union[dnslib.DNSRecord, bytes]) -> dns_pb2.DnsPacket:
        if isinstance(res, dnslib.DNSRecord):
            return dns_pb2.DnsPacket(msg=bytes(res.pack()))
        else:
            return dns_pb2.DnsPacket(msg=bytes(res))

    def lookup_referral(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.DNSZone,
        is_dnssec: bool,
    ):
        nameservers = models.NSRecord.objects.order_by(
            Length("record_name").desc()
        ).filter(zone=zone)
        ns_found = False
        for nameserver in nameservers:
            if record_name.matchSuffix(nameserver.record_name):
                ns_found = True
                ns = DNSLabel(nameserver.nameserver)
                dns_res.add_auth(
                    dnslib.RR(
                        f"{nameserver.record_name}.{zone.zone_root}",
                        QTYPE.NS,
                        rdata=dnslib.NS(ns),
                        ttl=nameserver.ttl,
                    )
                )
                if is_dnssec:
                    records = self.find_records(
                        models.DSRecord, DNSLabel(nameserver.record_name), zone
                    )
                    for record in records:
                        ds_data = bytearray(
                            struct.pack(
                                "!HBB",
                                record.key_tag,
                                record.algorithm,
                                record.digest_type,
                            )
                        )
                        digest_data = record.digest_bin
                        if not digest_data:
                            dns_res.header.rcode = RCODE.SERVFAIL
                            return
                        ds_data.extend(digest_data)
                        dns_res.add_auth(
                            dnslib.RR(
                                f"{nameserver.record_name}.{zone.zone_root}",
                                QTYPE.DS,
                                rdata=dnslib.RD(ds_data),
                                ttl=record.ttl,
                            )
                        )
                    if not len(records):
                        query_name = dnslib.DNSLabel(f"{nameserver.record_name}.{zone.zone_root}")
                        names = dnslib.DNSLabel(f"{nameserver.record_name}\x00.{zone.zone_root}")
                        dns_res.add_auth(
                            dnslib.RR(
                                query_name,
                                QTYPE.NSEC,
                                rdata=dnslib.NSEC(
                                    dnslib.DNSLabel(names), ["NS", "RRSIG", "NSEC"]
                                ),
                                ttl=86400,
                            )
                        )
                self.lookup_additional_addr(dns_res, ns)
        if not ns_found:
            if not self.any_records(record_name, zone):
                dns_res.header.rcode = RCODE.NXDOMAIN

    def lookup_cname(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.DNSZone,
        query_name: DNSLabel,
        is_dnssec: bool,
        func,
    ):
        cname_record = self.find_records(models.CNAMERecord, record_name, zone).first()
        if cname_record:
            dns_res.add_answer(
                dnslib.RR(
                    query_name,
                    QTYPE.CNAME,
                    rdata=dnslib.CNAME(cname_record.alias),
                    ttl=cname_record.ttl,
                )
            )
            zone, record_name = self.find_zone(DNSLabel(cname_record.alias))
            if zone:
                func(dns_res, record_name, zone, cname_record.alias, is_dnssec)
        else:
            self.lookup_referral(dns_res, record_name, zone, is_dnssec)

    def lookup_addr(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.DNSZone,
        query_name: DNSLabel,
        is_dnssec: bool,
    ):
        records = self.find_records(models.AddressRecord, record_name, zone)
        addr_found = False
        for record in records:
            address = ipaddress.ip_address(record.address)
            if type(address) == ipaddress.IPv4Address and dns_res.q.qtype == QTYPE.A:
                addr_found = True
                dns_res.add_answer(
                    dnslib.RR(
                        query_name,
                        QTYPE.A,
                        rdata=dnslib.A(address.compressed),
                        ttl=record.ttl,
                    )
                )
            elif (
                type(address) == ipaddress.IPv6Address and dns_res.q.qtype == QTYPE.AAAA
            ):
                addr_found = True
                dns_res.add_answer(
                    dnslib.RR(
                        query_name,
                        QTYPE.AAAA,
                        rdata=dnslib.AAAA(address.compressed),
                        ttl=record.ttl,
                    )
                )
        if not addr_found:
            records = self.find_records(models.DynamicAddressRecord, record_name, zone)
            for record in records:
                if dns_res.q.qtype == QTYPE.A and record.current_ipv4:
                    addr_found = True
                    dns_res.add_answer(
                        dnslib.RR(
                            query_name,
                            QTYPE.A,
                            rdata=dnslib.A(record.current_ipv4),
                            ttl=record.ttl,
                        )
                    )
                elif dns_res.q.qtype == QTYPE.AAAA and record.current_ipv6:
                    addr_found = True
                    dns_res.add_answer(
                        dnslib.RR(
                            query_name,
                            QTYPE.AAAA,
                            rdata=dnslib.AAAA(record.current_ipv6),
                            ttl=record.ttl,
                        )
                    )
        if not addr_found:
            records = self.find_records(models.ANAMERecord, record_name, zone)
            for record in records:
                question = dnslib.DNSRecord(q=dnslib.DNSQuestion(record.alias, dns_res.q.qtype))
                res_pkt = question.send(
                    settings.RESOLVER_ADDR, port=settings.RESOLVER_PORT, ipv6=True, tcp=False, timeout=5
                )
                res = dnslib.DNSRecord.parse(res_pkt)
                for rr in res.rr:
                    dns_res.add_answer(dnslib.RR(
                        query_name,
                        dns_res.q.qtype,
                        rdata=rr.rdata,
                        ttl=record.ttl
                    ))
        if not addr_found:
            self.lookup_cname(
                dns_res, record_name, zone, query_name, is_dnssec, self.lookup_addr
            )

    def lookup_additional_addr(
        self, dns_res: dnslib.DNSRecord, query_name: DNSLabel
    ):
        zone, record_name = self.find_zone(query_name)
        if zone and record_name:
            addr_found = False
            records = self.find_records(models.AddressRecord, record_name, zone)
            for record in records:
                address = ipaddress.ip_address(record.address)
                if type(address) == ipaddress.IPv4Address:
                    addr_found = True
                    dns_res.add_ar(
                        dnslib.RR(
                            query_name,
                            QTYPE.A,
                            rdata=dnslib.A(address.compressed),
                            ttl=record.ttl,
                        )
                    )
                elif type(address) == ipaddress.IPv6Address:
                    addr_found = True
                    dns_res.add_ar(
                        dnslib.RR(
                            query_name,
                            QTYPE.AAAA,
                            rdata=dnslib.AAAA(address.compressed),
                            ttl=record.ttl,
                        )
                    )
            if not addr_found:
                records = self.find_records(models.DynamicAddressRecord, record_name, zone)
                for record in records:
                    if dns_res.q.qtype == QTYPE.A and record.current_ipv4:
                        dns_res.add_ar(
                            dnslib.RR(
                                query_name,
                                QTYPE.A,
                                rdata=dnslib.A(record.current_ipv4),
                                ttl=record.ttl,
                            )
                        )
                    elif dns_res.q.qtype == QTYPE.AAAA and record.current_ipv6:
                        dns_res.add_ar(
                            dnslib.RR(
                                query_name,
                                QTYPE.AAAA,
                                rdata=dnslib.AAAA(record.current_ipv6),
                                ttl=record.ttl,
                            )
                        )

    def lookup_mx(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.DNSZone,
        query_name: DNSLabel,
        is_dnssec: bool,
    ):
        records = self.find_records(models.MXRecord, record_name, zone)
        for record in records:
            dns_res.add_answer(
                dnslib.RR(
                    query_name,
                    QTYPE.MX,
                    rdata=dnslib.MX(record.exchange, record.priority),
                    ttl=record.ttl,
                )
            )
        if not len(records):
            self.lookup_cname(
                dns_res, record_name, zone, query_name, is_dnssec, self.lookup_mx
            )

    def lookup_ns(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.DNSZone,
        query_name: DNSLabel,
        is_dnssec: bool,
    ):
        records = self.find_records(models.NSRecord, record_name, zone)
        for record in records:
            dns_res.add_answer(
                dnslib.RR(
                    query_name,
                    QTYPE.NS,
                    rdata=dnslib.NS(record.nameserver),
                    ttl=record.ttl,
                )
            )
        if record_name == "@":
            for ns in NAMESERVERS:
                dns_res.add_answer(
                    dnslib.RR(query_name, QTYPE.NS, rdata=dnslib.NS(ns), ttl=86400,)
                )
        if not len(records):
            self.lookup_cname(
                dns_res, record_name, zone, query_name, is_dnssec, self.lookup_ns
            )

    def lookup_txt(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.DNSZone,
        query_name: DNSLabel,
        is_dnssec: bool,
    ):
        records = self.find_records(models.TXTRecord, record_name, zone)
        for record in records:
            dns_res.add_answer(
                dnslib.RR(
                    query_name,
                    QTYPE.TXT,
                    rdata=dnslib.TXT(
                        [
                            record.data[i : i + 255].encode()
                            for i in range(0, len(record.data), 255)
                        ]
                    ),
                    ttl=record.ttl,
                )
            )
        if not len(records):
            self.lookup_cname(
                dns_res, record_name, zone, query_name, is_dnssec, self.lookup_txt
            )

    def lookup_srv(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.DNSZone,
        query_name: DNSLabel,
        is_dnssec: bool,
    ):
        records = self.find_records(models.SRVRecord, record_name, zone)
        for record in records:
            dns_res.add_answer(
                dnslib.RR(
                    query_name,
                    QTYPE.SRV,
                    rdata=dnslib.SRV(
                        record.priority, record.weight, record.port, record.target
                    ),
                    ttl=record.ttl,
                )
            )
        if not len(records):
            self.lookup_cname(
                dns_res, record_name, zone, query_name, is_dnssec, self.lookup_srv
            )

    def lookup_caa(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.DNSZone,
        query_name: DNSLabel,
        is_dnssec: bool,
    ):
        records = self.find_records(models.CAARecord, record_name, zone)
        for record in records:
            dns_res.add_answer(
                dnslib.RR(
                    query_name,
                    QTYPE.CAA,
                    rdata=dnslib.CAA(
                        flags=record.flag, tag=record.tag, value=record.value
                    ),
                    ttl=record.ttl,
                )
            )
        if not len(records):
            self.lookup_cname(
                dns_res, record_name, zone, query_name, is_dnssec, self.lookup_caa
            )

    def lookup_naptr(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.DNSZone,
        query_name: DNSLabel,
        is_dnssec: bool,
    ):
        records = self.find_records(models.NAPTRRecord, record_name, zone)
        for record in records:
            dns_res.add_answer(
                dnslib.RR(
                    query_name,
                    QTYPE.NAPTR,
                    rdata=dnslib.NAPTR(
                        order=record.order,
                        preference=record.preference,
                        flags=record.flags,
                        service=record.service,
                        regexp=record.regexp,
                        replacement=record.replacement,
                    ),
                    ttl=record.ttl,
                )
            )
        if not len(records):
            self.lookup_cname(
                dns_res, record_name, zone, query_name, is_dnssec, self.lookup_naptr
            )

    def lookup_sshfp(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.DNSZone,
        query_name: DNSLabel,
        is_dnssec: bool,
    ):
        records = self.find_records(models.SSHFPRecord, record_name, zone)
        for record in records:
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
            sha1_rd = bytearray(struct.pack("!BB", algo_num, 1))
            sha1_rd.extend(hashlib.sha1(pubkey._decoded_key).digest())
            sha256_rd = bytearray(struct.pack("!BB", algo_num, 2))
            sha256_rd.extend(hashlib.sha256(pubkey._decoded_key).digest())
            dns_res.add_answer(
                dnslib.RR(
                    query_name, QTYPE.SSHFP, rdata=dnslib.RD(sha1_rd), ttl=record.ttl,
                )
            )
            dns_res.add_answer(
                dnslib.RR(
                    query_name, QTYPE.SSHFP, rdata=dnslib.RD(sha256_rd), ttl=record.ttl,
                )
            )
        if not len(records):
            self.lookup_cname(
                dns_res, record_name, zone, query_name, is_dnssec, self.lookup_sshfp
            )

    def lookup_dnskey(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.DNSZone,
        query_name: DNSLabel,
        is_dnssec: bool,
    ):
        if record_name == DNSLabel("@"):
            pub_key = self.priv_key.public_key()
            nums = pub_key.public_numbers()
            dns_res.add_answer(
                dnslib.RR(
                    query_name,
                    QTYPE.DNSKEY,
                    rdata=dnslib.DNSKEY(
                        257,
                        3,
                        13,
                        nums.x.to_bytes(32, byteorder="big")
                        + nums.y.to_bytes(32, byteorder="big"),
                    ),
                    ttl=86400,
                )
            )
            if zone.zsk_private:
                priv_key = load_pem_private_key(
                    zone.zsk_private.encode(), password=None, backend=default_backend()
                )
                if not issubclass(type(priv_key), EllipticCurvePrivateKey):
                    raise Exception("Only EC private keys supported")
                nums = priv_key.public_key().public_numbers()
                dns_res.add_answer(
                    dnslib.RR(
                        query_name,
                        QTYPE.DNSKEY,
                        rdata=dnslib.DNSKEY(
                            256,
                            3,
                            13,
                            nums.x.to_bytes(32, byteorder="big")
                            + nums.y.to_bytes(32, byteorder="big"),
                        ),
                        ttl=86400,
                    )
                )
            self.sign_rrset(
                dns_res, zone, query_name, is_dnssec, self.priv_key, flags=257
            )

    def lookup_cds(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: typing.Union[models.DNSZone, models.ReverseDNSZone],
        query_name: DNSLabel,
        is_dnssec: bool,
    ):
        if record_name == DNSLabel("@"):
            if isinstance(zone, models.DNSZone):
                zone_root = zone.zone_root
            elif isinstance(zone, models.ReverseDNSZone):
                zone_network = ipaddress.ip_network(
                    (zone.zone_root_address, zone.zone_root_prefix)
                )
                zone_root = network_to_apra(zone_network)
            else:
                return

            pub_key = self.priv_key.public_key()
            nums = pub_key.public_numbers()
            buffer = dnslib.DNSBuffer()
            rd = dnslib.DNSKEY(
                257,
                3,
                13,
                nums.x.to_bytes(32, byteorder="big")
                + nums.y.to_bytes(32, byteorder="big"),
            )
            buffer.encode_name(dnslib.DNSLabel(zone_root))
            rd.pack(buffer)
            digest = hashlib.sha256(buffer.data).digest()
            tag = make_key_tag(pub_key)
            ds_data = bytearray(struct.pack("!HBB", tag, 13, 2))
            ds_data.extend(digest)
            dns_res.add_answer(
                dnslib.RR(query_name, QTYPE.CDS, rdata=dnslib.RD(ds_data), ttl=86400)
            )

    def lookup_cdnskey(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.DNSZone,
        query_name: DNSLabel,
        is_dnssec: bool,
    ):
        if record_name == DNSLabel("@"):
            pub_key = self.priv_key.public_key()
            nums = pub_key.public_numbers()
            dns_res.add_answer(
                dnslib.RR(
                    query_name,
                    QTYPE.CDNSKEY,
                    rdata=dnslib.DNSKEY(
                        257,
                        3,
                        13,
                        nums.x.to_bytes(32, byteorder="big")
                        + nums.y.to_bytes(32, byteorder="big"),
                    ),
                    ttl=86400,
                )
            )

    def lookup_ds(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.DNSZone,
        query_name: DNSLabel,
        is_dnssec: bool,
    ):
        records = self.find_records(models.DSRecord, record_name, zone)
        for record in records:
            ds_data = bytearray(
                struct.pack(
                    "!HBB", record.key_tag, record.algorithm, record.digest_type
                )
            )
            digest_data = record.digest_bin
            if not digest_data:
                dns_res.header.rcode = RCODE.SERVFAIL
                return
            ds_data.extend(digest_data)
            dns_res.add_answer(
                dnslib.RR(
                    query_name, QTYPE.DS, rdata=dnslib.RD(ds_data), ttl=record.ttl,
                )
            )
        if not len(records):
            self.lookup_cname(
                dns_res, record_name, zone, query_name, is_dnssec, self.lookup_ds
            )

    def lookup_ptr(
        self,
        dns_res: dnslib.DNSRecord,
        addr: IP_ADDR,
        zone: models.ReverseDNSZone,
        query_name: DNSLabel,
        is_dnssec: bool,
    ):
        records = self.find_reverse_records(models.PTRRecord, addr, zone)
        for record in records:
            dns_res.add_answer(
                dnslib.RR(
                    query_name,
                    QTYPE.PTR,
                    rdata=dnslib.PTR(record.pointer),
                    ttl=record.ttl,
                )
            )
        if not len(records):
            address_records = models.AddressRecord.objects.filter(
                address=str(addr), auto_reverse=True, zone__user=zone.user
            )
            if address_records:
                for record in address_records:
                    dns_res.add_answer(
                        dnslib.RR(
                            query_name,
                            QTYPE.PTR,
                            rdata=dnslib.PTR(
                                f"{record.record_name}.{record.zone.zone_root}"
                            ),
                            ttl=record.ttl,
                        )
                    )
            else:
                dns_res.header.rcode = RCODE.NXDOMAIN

    @staticmethod
    def encode_type_bitmap_window(rrlist):
        windows = {}
        out = bytearray()

        for rr in rrlist:
            v = getattr(dnslib.QTYPE, rr)
            w = (v & 0xFF00) >> 8
            if w in windows:
                windows[w].append(v & 0xFF)
            else:
                windows[w] = [v & 0xFF]

        for window, rrs in sorted(windows.items(), key=lambda w: w[0]):
            bitmap = bytearray([0]*32)
            for rr in rrs:
                bitmap[rr//8] |= 1 << (7 - rr % 8)
            while bitmap[-1] == 0:
                bitmap = bitmap[:-1]
            out.extend(struct.pack("BB", window, len(bitmap)) + bitmap)
        return out

    def sign_rrset(
        self,
        dns_res: dnslib.DNSRecord,
        zone: typing.Union[models.DNSZone, models.ReverseDNSZone],
        query_name: DNSLabel,
        is_dnssec: bool,
        priv_key=None,
        flags=256,
    ):
        if isinstance(zone, models.DNSZone):
            zone_root = zone.zone_root
        elif isinstance(zone, models.ReverseDNSZone):
            zone_network = ipaddress.ip_network(
                (zone.zone_root_address, zone.zone_root_prefix)
            )
            zone_root = network_to_apra(zone_network)
        else:
            return
        if not len(dns_res.rr) and not len(dns_res.auth):
            if is_dnssec:
                names = [b"\x00"]
                names.extend(query_name.label)
                if dns_res.header.rcode == RCODE.NXDOMAIN:
                    dns_res.header.rcode = RCODE.NOERROR
                    dns_res.add_auth(
                        dnslib.RR(
                            query_name,
                            QTYPE.NSEC,
                            rdata=dnslib.NSEC(
                                dnslib.DNSLabel(names), ["RRSIG", "NSEC"]
                            ),
                            ttl=86400,
                        )
                    )
                else:
                    qtypes = [
                        'A', 'NS', 'SOA', 'HINFO', 'MX', 'TXT', 'AAAA', 'LOC', 'SRV', 'CERT', 'SSHFP', 'RRSIG', 'NSEC',
                        'DNSKEY', 'TLSA', 'HIP', 'CDS', 'CDNSKEY', 'OPENPGPKEY', 'SPF', 'CAA', 'PTR'
                    ]
                    try:
                        qtypes.remove(dnslib.QTYPE[dns_res.q.qtype])
                    except ValueError:
                        pass
                    bitmap = self.encode_type_bitmap_window(qtypes)
                    buf = dnslib.DNSBuffer()
                    buf.encode_name_nocompress(dnslib.DNSLabel(names))
                    buf.append(bitmap)
                    dns_res.add_auth(
                        dnslib.RR(
                            query_name,
                            QTYPE.NSEC,
                            rdata=dnslib.RD(buf.data),
                            ttl=86400,
                        )
                    )
            dns_res.add_auth(
                dnslib.RR(
                    zone_root,
                    QTYPE.SOA,
                    rdata=dnslib.SOA(
                        NAMESERVERS[0],
                        "noc.as207960.net",
                        (
                            int(zone.last_modified.timestamp()),
                            86400,
                            7200,
                            3600000,
                            172800,
                        ),
                    ),
                    ttl=86400,
                )
            )

        if is_dnssec:
            def sign_section(section, add_fn, priv_key, sign_ns=False):
                rtypes = {}
                for rr in section:
                    if rr.rtype in rtypes.keys():
                        if rr.rname in rtypes[rr.rtype].keys():
                            rtypes[rr.rtype][rr.rname].append(rr)
                        else:
                            rtypes[rr.rtype][rr.rname] = [rr]
                    else:
                        rtypes[rr.rtype] = {rr.rname: [rr]}
                if priv_key is None:
                    if zone.zsk_private:
                        priv_key = load_pem_private_key(
                            zone.zsk_private.encode(),
                            password=None,
                            backend=default_backend(),
                        )
                        if not issubclass(type(priv_key), EllipticCurvePrivateKey):
                            raise Exception("Only EC private keys supported")

                if priv_key is None:
                    return

                pub_key = priv_key.public_key()
                key_tag = make_key_tag(pub_key, flags=flags)
                now_ts = int(timezone.now().timestamp()) - 300

                for rtype, rrs in rtypes.items():
                    if rtype == QTYPE.NS and not sign_ns:
                        continue
                    for label, rrs in rrs.items():
                        if label.matchSuffix(DNSLabel(zone_root)):
                            this_priv_key = priv_key
                            this_zone_root = zone_root
                            this_key_tag = key_tag
                        else:
                            this_zone, _ = self.find_zone(label)
                            if not this_zone:
                                continue
                            this_zone_root = this_zone.zone_root
                            if this_zone.zsk_private:
                                this_priv_key = load_pem_private_key(
                                    this_zone.zsk_private.encode(),
                                    password=None,
                                    backend=default_backend(),
                                )
                                if not issubclass(type(this_priv_key), EllipticCurvePrivateKey):
                                    raise Exception("Only EC private keys supported")
                            else:
                                continue

                            this_pub_key = this_priv_key.public_key()
                            this_key_tag = make_key_tag(this_pub_key, flags=flags)

                        rrsig = dnslib.RRSIG(
                            covered=rtype,
                            algorithm=13,
                            labels=len(label.label),
                            orig_ttl=rrs[0].ttl,
                            sig_inc=now_ts,
                            sig_exp=now_ts + 87000,
                            key_tag=this_key_tag,
                            name=this_zone_root,
                            sig=b"",
                        )
                        data = bytearray()
                        buffer = dnslib.DNSBuffer()
                        rrsig.pack(buffer)
                        data.extend(buffer.data)

                        def rrdata_key(r):
                            buffer = dnslib.DNSBuffer()
                            rd_buffer = dnslib.DNSBuffer()
                            buffer.encode_name_nocompress(r.rname)
                            buffer.pack("!HHI", r.rtype, r.rclass, r.ttl)
                            rdlength_ptr = buffer.offset
                            buffer.pack("!H", 0)
                            start = buffer.offset
                            if isinstance(r.rdata, dnslib.SOA):
                                rd_buffer.encode_name_nocompress(r.rdata.mname)
                                rd_buffer.encode_name_nocompress(r.rdata.rname)
                                rd_buffer.pack("!IIIII", *r.rdata.times)
                            else:
                                r.rdata.pack(rd_buffer)
                            buffer.append(rd_buffer.data)
                            end = buffer.offset
                            buffer.update(rdlength_ptr, "!H", end - start)
                            return buffer.data, rd_buffer.data

                        for rr in sorted(map(rrdata_key, rrs), key=lambda r: r[1]):
                            data.extend(rr[0])

                        # print(data)
                        sig = decode_dss_signature(
                            this_priv_key.sign(data, ec.ECDSA(hashes.SHA256()))
                        )
                        rrsig.sig = sig[0].to_bytes(32, byteorder="big") + sig[
                            1
                        ].to_bytes(32, byteorder="big")
                        add_fn(dnslib.RR(label, QTYPE.RRSIG, rdata=rrsig, ttl=86400))

            sign_section(dns_res.rr, dns_res.add_answer, priv_key, sign_ns=True)
            sign_section(dns_res.auth, dns_res.add_auth, priv_key)
            sign_section(dns_res.ar, dns_res.add_ar, priv_key)

    def handle_secondary(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.SecondaryDNSZone,
        query_name: DNSLabel,
        is_dnssec: bool,
    ):
        def lookup_referral(record_name: DNSLabel):
            nameservers = zone.secondarydnszonerecord_set.filter(
                rtype=int(dnslib.QTYPE.NS)
            ).order_by(Length("record_name").desc())
            ns_found = False
            for nameserver in nameservers:
                if record_name.matchSuffix(nameserver.record_name):
                    ns_found = True
                    try:
                        buffer = dnslib.DNSBuffer(nameserver.rdata)
                        ns = dnslib.NS.parse(buffer, len(nameserver.rdata)).label
                    except (dnslib.DNSError, ValueError):
                        ns = None
                    dns_res.add_auth(
                        dnslib.RR(
                            nameserver.record_name,
                            QTYPE.NS,
                            rdata=dnslib.RD(nameserver.rdata),
                            ttl=nameserver.ttl,
                        )
                    )
                    if is_dnssec:
                        ds_records = zone.secondarydnszonerecord_set.filter(
                            record_name=str(record_name),
                            rtype=int(QTYPE.DS)
                        )
                        for record in ds_records:
                            dns_res.add_auth(
                                dnslib.RR(
                                    nameserver.record_name,
                                    QTYPE.DS,
                                    rdata=dnslib.RD(record.rdata),
                                    ttl=record.ttl,
                                )
                            )
                        if not len(ds_records):
                            nsec_records = zone.secondarydnszonerecord_set.filter(
                                record_name=str(record_name),
                                rtype=int(QTYPE.NSEC)
                            )
                            for record in nsec_records:
                                dns_res.add_answer(dnslib.RR(
                                    query_name, QTYPE.NSEC, ttl=record.ttl, rdata=dnslib.RD(record.rdata)
                                ))
                    if ns:
                        additional_records = zone.secondarydnszonerecord_set.filter(
                            record_name=str(ns),
                        ).filter(
                            Q(rtype=int(dnslib.QTYPE.A)) | Q(rtype=int(dnslib.QTYPE.AAAA)),
                        )
                        for ar in additional_records:
                            dns_res.add_ar(
                                dnslib.RR(
                                    ar.record_name,
                                    ar.rtype,
                                    rdata=dnslib.RD(ar.rdata),
                                    ttl=ar.ttl,
                                )
                            )
            if not ns_found:
                if zone.secondarydnszonerecord_set.filter(
                    record_name=str(record_name),
                ).count() == 0:
                    dns_res.header.rcode = RCODE.NXDOMAIN

        def lookup_cname(record_name: DNSLabel):
            cname_record = zone.secondarydnszonerecord_set.filter(
                record_name=str(record_name),
                rtype=int(QTYPE.CNAME)
            ).first()
            if cname_record:
                dns_res.add_answer(dnslib.RR(
                    query_name, QTYPE.CNAME, ttl=cname_record.ttl, rdata=dnslib.RD(cname_record.rdata)
                ))
                try:
                    buffer = dnslib.DNSBuffer(cname_record.rdata)
                    lookup_record(dnslib.CNAME.parse(buffer, len(cname_record.rdata)).label)
                except (dnslib.DNSError, ValueError):
                    pass
            else:
                lookup_referral(record_name)

        def lookup_record(record_name: DNSLabel):
            records = zone.secondarydnszonerecord_set.filter(
                record_name=str(record_name),
                rtype=int(dns_res.q.qtype)
            )
            for record in records:
                dns_res.add_answer(dnslib.RR(query_name, record.rtype, ttl=record.ttl, rdata=dnslib.RD(record.rdata)))
            if not len(records):
                lookup_cname(record_name)

        lookup_record(record_name)

        if is_dnssec:
            if dns_res.header.rcode == RCODE.NXDOMAIN:
                nsec_records = zone.secondarydnszonerecord_set.filter(
                    rtype=int(QTYPE.NSEC)
                ).order_by('record_name')
                prev = None
                for o in nsec_records:
                    if o.record_name >= record_name:
                        break
                    prev = o
                if prev:
                    dns_res.add_auth(dnslib.RR(query_name, QTYPE.NSEC, ttl=prev.ttl, rdata=dnslib.RD(prev.rdata)))
            if not len(dns_res.a):
                records = zone.secondarydnszonerecord_set.filter(
                    record_name=str(record_name),
                    rtype=int(QTYPE.NSEC)
                )
                for record in records:
                    dns_res.add_auth(dnslib.RR(query_name, QTYPE.NSEC, ttl=record.ttl, rdata=dnslib.RD(record.rdata)))
            covered_rtype = {}
            rrsig_records = {}
            for a in dns_res.a:
                covered_rtype[a.rname] = []
            for a in dns_res.auth:
                covered_rtype[a.rname] = []
            for a in dns_res.ar:
                covered_rtype[a.rname] = []
            for rname in covered_rtype.keys():
                records = zone.secondarydnszonerecord_set.filter(
                    record_name=str(rname.rname),
                    rtype=int(dnslib.QTYPE.RRSIG)
                )
                out_records = {}
                for r in records:
                    try:
                        buffer = dnslib.DNSBuffer(r.rdata)
                        rrsig = dnslib.RRSIG.parse(buffer, len(r.rdata))
                        out_records[rrsig.covered] = r
                    except (dnslib.DNSError, ValueError):
                        pass
                rrsig_records[rname] = out_records
            for a in dns_res.a:
                if a.rtype not in covered_rtype[a.rname]:
                    rrsig = rrsig_records[a.rname].get(a.rtype)
                    if rrsig:
                        dns_res.add_answer(
                            dnslib.RR(a.rname, dnslib.QTYPE.RRSIG, ttl=rrsig.ttl, rdata=dnslib.RD(rrsig.rdata))
                        )
            for a in dns_res.auth:
                if a.rtype not in covered_rtype[a.rname]:
                    rrsig = rrsig_records[a.rname].get(a.rtype)
                    if rrsig:
                        dns_res.add_auth(
                            dnslib.RR(a.rname, dnslib.QTYPE.RRSIG, ttl=rrsig.ttl, rdata=dnslib.RD(rrsig.rdata))
                        )
            for a in dns_res.ar:
                if a.rtype not in covered_rtype[a.rname]:
                    rrsig = rrsig_records[a.rname].get(a.rtype)
                    if rrsig:
                        dns_res.add_ar(
                            dnslib.RR(a.rname, dnslib.QTYPE.RRSIG, ttl=rrsig.ttl, rdata=dnslib.RD(rrsig.rdata))
                        )

    def handle_query(self, dns_req: dnslib.DNSRecord):
        dns_res = dns_req.reply()

        if dns_req.header.opcode != OPCODE.QUERY:
            dns_res.header.rcode = RCODE.REFUSED
            return dns_res

        query_name = dns_req.q.qname
        query_name = DNSLabel(
            list(map(lambda n: n.decode().lower().encode(), query_name.label))
        )
        is_rdns = self.is_rdns(query_name)
        is_dnssec = bool(
            next(
                map(
                    lambda r: r.edns_do,
                    filter(lambda r: r.rtype == QTYPE.OPT, dns_req.ar),
                ),
                0,
            )
        )
        is_axfr = dns_req.q.qtype == QTYPE.AXFR

        if not is_axfr:
            if is_rdns:
                zone, record_name, zone_network = self.find_rzone(query_name)
            else:
                zone, record_name = self.find_zone(query_name)
            if not zone:
                zone, record_name = self.find_secondary_zone(query_name)
                if not zone:
                    dns_res.header.rcode = RCODE.NXDOMAIN
                    return dns_res
                self.handle_secondary(dns_res, record_name, zone, query_name, is_dnssec)
                return dns_res
            dns_res.header.rcode = RCODE.NOERROR

            if not is_rdns:
                if dns_req.q.qtype == QTYPE.SOA:
                    dns_res.add_answer(
                        dnslib.RR(
                            zone.zone_root,
                            QTYPE.SOA,
                            rdata=dnslib.SOA(
                                NAMESERVERS[0],
                                "noc.as207960.net",
                                (
                                    int(zone.last_modified.timestamp()),
                                    86400,
                                    7200,
                                    3600000,
                                    172800,
                                ),
                            ),
                            ttl=86400,
                        )
                    )
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)
                    return dns_res
                elif dns_req.q.qtype in [QTYPE.A, QTYPE.AAAA]:
                    self.lookup_addr(dns_res, record_name, zone, query_name, is_dnssec)
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)
                elif dns_req.q.qtype == QTYPE.MX:
                    self.lookup_mx(dns_res, record_name, zone, query_name, is_dnssec)
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)
                elif dns_req.q.qtype == QTYPE.NS:
                    self.lookup_ns(dns_res, record_name, zone, query_name, is_dnssec)
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)
                elif dns_req.q.qtype == QTYPE.TXT:
                    self.lookup_txt(dns_res, record_name, zone, query_name, is_dnssec)
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)
                elif dns_req.q.qtype == QTYPE.SRV:
                    self.lookup_srv(dns_res, record_name, zone, query_name, is_dnssec)
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)
                elif dns_req.q.qtype == QTYPE.CAA:
                    self.lookup_caa(dns_res, record_name, zone, query_name, is_dnssec)
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)
                elif dns_req.q.qtype == QTYPE.NAPTR:
                    self.lookup_naptr(dns_res, record_name, zone, query_name, is_dnssec)
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)
                elif dns_req.q.qtype == QTYPE.SSHFP:
                    self.lookup_sshfp(dns_res, record_name, zone, query_name, is_dnssec)
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)
                elif dns_req.q.qtype == QTYPE.DNSKEY:
                    self.lookup_dnskey(dns_res, record_name, zone, query_name, is_dnssec)
                elif dns_req.q.qtype == QTYPE.CDS:
                    self.lookup_cds(dns_res, record_name, zone, query_name, is_dnssec)
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)
                elif dns_req.q.qtype == QTYPE.CDNSKEY:
                    self.lookup_cdnskey(dns_res, record_name, zone, query_name, is_dnssec)
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)
                elif dns_req.q.qtype == QTYPE.DS:
                    self.lookup_ds(dns_res, record_name, zone, query_name, is_dnssec)
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)
                elif dns_req.q.qtype == QTYPE.CNAME:
                    record = self.find_records(
                        models.CNAMERecord, record_name, zone
                    ).first()
                    if record:
                        dns_res.add_answer(
                            dnslib.RR(
                                query_name,
                                QTYPE.CNAME,
                                rdata=dnslib.CNAME(record.alias),
                                ttl=record.ttl,
                            )
                        )
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)
                else:
                    self.lookup_cname(dns_res, record_name, zone, query_name, is_dnssec, (lambda _0, _1, _2, _3, _4: None))
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)
            else:
                network = network_to_apra(zone_network)
                record_name_label = query_name.stripSuffix(network)
                if len(record_name_label.label) == 0:
                    record_name_label = DNSLabel("@")
                if dns_req.q.qtype == QTYPE.SOA:
                    dns_res.add_answer(
                        dnslib.RR(
                            network,
                            QTYPE.SOA,
                            rdata=dnslib.SOA(
                                NAMESERVERS[0],
                                "noc.as207960.net",
                                (
                                    int(zone.last_modified.timestamp()),
                                    86400,
                                    7200,
                                    3600000,
                                    172800,
                                ),
                            ),
                            ttl=86400,
                        )
                    )
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)
                    return dns_res
                elif dns_req.q.qtype == QTYPE.PTR:
                    self.lookup_ptr(dns_res, record_name, zone, query_name, is_dnssec)
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)
                elif dns_req.q.qtype == QTYPE.DNSKEY:
                    self.lookup_dnskey(
                        dns_res, record_name_label, zone, query_name, is_dnssec
                    )
                elif dns_req.q.qtype == QTYPE.CDS:
                    self.lookup_cds(dns_res, record_name_label, zone, query_name, is_dnssec)
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)
                elif dns_req.q.qtype == QTYPE.CDNSKEY:
                    self.lookup_cdnskey(
                        dns_res, record_name_label, zone, query_name, is_dnssec
                    )
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)
                elif dns_req.q.qtype == QTYPE.NS and query_name == network:
                    for ns in NAMESERVERS:
                        dns_res.add_answer(
                            dnslib.RR(query_name, QTYPE.NS, rdata=dnslib.NS(ns), ttl=86400,)
                        )
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)
                else:
                    self.sign_rrset(dns_res, zone, query_name, is_dnssec)

            dns_res.add_ar(dnslib.EDNS0(dnslib.DNSLabel("."), flags="do" if is_dnssec else "", version=1))
            return dns_res
        else:
            zone = None
            zones = models.DNSZone.objects.filter(active=True).order_by(Length("zone_root").desc())
            for z in zones:
                zone_root = DNSLabel(z.zone_root)
                if query_name == zone_root:
                    zone = z
            if not zone:
                dns_res.header.rcode = RCODE.REFUSED
                return dns_res

            out = bytearray()
            soa_dns_res = dns_req.reply()
            soa_dns_res.add_answer(
                dnslib.RR(
                    zone.zone_root,
                    QTYPE.SOA,
                    rdata=dnslib.SOA(
                        NAMESERVERS[0],
                        "noc.as207960.net",
                        (
                            int(zone.last_modified.timestamp()),
                            86400,
                            7200,
                            3600000,
                            172800,
                        ),
                    ),
                    ttl=86400,
                )
            )
            # self.sign_rrset(soa_dns_res, zone, query_name, is_dnssec)
            out.extend(soa_dns_res.pack())
            out.extend(dns_res.pack())
            out.extend(soa_dns_res.pack())
            return out

    def Query(self, request: dns_pb2.DnsPacket, context):
        try:
            dns_req = dnslib.DNSRecord.parse(request.msg)
        except dnslib.DNSError:
            dns_res = dnslib.DNSRecord()
            dns_res.header.rcode = RCODE.FORMERR
            return self.make_resp(dns_res)

        try:
            dns_res = self.handle_query(dns_req)
        except Exception as e:
            sentry_sdk.capture_exception(e)
            traceback.print_exc()
            dns_res = dns_req.reply()
            dns_res.header.rcode = RCODE.SERVFAIL
            raise e

        res = self.make_resp(dns_res)
        # print(res)
        return res
