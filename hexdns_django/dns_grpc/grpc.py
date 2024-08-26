import ipaddress
import struct
import traceback
import typing
import dataclasses
import dnslib
import sentry_sdk
import datetime
import hmac
import requests
import sys
import django.core.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from django.conf import settings
from django.db.models import Q
from django.db.models.functions import Length
from django.template.defaultfilters import length
from dnslib import CLASS, OPCODE, QTYPE, RCODE
from dnslib.label import DNSLabel

from . import models
from .proto import dns_pb2, dns_pb2_grpc

NAMESERVERS = ["ns1.as207960.net", "ns2.as207960.net", "ns3.as207960.net", "ns4.as207960.net"]
IP4_APRA = DNSLabel("in-addr.arpa.")
IP6_APRA = DNSLabel("ip6.arpa.")
IP_NETWORK = typing.Union[ipaddress.IPv6Network, ipaddress.IPv4Network]
IP_ADDR = typing.Union[ipaddress.IPv6Address, ipaddress.IPv4Address]
TSIG_BADSIG = 16
TSIG_BADKEY = 17
TSIG_BADTIME = 18
HMAC_NAMES = {
    "hmac-md5.sig-alg.reg.int": "md5",
    "hmac-sha1": "sha1",
    "hmac-sha256": "sha256",
    "hmac-sha384": "sha384",
    "hmac-sha512": "sha512",
}


@dataclasses.dataclass
class TSIG:
    alg_name: DNSLabel
    time_signed: datetime.datetime
    fudge: int
    mac: bytes
    original_id: int
    error: int
    other_data: bytes

    def make_tsig(self) -> bytes:
        buffer = dnslib.DNSBuffer()
        buffer.encode_name_nocompress(self.alg_name)

        timestamp = (int(self.time_signed.timestamp()) << 16) | (self.fudge & 0xFFFF)
        buffer.pack("!QH", timestamp, len(self.mac))
        buffer.append(self.mac)
        buffer.pack("!HHH",  self.original_id, self.error, len(self.other_data))
        buffer.append(self.other_data)

        return buffer.data

    def make_variables(self) -> bytes:
        buffer = dnslib.DNSBuffer()
        buffer.encode_name_nocompress(self.alg_name)

        timestamp = (int(self.time_signed.timestamp()) << 16) | (self.fudge & 0xFFFF)
        buffer.pack("!QHH", timestamp, self.error, len(self.other_data))
        buffer.append(self.other_data)

        return buffer.data

    @classmethod
    def decode_tsig(cls, data: bytes):
        buffer = dnslib.DNSBuffer(data)
        alg_name = buffer.decode_name()
        timestamp, mac_len = buffer.unpack("!QH")
        mac = buffer.get(mac_len)
        original_id, error, other_len = buffer.unpack("!HHH")
        other_data = buffer.get(other_len)

        fudge = timestamp & 0xFFFF
        time_signed_stamp = timestamp >> 16
        time_signed = datetime.datetime.utcfromtimestamp(time_signed_stamp)

        return cls(
            alg_name=alg_name,
            time_signed=time_signed,
            fudge=fudge,
            mac=mac,
            original_id=original_id,
            error=error,
            other_data=other_data
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

    @staticmethod
    def find_zone(
            qname: DNSLabel
    ) -> (typing.Optional[models.DNSZone], typing.Optional[DNSLabel]):
        zones = models.DNSZone.objects.order_by(Length("zone_root").desc())
        for zone in zones:
            zone_root = DNSLabel(zone.zone_root)
            if qname.matchSuffix(zone_root):
                record_name = qname.stripSuffix(zone_root)
                if len(record_name.label) == 0:
                    record_name = DNSLabel("@")
                try:
                    account = zone.get_user().account
                    active = account.subscription_active
                except requests.exceptions.RequestException:
                    active = True
                if active:
                    return zone, record_name
                else:
                    return None, None
        return None, None

    @staticmethod
    def find_records(
            model: typing.Type[models.DNSZoneRecord],
            rname: DNSLabel,
            zone: models.DNSZone,
    ):
        search_name = ".".join(map(lambda n: n.decode(), rname.label))
        records = model.objects.filter(record_name=search_name, zone=zone)
        if records.count():
            return records
        else:
            labels = list(rname.label)
            if len(labels):
                labels[0] = b"*"
            wildcard_search_name = ".".join(map(lambda n: n.decode(), labels))
            return model.objects.filter(record_name=wildcard_search_name, zone=zone)

    def any_records(
            self, rname: DNSLabel, zone: models.DNSZone, include_cname: bool = True
    ):
        search_name = ".".join(map(lambda n: n.decode(), rname.label))
        labels = list(rname.label)
        if len(labels):
            labels[0] = b"*"
        wildcard_search_name = ".".join(map(lambda n: n.decode(), labels))
        if models.AddressRecord.objects.filter(zone=zone).filter(
                Q(record_name=search_name) | Q(record_name=wildcard_search_name)
        ).count():
            return True
        if models.DynamicAddressRecord.objects.filter(zone=zone).filter(
                Q(record_name=search_name) | Q(record_name=wildcard_search_name)
        ).count():
            return True
        if include_cname and models.CNAMERecord.objects.filter(zone=zone).filter(
                Q(record_name=search_name) | Q(record_name=wildcard_search_name)
        ).count():
            return True
        if models.RedirectRecord.objects.filter(zone=zone).filter(
                Q(record_name=search_name) | Q(record_name=wildcard_search_name)
        ).count():
            return True
        if models.MXRecord.objects.filter(zone=zone).filter(
                Q(record_name=search_name) | Q(record_name=wildcard_search_name)
        ).count():
            return True
        if models.NSRecord.objects.filter(zone=zone).filter(
                Q(record_name=search_name) | Q(record_name=wildcard_search_name)
        ).count():
            return True
        if models.TXTRecord.objects.filter(zone=zone).filter(
                Q(record_name=search_name) | Q(record_name=wildcard_search_name)
        ).count():
            return True
        if models.SRVRecord.objects.filter(zone=zone).filter(
                Q(record_name=search_name) | Q(record_name=wildcard_search_name)
        ).count():
            return True
        if models.CAARecord.objects.filter(zone=zone).filter(
                Q(record_name=search_name) | Q(record_name=wildcard_search_name)
        ).count():
            return True
        if models.NAPTRRecord.objects.filter(zone=zone).filter(
                Q(record_name=search_name) | Q(record_name=wildcard_search_name)
        ).count():
            return True
        if models.SSHFPRecord.objects.filter(zone=zone).filter(
                Q(record_name=search_name) | Q(record_name=wildcard_search_name)
        ).count():
            return True
        if models.DSRecord.objects.filter(zone=zone).filter(
                Q(record_name=search_name) | Q(record_name=wildcard_search_name)
        ).count():
            return True
        if models.ANAMERecord.objects.filter(zone=zone).filter(
                Q(record_name=search_name) | Q(record_name=wildcard_search_name)
        ).count():
            return True
        if models.LOCRecord.objects.filter(zone=zone).filter(
                Q(record_name=search_name) | Q(record_name=wildcard_search_name)
        ).count():
            return True
        if models.HINFORecord.objects.filter(zone=zone).filter(
                Q(record_name=search_name) | Q(record_name=wildcard_search_name)
        ).count():
            return True
        if models.RPRecord.objects.filter(zone=zone).filter(
                Q(record_name=search_name) | Q(record_name=wildcard_search_name)
        ).count():
            return True

        port, scheme, new_record_name = self.parse_https_record_name(rname)
        labels = list(new_record_name.label)
        if len(labels):
            labels[0] = b"*"
        new_wildcard_search_name = ".".join(map(lambda n: n.decode(), labels))
        new_record_name = ".".join(map(lambda n: n.decode(), new_record_name.label))
        if models.HTTPSRecord.objects.filter(zone=zone).filter(
                Q(record_name=new_record_name) | Q(record_name=new_wildcard_search_name)
        ).filter(scheme=scheme, port=port).count():
            return True

        return False

    def any_record_type(
            self, rname: DNSLabel, zone: models.DNSZone, qtype: int
    ):
        search_name = ".".join(map(lambda n: n.decode(), rname.label))

        if qtype in [QTYPE.A, QTYPE.AAAA]:
            records = self.find_records(models.AddressRecord, rname, zone)
            for record in records:
                address = ipaddress.ip_address(record.address)
                if type(address) == ipaddress.IPv4Address and qtype == QTYPE.A:
                    return True
                elif type(address) == ipaddress.IPv6Address and qtype == QTYPE.AAAA:
                    return True
            return False
        elif qtype == QTYPE.MX:
            if models.MXRecord.objects.filter(record_name=search_name, zone=zone).count():
                return True
        elif qtype == QTYPE.NS:
            if models.NSRecord.objects.filter(record_name=search_name, zone=zone).count():
                return True
        elif qtype == QTYPE.TXT:
            if models.TXTRecord.objects.filter(record_name=search_name, zone=zone).count():
                return True
        elif qtype == QTYPE.SRV:
            if models.SRVRecord.objects.filter(record_name=search_name, zone=zone).count():
                return True
        elif qtype == QTYPE.CAA:
            if models.CAARecord.objects.filter(record_name=search_name, zone=zone).count():
                return True
        elif qtype == QTYPE.NAPTR:
            if models.NAPTRRecord.objects.filter(record_name=search_name, zone=zone).count():
                return True
        elif qtype == QTYPE.SSHFP:
            if models.SSHFPRecord.objects.filter(record_name=search_name, zone=zone).count():
                return True
        elif qtype == QTYPE.DS:
            if models.DSRecord.objects.filter(record_name=search_name, zone=zone).count():
                return True
        elif qtype == QTYPE.LOC:
            if models.LOCRecord.objects.filter(record_name=search_name, zone=zone).count():
                return True
        elif qtype == QTYPE.HINFO:
            if models.HINFORecord.objects.filter(record_name=search_name, zone=zone).count():
                return True
        elif qtype == QTYPE.RP:
            if models.RPRecord.objects.filter(record_name=search_name, zone=zone).count():
                return True
        elif qtype == QTYPE.HTTPS:
            port, scheme, new_record_name = self.parse_https_record_name(rname)
            new_record_name = ".".join(map(lambda n: n.decode(), new_record_name.label))
            if models.HTTPSRecord.objects.filter(
                    record_name=new_record_name, zone=zone, scheme=scheme, port=port
            ).count():
                return True
        elif qtype == QTYPE.CNAME:
            if models.CNAMERecord.objects.filter(record_name=search_name, zone=zone).count():
                return True

        return False

    @staticmethod
    def make_resp(res: typing.Union[dnslib.DNSRecord, bytes]) -> dns_pb2.DnsPacket:
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
        if not ns_found and record_name != "@":
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
        if not self.any_records(record_name, zone, include_cname=False):
            cname_record = self.find_records(models.CNAMERecord, record_name, zone).first()
            if cname_record:
                dns_res.add_answer(cname_record.to_rr(query_name))
                new_zone, new_record_name = self.find_zone(DNSLabel(cname_record.alias))
                if new_zone and new_zone != zone and record_name != new_record_name:
                    func(dns_res, new_record_name, new_zone, cname_record.alias, is_dnssec)
            else:
                self.lookup_referral(dns_res, record_name, zone, is_dnssec)
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
                dns_res.add_answer(record.to_rr(query_name))
            elif type(address) == ipaddress.IPv6Address and dns_res.q.qtype == QTYPE.AAAA:
                addr_found = True
                dns_res.add_answer(record.to_rr(query_name))
        if not addr_found:
            records = self.find_records(models.DynamicAddressRecord, record_name, zone)
            for record in records:
                if dns_res.q.qtype == QTYPE.A and record.current_ipv4:
                    addr_found = True
                    dns_res.add_answer(record.to_rr_v4(query_name))
                elif dns_res.q.qtype == QTYPE.AAAA and record.current_ipv6:
                    addr_found = True
                    dns_res.add_answer(record.to_rr_v6(query_name))
        if not addr_found:
            records = self.find_records(models.ANAMERecord, record_name, zone)
            for record in records:
                rrs = record.to_rrs(dns_res.q.qtype, query_name)
                if rrs:
                    addr_found = True
                    for rr in rrs:
                        dns_res.add_answer(rr)
        if not addr_found:
            redirect_record = self.find_records(models.RedirectRecord, record_name, zone).first()
            if redirect_record:
                if dns_res.q.qtype == QTYPE.A:
                    addr_found = True
                    dns_res.add_answer(redirect_record.to_rr_v4(query_name))
                elif dns_res.q.qtype == QTYPE.AAAA:
                    addr_found = True
                    dns_res.add_answer(redirect_record.to_rr_v6(query_name))
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
                addr_found = True
                dns_res.add_ar(record.to_rr(query_name))
            if not addr_found:
                records = self.find_records(models.DynamicAddressRecord, record_name, zone)
                for record in records:
                    v4_rr = record.to_rr_v4(query_name)
                    v6_rr = record.to_rr_v6(query_name)

                    if v4_rr:
                        dns_res.add_ar(v4_rr)
                    if v6_rr:
                        dns_res.add_ar(v6_rr)
            if not addr_found:
                records = self.find_records(models.ANAMERecord, record_name, zone)
                for record in records:
                    rrs = record.to_rrs(dns_res.q.qtype, query_name)
                    for rr in rrs:
                        dns_res.add_answer(rr)

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
            dns_res.add_answer(record.to_rr(query_name))
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
            dns_res.add_answer(record.to_rr(query_name))
        if record_name == "@":
            if hasattr(zone, "custom_ns") and zone.custom_ns.count():
                for ns in zone.custom_ns.all():
                    dns_res.add_answer(
                        dnslib.RR(query_name, QTYPE.NS, rdata=dnslib.NS(ns.nameserver), ttl=86400, )
                    )
            else:
                for ns in NAMESERVERS:
                    dns_res.add_answer(
                        dnslib.RR(query_name, QTYPE.NS, rdata=dnslib.NS(ns), ttl=86400, )
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
            dns_res.add_answer(record.to_rr(query_name))
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
            dns_res.add_answer(record.to_rr(query_name))
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
            dns_res.add_answer(record.to_rr(query_name))
        if not len(records):
            redirect_record = self.find_records(models.RedirectRecord, record_name, zone).first()
            if redirect_record:
                dns_res.add_answer(redirect_record.to_rr_caa(query_name))
            else:
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
            dns_res.add_answer(record.to_rr(query_name))
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
            for rr in record.to_rrs(query_name):
                dns_res.add_answer(rr)
        if not len(records):
            self.lookup_cname(
                dns_res, record_name, zone, query_name, is_dnssec, self.lookup_sshfp
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
            rr = record.to_rr(query_name)
            if rr:
                dns_res.add_answer(rr)
        if not len(records):
            self.lookup_cname(
                dns_res, record_name, zone, query_name, is_dnssec, self.lookup_ds
            )

    def lookup_loc(
            self,
            dns_res: dnslib.DNSRecord,
            record_name: DNSLabel,
            zone: models.DNSZone,
            query_name: DNSLabel,
            is_dnssec: bool,
    ):

        records = self.find_records(models.LOCRecord, record_name, zone)  # type: typing.List[models.LOCRecord]
        for record in records:
            dns_res.add_answer(record.to_rr(query_name))

        if not len(records):
            self.lookup_cname(
                dns_res, record_name, zone, query_name, is_dnssec, self.lookup_loc
            )

    def lookup_hinfo(
            self,
            dns_res: dnslib.DNSRecord,
            record_name: DNSLabel,
            zone: models.DNSZone,
            query_name: DNSLabel,
            is_dnssec: bool,
    ):
        records = self.find_records(models.HINFORecord, record_name, zone)  # type: typing.List[models.HINFORecord]
        for record in records:
            dns_res.add_answer(record.to_rr(query_name))
        if not len(records):
            self.lookup_cname(
                dns_res, record_name, zone, query_name, is_dnssec, self.lookup_hinfo
            )

    def lookup_rp(
            self,
            dns_res: dnslib.DNSRecord,
            record_name: DNSLabel,
            zone: models.DNSZone,
            query_name: DNSLabel,
            is_dnssec: bool,
    ):
        records = self.find_records(models.RPRecord, record_name, zone)  # type: typing.List[models.RPRecord]
        for record in records:
            dns_res.add_answer(record.to_rr(query_name))

        if not len(records):
            self.lookup_cname(
                dns_res, record_name, zone, query_name, is_dnssec, self.lookup_rp
            )

    @staticmethod
    def parse_https_record_name(record_name: DNSLabel):
        port = 443
        scheme = "https"
        new_record_name = record_name
        if len(record_name.label) >= 2:
            poss_port = record_name.label[0]
            poss_scheme = record_name.label[1]
            if poss_port.startswith(b"_") and poss_scheme.startswith(b"_"):
                try:
                    poss_port = int(poss_port[1:].decode())
                    poss_scheme = poss_scheme[1:].decode()
                except (UnicodeDecodeError, ValueError):
                    pass
                else:
                    port = poss_port
                    scheme = poss_scheme
                    if len(record_name.label) > 2:
                        new_record_name = dnslib.DNSLabel(record_name.label[2:])
                    else:
                        new_record_name = dnslib.DNSLabel("@")
        return port, scheme, new_record_name

    def lookup_https(
            self,
            dns_res: dnslib.DNSRecord,
            record_name: DNSLabel,
            zone: models.DNSZone,
            query_name: DNSLabel,
            is_dnssec: bool,
    ):
        port, scheme, new_record_name = self.parse_https_record_name(record_name)
        records = self.find_records(models.HTTPSRecord, new_record_name, zone)
        records = list(filter(lambda r: r.scheme == scheme and r.port == port, records))
        for record in records:
            dns_res.add_answer(record.to_rr(query_name))
        if not len(records):
            self.lookup_cname(
                dns_res, record_name, zone, query_name, is_dnssec, self.lookup_sshfp
            )

    def lookup_dhcid(
            self,
            dns_res: dnslib.DNSRecord,
            record_name: DNSLabel,
            zone: models.DNSZone,
            query_name: DNSLabel,
            is_dnssec: bool,
    ):
        records = self.find_records(models.DHCIDRecord, record_name, zone)  # type: typing.List[models.DHCIDRecord]
        for record in records:
            dns_res.add_answer(record.to_rr(query_name))

        if not len(records):
            self.lookup_cname(
                dns_res, record_name, zone, query_name, is_dnssec, self.lookup_dhcid
            )

    def lookup_tlsa(
            self,
            dns_res: dnslib.DNSRecord,
            record_name: DNSLabel,
            zone: models.DNSZone,
            query_name: DNSLabel,
            is_dnssec: bool,
    ):
        records = self.find_records(models.TLSARecord, record_name, zone)  # type: typing.List[models.TLSARecord]
        for record in records:
            dns_res.add_answer(record.to_rr(query_name))

        if not len(records):
            self.lookup_cname(
                dns_res, record_name, zone, query_name, is_dnssec, self.lookup_tlsa
            )

    def handle_axfr_query(self, dns_req: dnslib.DNSRecord):
        dns_res = dns_req.reply(ra=False)

        if dns_req.header.opcode != OPCODE.QUERY:
            dns_res.header.rcode = RCODE.REFUSED
            yield dns_res
            return

        query_name = dns_req.q.qname
        query_name = DNSLabel(
            list(map(lambda n: n.decode().lower().encode(), query_name.label))
        )

        zone = None
        zones = models.DNSZone.objects.order_by(Length("zone_root").desc())
        for z in zones:
            zone_root = DNSLabel(z.zone_root)
            if query_name == zone_root:
                zone = z
        if not zone:
            dns_res.header.rcode = RCODE.REFUSED
            yield dns_res
            return

        soa_dns_res = dns_req.reply(ra=False)
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

        yield soa_dns_res
        yield dns_res
        yield soa_dns_res

        # self.sign_rrset(soa_dns_res, zone, query_name, is_dnssec)

    def handle_update_query(self, dns_req: dnslib.DNSRecord):
        dns_res = dns_req.reply(ra=False)

        # RFC 2136 § 3.1
        if dns_req.header.opcode != OPCODE.UPDATE or dns_req.q.qclass != CLASS.IN or dns_req.q.qtype != QTYPE.SOA:
            dns_res.header.rcode = RCODE.REFUSED
            return dns_res

        req_tsig = None
        if dns_req.ar:
            last_ar = dns_req.ar[-1]
            if last_ar.rtype == QTYPE.TSIG:
                req_tsig = last_ar
                del dns_req.ar[-1]
                dns_req.set_header_qa()

        if not req_tsig:
            dns_res.header.rcode = RCODE.REFUSED
            return dns_res

        zone_name = dns_req.q.qname
        zone_name = DNSLabel(
            list(map(lambda n: n.decode().lower().encode(), zone_name.label))
        )

        tsig_key = None  # type: typing.Optional[models.DNSZoneUpdateSecrets]
        if req_tsig.rname.matchSuffix(zone_name):
            tsig_key_id = str(req_tsig.rname.stripSuffix(zone_name)).strip(".")
            try:
                tsig_key = models.DNSZoneUpdateSecrets.objects.filter(id=str(tsig_key_id)).first()
            except django.core.exceptions.ValidationError:
                pass

        def tsig_unsigned_error(error):
            dns_res.header.rcode = RCODE.NOTAUTH
            res_tsig = TSIG(
                alg_name=dnslib.DNSLabel("."),
                time_signed=datetime.datetime.utcnow(),
                fudge=300,
                mac=b'',
                original_id=dns_res.header.id,
                error=error,
                other_data=b''
            )
            dns_res.add_ar(dnslib.RR(
                req_tsig.rname, QTYPE.TSIG, getattr(CLASS, "*"), 0,
                dnslib.RD(res_tsig.make_tsig())
            ))

        if tsig_key is None:
            tsig_unsigned_error(TSIG_BADKEY)
            return dns_res

        incoming_tsig = TSIG.decode_tsig(req_tsig.rdata.data)
        tsig_alg_label = ".".join(map(lambda n: n.decode().lower(), incoming_tsig.alg_name.label))
        if tsig_alg_label not in HMAC_NAMES:
            tsig_unsigned_error(TSIG_BADSIG)
            return dns_res

        # RFC 2845 § 4.5.3
        message_digest = HMAC_NAMES[tsig_alg_label]
        incoming_hmac = hmac.new(bytes(tsig_key.secret), digestmod=message_digest)
        incoming_hmac2 = hmac.new(bytes(tsig_key.secret), digestmod=message_digest)
        dns_req.header.id = incoming_tsig.original_id

        for r in dns_req.rr:
            if r.rdata == '':
                r.rdata = dnslib.RD(data=b'')
        for r in dns_req.auth:
            if r.rdata == '':
                r.rdata = dnslib.RD(data=b'')
        for r in dns_req.ar:
            if r.rdata == '':
                r.rdata = dnslib.RD(data=b'')

        def pack_rr_canon(rd, buffer):
            buffer.encode_name_nocompress(rd.rname)
            buffer.pack("!HHI", rd.rtype, rd.rclass, rd.ttl)
            rdlength_ptr = buffer.offset
            buffer.pack("!H", 0)
            start = buffer.offset
            if rd.rtype == QTYPE.OPT:
                for opt in rd.rdata:
                    opt.pack(buffer)
            elif isinstance(rd.rdata, dnslib.MX):
                buffer.pack("!H", rd.rdata.preference)
                buffer.encode_name_nocompress(rd.rdata.label)
            elif isinstance(rd.rdata, dnslib.CNAME):
                buffer.encode_name_nocompress(rd.rdata.label)
            elif isinstance(rd.rdata, dnslib.SOA):
                buffer.encode_name_nocompress(rd.rdata.mname)
                buffer.encode_name_nocompress(rd.rdata.rname)
                buffer.pack("!IIIII", *rd.rdata.times)
            elif isinstance(rd.rdata, dnslib.SRV):
                buffer.pack("!HHH", rd.rdata.priority, rd.rdata.weight, rd.rdata.port)
                buffer.encode_name_nocompress(rd.rdata.target)
            else:
                rd.rdata.pack(buffer)
            end = buffer.offset
            buffer.update(rdlength_ptr, "!H", end-start)

        d = dns_req.pack()
        db = dnslib.DNSBuffer()
        dns_req.header.pack(db)
        for q in dns_req.questions:
            db.encode_name(q.qname)
            db.pack("!HH", q.qtype, q.qclass)
        for rr in dns_req.rr:
            pack_rr_canon(rr, db)
        for auth in dns_req.auth:
            pack_rr_canon(auth, db)
        for ar in dns_req.ar:
            pack_rr_canon(ar, db)
        d2 = db.data

        for r in dns_req.rr:
            if type(r.rdata) == dnslib.RD and r.rdata.data == b'':
                r.rdata = ''
        for r in dns_req.auth:
            if type(r.rdata) == dnslib.RD and r.rdata.data == b'':
                r.rdata = ''
        for r in dns_req.ar:
            if type(r.rdata) == dnslib.RD and r.rdata.data == b'':
                r.rdata = ''

        temp_buffer = dnslib.DNSBuffer()
        temp_buffer.encode_name_nocompress(req_tsig.rname)
        temp_buffer.pack("!HI", getattr(CLASS, "*"), 0)
        d += temp_buffer.data
        d2 += temp_buffer.data
        d += incoming_tsig.make_variables()
        d2 += incoming_tsig.make_variables()
        incoming_hmac.update(d)
        incoming_hmac2.update(d2)
        incoming_digest = incoming_hmac.digest()
        incoming_digest2 = incoming_hmac2.digest()

        if (incoming_digest != incoming_tsig.mac) and (incoming_digest2 != incoming_tsig.mac):
            tsig_unsigned_error(TSIG_BADSIG)
            return dns_res

        # RFC 2845 § 4.2
        def sign_resp(error=0, other_data=b'', time_now=None):
            if time_now is None:
                time_now = datetime.datetime.utcnow()

            if error != 0:
                dns_res.header.rcode = RCODE.NOTAUTH

            outgoing_tsig = TSIG(
                alg_name=incoming_tsig.alg_name,
                time_signed=time_now,
                fudge=300,
                mac=b'',
                original_id=dns_res.header.id,
                error=error,
                other_data=other_data
            )

            outgoing_hmac = hmac.new(bytes(tsig_key.secret), digestmod=message_digest)
            outgoing_hmac.update(struct.pack('!H', len(incoming_tsig.mac)))
            outgoing_hmac.update(incoming_tsig.mac)
            outgoing_hmac.update(dns_res.pack())
            temp_buffer = dnslib.DNSBuffer()
            temp_buffer.encode_name_nocompress(req_tsig.rname)
            temp_buffer.pack("!HI", getattr(CLASS, "*"), 0)
            outgoing_hmac.update(temp_buffer.data)
            outgoing_hmac.update(outgoing_tsig.make_variables())

            outgoing_digest = outgoing_hmac.digest()
            outgoing_tsig.mac = outgoing_digest

            dns_res.add_ar(dnslib.RR(
                req_tsig.rname, QTYPE.TSIG, getattr(CLASS, "*"), 0,
                dnslib.RD(outgoing_tsig.make_tsig())
            ))

        # RFC 2845 § 4.5.2
        now = datetime.datetime.utcnow()
        min_time = incoming_tsig.time_signed - datetime.timedelta(seconds=incoming_tsig.fudge)
        max_time = incoming_tsig.time_signed + datetime.timedelta(seconds=incoming_tsig.fudge)
        if now < min_time or now > max_time:
            server_timestamp = int(now.timestamp())
            upper_time = (server_timestamp >> 32) & 0xffff
            lower_time = server_timestamp & 0xffffffff
            sign_resp(TSIG_BADTIME, struct.pack("!HI", upper_time, lower_time), time_now=incoming_tsig.time_signed)
            return dns_res

        zone = None
        zones = models.DNSZone.objects.order_by(Length("zone_root").desc())
        for z in zones:
            zone_root = DNSLabel(z.zone_root)
            if zone_name == zone_root:
                zone = z
        if not zone:
            dns_res.header.rcode = RCODE.NOTAUTH
            sign_resp()
            return dns_res

        if tsig_key.zone != zone:
            dns_res.header.rcode = RCODE.NOTAUTH
            sign_resp()
            return dns_res

        prset = dns_req.rr
        upset = dns_req.auth

        # RFC 2136 § 3.2
        temp_prereq_rrset = {}

        for rr in prset:
            if rr.ttl != 0:
                dns_res.header.rcode = RCODE.FORMERR
                sign_resp()
                return dns_res

            if not rr.rname.matchSuffix(zone_name):
                dns_res.header.rcode = RCODE.NOTZONE
                sign_resp()
                return dns_res

            record_name = rr.rname.stripSuffix(zone_name)
            if len(record_name.label) == 0:
                record_name = DNSLabel("@")

            # RFC 2136 § 3.2.1
            if rr.rclass == getattr(CLASS, "*"):
                if rr.rdata != '':
                    dns_res.header.rcode = RCODE.FORMERR
                    sign_resp()
                    return dns_res

                if rr.rtype == QTYPE.ANY:
                    if not self.any_records(record_name, zone):
                        dns_res.header.rcode = RCODE.NXDOMAIN
                        sign_resp()
                        return dns_res
                else:
                    if not self.any_record_type(record_name, zone, rr.rtype):
                        dns_res.header.rcode = RCODE.NXRRSET
                        sign_resp()
                        return dns_res

            # RFC 2136 § 3.2.2
            elif rr.rclass == getattr(CLASS, "None"):
                if rr.rdata != '':
                    dns_res.header.rcode = RCODE.FORMERR
                    sign_resp()
                    return dns_res

                if rr.rtype == QTYPE.ANY:
                    if self.any_records(record_name, zone):
                        dns_res.header.rcode = RCODE.YXDOMAIN
                        sign_resp()
                        return dns_res
                else:
                    if self.any_record_type(record_name, zone, rr.rtype):
                        dns_res.header.rcode = RCODE.YXRRSET
                        sign_resp()
                        return dns_res

            # RFC 2136 § 3.2.3
            elif rr.rclass == dns_req.q.qclass:
                temp_key = (rr.rname, rr.rtype)
                if temp_key in temp_prereq_rrset:
                    temp_prereq_rrset[temp_key].append(rr)
                else:
                    temp_prereq_rrset[temp_key] = [rr]
            else:
                dns_res.header.rcode = RCODE.FORMERR
                sign_resp()
                return dns_res

        # RFC 2136 § 3.2.5
        for (rname, rtype), values in temp_prereq_rrset.items():
            record_name = rname.stripSuffix(zone_name)
            if len(record_name.label) == 0:
                record_name = DNSLabel("@")

            temp_dns_res = dnslib.DNSRecord()
            temp_dns_res.add_question(dnslib.DNSQuestion(rname, rtype))

            if rtype in [QTYPE.A, QTYPE.AAAA]:
                self.lookup_addr(temp_dns_res, record_name, zone, rname, False)
            elif rtype == QTYPE.MX:
                self.lookup_mx(temp_dns_res, record_name, zone, rname, False)
            elif rtype == QTYPE.NS:
                self.lookup_ns(temp_dns_res, record_name, zone, rname, False)
            elif rtype == QTYPE.TXT:
                self.lookup_txt(temp_dns_res, record_name, zone, rname, False)
            elif rtype == QTYPE.SRV:
                self.lookup_srv(temp_dns_res, record_name, zone, rname, False)
            elif rtype == QTYPE.CAA:
                self.lookup_caa(temp_dns_res, record_name, zone, rname, False)
            elif rtype == QTYPE.NAPTR:
                self.lookup_naptr(temp_dns_res, record_name, zone, rname, False)
            elif rtype == QTYPE.SSHFP:
                self.lookup_sshfp(temp_dns_res, record_name, zone, rname, False)
            elif rtype == QTYPE.DS:
                self.lookup_ds(temp_dns_res, record_name, zone, rname, False)
            elif rtype == QTYPE.LOC:
                self.lookup_loc(temp_dns_res, record_name, zone, rname, False)
            elif rtype == QTYPE.HINFO:
                self.lookup_hinfo(temp_dns_res, record_name, zone, rname, False)
            elif rtype == QTYPE.RP:
                self.lookup_rp(temp_dns_res, record_name, zone, rname, False)
            elif rtype == QTYPE.HTTPS:
                self.lookup_https(temp_dns_res, record_name, zone, rname, False)
            elif rtype == QTYPE.DHCID:
                self.lookup_dhcid(temp_dns_res, record_name, zone, rname, False)
            elif rtype == QTYPE.TLSA:
                self.lookup_tlsa(temp_dns_res, record_name, zone, rname, False)
            elif rtype == QTYPE.CNAME:
                record = self.find_records(
                    models.CNAMERecord, record_name, zone
                ).first()
                if record:
                    dns_res.add_answer(
                        dnslib.RR(
                            rname,
                            QTYPE.CNAME,
                            rdata=dnslib.CNAME(record.alias),
                            ttl=record.ttl,
                        )
                    )

            found_rr = temp_dns_res.rr
            for rr in found_rr:
                rr.ttl = 0
            values.sort(key=lambda r: (r.rname, r.rdata))
            found_rr.sort(key=lambda r: (r.rname, r.rdata))

            if values != found_rr:
                dns_res.header.rcode = RCODE.YXRRSET
                sign_resp()
                return dns_res

        supported_types = (
            QTYPE.A, QTYPE.AAAA, QTYPE.MX, QTYPE.NS, QTYPE.TXT, QTYPE.SRV, QTYPE.CAA, QTYPE.NAPTR, QTYPE.DS,
            QTYPE.LOC, QTYPE.HINFO, QTYPE.RP, QTYPE.CNAME, QTYPE.DHCID, QTYPE.TLSA
        )

        # RFC 2136 § 3.4.1
        for rr in upset:
            # RFC 2136 § 3.4.1
            if rr.rclass not in (getattr(CLASS, "*"), getattr(CLASS, "None"), dns_req.q.qclass):
                dns_res.header.rcode = RCODE.YXRRSET
                sign_resp()
                return dns_res

            if not rr.rname.matchSuffix(zone_name):
                dns_res.header.rcode = RCODE.NOTZONE
                sign_resp()
                return dns_res

            # RFC 2136 § 3.4.1.2
            if rr.rclass == dns_req.q.qclass:
                if rr.rtype not in supported_types:
                    dns_res.header.rcode = RCODE.FORMERR
                    sign_resp()
                    return dns_res

            elif rr.rclass == getattr(CLASS, "*"):
                if rr.rdata != '' or rr.rtype not in supported_types + (QTYPE.ANY,) or rr.ttl != 0:
                    dns_res.header.rcode = RCODE.FORMERR
                    sign_resp()
                    return dns_res

            elif rr.rclass == getattr(CLASS, "None"):
                if rr.ttl != 0 or rr.rtype not in supported_types:
                    dns_res.header.rcode = RCODE.FORMERR
                    sign_resp()
                    return dns_res

            else:
                dns_res.header.rcode = RCODE.FORMERR
                sign_resp()
                return dns_res

        def get_record_models(rrtype, record_name: dnslib.DNSLabel):
            if rrtype in [QTYPE.A, QTYPE.AAAA]:
                return self.find_records(models.AddressRecord, record_name, zone)
            elif rrtype == QTYPE.MX:
                return self.find_records(models.MXRecord, record_name, zone)
            elif rrtype == QTYPE.NS:
                return self.find_records(models.NSRecord, record_name, zone)
            elif rrtype == QTYPE.TXT:
                return self.find_records(models.TXTRecord, record_name, zone)
            elif rrtype == QTYPE.SRV:
                return self.find_records(models.SRVRecord, record_name, zone)
            elif rrtype == QTYPE.CAA:
                return self.find_records(models.CAARecord, record_name, zone)
            elif rrtype == QTYPE.NAPTR:
                return self.find_records(models.NAPTRRecord, record_name, zone)
            elif rrtype == QTYPE.DS:
                return self.find_records(models.DSRecord, record_name, zone)
            elif rrtype == QTYPE.LOC:
                return self.find_records(models.LOCRecord, record_name, zone)
            elif rrtype == QTYPE.HINFO:
                return self.find_records(models.HINFORecord, record_name, zone)
            elif rrtype == QTYPE.RP:
                return self.find_records(models.RPRecord, record_name, zone)
            elif rrtype == QTYPE.DHCID:
                return self.find_records(models.DHCIDRecord, record_name, zone)
            elif rrtype == QTYPE.TLSA:
                return self.find_records(models.TLSARecord, record_name, zone)
            elif rrtype == QTYPE.CNAME:
                return self.find_records(models.CNAMERecord, record_name, zone)
            else:
                return None

        def can_manage(rrtype, record_name: dnslib.DNSLabel):
            if tsig_key.restrict_to != "@":
                restrict_suffix = dnslib.DNSLabel(tsig_key.restrict_to)
                if not record_name.matchSuffix(restrict_suffix):
                    return False

            if tsig_key.type == tsig_key.TYPE_UNLIMITED:
                return True
            elif tsig_key.type == tsig_key.TYPE_ACME_DNS01:
                if record_name.label[0] == b"_acme-challenge" and rrtype == QTYPE.TXT:
                    return True
                else:
                    return False
            else:
                return False

        # RFC 2136 § 3.4.2
        to_update = []
        for rr in upset:
            record_name = rr.rname.stripSuffix(zone_name)

            # RFC 2136 § 3.4.2.2
            if rr.rclass == dns_req.q.qclass:
                if not can_manage(rr.rtype, record_name):
                    dns_res.header.rcode = RCODE.NOTAUTH
                    sign_resp()
                    return dns_res

                def _try_update():
                    if rr.rtype == QTYPE.CNAME:
                        if self.any_records(record_name, zone, include_cname=False):
                            return False
                    elif self.any_record_type(record_name, zone, QTYPE.CNAME):
                        return False

                    records = get_record_models(rr.rtype, record_name)
                    if records is None:
                        return True

                    for record in records:
                        record_rr = record.to_rr(rr.rname)

                        if rr.rdata == record_rr.rdata:
                            record.update_from_rr(rr)
                            record.save()
                            return False

                    return True

                if rr.rtype in [QTYPE.A, QTYPE.AAAA]:
                    new_record = models.AddressRecord.from_rr(rr, zone)
                elif rr.rtype == QTYPE.MX:
                    new_record = models.MXRecord.from_rr(rr, zone)
                elif rr.rtype == QTYPE.NS:
                    new_record = models.NSRecord.from_rr(rr, zone)
                elif rr.rtype == QTYPE.TXT:
                    new_record = models.TXTRecord.from_rr(rr, zone)
                elif rr.rtype == QTYPE.SRV:
                    new_record = models.SRVRecord.from_rr(rr, zone)
                elif rr.rtype == QTYPE.CAA:
                    new_record = models.CAARecord.from_rr(rr, zone)
                elif rr.rtype == QTYPE.NAPTR:
                    new_record = models.NAPTRRecord.from_rr(rr, zone)
                elif rr.rtype == QTYPE.DS:
                    new_record = models.DSRecord.from_rr(rr, zone)
                elif rr.rtype == QTYPE.LOC:
                    new_record = models.LOCRecord.from_rr(rr, zone)
                elif rr.rtype == QTYPE.HINFO:
                    new_record = models.HINFORecord.from_rr(rr, zone)
                elif rr.rtype == QTYPE.RP:
                    new_record = models.RPRecord.from_rr(rr, zone)
                elif rr.rtype == QTYPE.DHCID:
                    new_record = models.DHCIDRecord.from_rr(rr, zone)
                elif rr.rtype == QTYPE.TLSA:
                    new_record = models.TLSARecord.from_rr(rr, zone)
                elif rr.rtype == QTYPE.CNAME:
                    new_record = models.CNAMERecord.from_rr(rr, zone)
                else:
                    continue

                if _try_update():
                    new_record.save()

            # RFC 2136 § 3.4.2.3
            elif rr.rclass == getattr(CLASS, "*"):
                if rr.rtype == QTYPE.ANY:
                    for m in (
                            models.AddressRecord, models.MXRecord, models.NSRecord, models.TXTRecord, models.SRVRecord,
                            models.CAARecord, models.NAPTRRecord, models.DSRecord, models.LOCRecord, models.HINFORecord,
                            models.RPRecord, models.CNAMERecord, models.DHCIDRecord, models.TLSARecord
                    ):
                        for record in self.find_records(m, record_name, zone):
                            record_rr = record.to_rr(rr.rname)
                            if not can_manage(record_rr.rtype, record_name):
                                dns_res.header.rcode = RCODE.NOTAUTH
                                sign_resp()
                                return dns_res
                            record.delete()
                else:
                    records = get_record_models(rr.rtype, record_name)
                    if not can_manage(rr.rtype, record_name):
                        dns_res.header.rcode = RCODE.NOTAUTH
                        sign_resp()
                        return dns_res

                    if records is not None:
                        for record in records:
                            record_rr = record.to_rr(rr.rname)
                            if record_rr.rtype == rr.rtype:
                                record.delete()

            # RFC 2136 § 3.4.2.4
            elif rr.rclass == getattr(CLASS, "None"):
                records = get_record_models(rr.rtype, record_name)
                if records is None:
                    continue

                if not can_manage(rr.rtype, record_name):
                    dns_res.header.rcode = RCODE.NOTAUTH
                    sign_resp()
                    return dns_res

                for record in records:
                    record_rr = record.to_rr(rr.rname)
                    if rr.rdata == record_rr.rdata and record_rr.rtype == rr.rtype:
                        record.delete()

        sign_resp()
        return dns_res

    def AXFRQuery(self, request: dns_pb2.DnsPacket, context):
        try:
            dns_req = self.parse_dns_record(request.msg)
        except dnslib.DNSError:
            traceback.print_exc()
            sys.stdout.flush()
            sys.stderr.flush()
            dns_res = dnslib.DNSRecord()
            dns_res.header.rcode = RCODE.FORMERR
            yield self.make_resp(dns_res)
            return

        try:
            dns_res = self.handle_axfr_query(dns_req)
        except models.DNSError as e:
            print(e.message, flush=True)
            dns_res = dns_req.reply(ra=False)
            dns_res.header.rcode = RCODE.SERVFAIL
            return self.make_resp(dns_res)
        except Exception as e:
            sentry_sdk.capture_exception(e)
            traceback.print_exc()
            sys.stdout.flush()
            sys.stderr.flush()
            dns_res = dns_req.reply(ra=False)
            dns_res.header.rcode = RCODE.SERVFAIL
            yield self.make_resp(dns_res)
            return

        for res in dns_res:
            res = self.make_resp(res)
            yield res

    def UpdateQuery(self, request: dns_pb2.DnsPacket, context):
        try:
            dns_req = self.parse_dns_record(request.msg)
        except dnslib.DNSError:
            traceback.print_exc()
            sys.stdout.flush()
            sys.stderr.flush()
            dns_res = dnslib.DNSRecord()
            dns_res.header.rcode = RCODE.FORMERR
            return self.make_resp(dns_res)

        try:
            dns_res = self.handle_update_query(dns_req)
        except models.DNSError as e:
            print(e.message, flush=True)
            dns_res = dns_req.reply(ra=False)
            dns_res.header.rcode = RCODE.SERVFAIL
            return self.make_resp(dns_res)
        except Exception as e:
            sentry_sdk.capture_exception(e)
            traceback.print_exc()
            sys.stdout.flush()
            sys.stderr.flush()
            dns_res = dns_req.reply(ra=False)
            dns_res.header.rcode = RCODE.SERVFAIL
            return self.make_resp(dns_res)

        res = self.make_resp(dns_res)
        return res

    def parse_dns_record(self, packet: bytes):
        buffer = dnslib.DNSBuffer(packet)
        try:
            header = dnslib.DNSHeader.parse(buffer)
            questions = []
            rr = []
            auth = []
            ar = []
            for i in range(header.q):
                questions.append(dnslib.DNSQuestion.parse(buffer))
            for i in range(header.a):
                rr.append(self.parse_rr(buffer))
            for i in range(header.auth):
                auth.append(self.parse_rr(buffer))
            for i in range(header.ar):
                ar.append(self.parse_rr(buffer))
            return dnslib.DNSRecord(header,questions,rr,auth=auth,ar=ar)
        except dnslib.DNSError:
            raise
        except (BufferError,dnslib.BimapError) as e:
            raise dnslib.DNSError("Error unpacking DNSRecord [offset=%d]: %s" % (buffer.offset,e))

    def parse_rr(self, buffer: dnslib.DNSBuffer):
        try:
            rname = buffer.decode_name()
            rtype, rclass, ttl, rdlength = buffer.unpack("!HHIH")
            if rtype == QTYPE.OPT:
                options = []
                option_buffer = dnslib.Buffer(buffer.get(rdlength))
                while option_buffer.remaining() > 4:
                    code, length = option_buffer.unpack("!HH")
                    data = option_buffer.get(length)
                    options.append(dnslib.EDNSOption(code,data))
                rdata = options
            else:
                if rdlength:
                    rdata = dnslib.RDMAP.get(QTYPE.get(rtype), dnslib.RD).parse(buffer, rdlength)
                else:
                    rdata = dnslib.RD.parse(buffer, rdlength)
            return dnslib.RR(rname,rtype,rclass,ttl,rdata)
        except (BufferError, dnslib.BimapError) as e:
            raise dnslib.DNSError("Error unpacking RR [offset=%d]: %s" % (buffer.offset,e))