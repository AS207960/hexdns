from .proto import dns_pb2
from .proto import dns_pb2_grpc
from . import models
import dnslib
import ipaddress
import typing
import traceback
from dnslib import QTYPE, RCODE, OPCODE
from dnslib.label import DNSLabel
from django.db.models.functions import Length


def grpc_hook(server):
    dns_pb2_grpc.add_DnsServiceServicer_to_server(DnsServiceServicer(), server)


class DnsServiceServicer(dns_pb2_grpc.DnsServiceServicer):
    IP4_APRA = DNSLabel("in-addr.arpa.")
    IP6_APRA = DNSLabel("ip6.arpa.")
    IP_NETWORK = typing.Union[ipaddress.IPv6Network, ipaddress.IPv4Network]
    IP_ADDR = typing.Union[ipaddress.IPv6Address, ipaddress.IPv4Address]

    def is_rdns(self, qname: DNSLabel) -> bool:
        if qname.matchSuffix(self.IP4_APRA):
            return True
        elif qname.matchSuffix(self.IP6_APRA):
            return True
        else:
            return False

    def find_zone(
        self, qname: DNSLabel
    ) -> (typing.Optional[models.DNSZone], typing.Optional[DNSLabel]):
        zones = models.DNSZone.objects.order_by(Length("zone_root").desc())
        for zone in zones:
            zone_root = DNSLabel(zone.zone_root)
            if qname.matchSuffix(zone_root):
                record_name = qname.stripSuffix(zone_root)
                if len(record_name.label) == 0:
                    record_name = DNSLabel("@")
                return zone, record_name
        return None, None

    def find_rzone(
        self, qname: DNSLabel
    ) -> (typing.Optional[models.ReverseDNSZone], typing.Optional[IP_ADDR]):
        is_ip6_zone = qname.matchSuffix(self.IP6_APRA)
        qname = (
            qname.stripSuffix(self.IP6_APRA)
            if is_ip6_zone
            else qname.stripSuffix(self.IP4_APRA)
        )

        if is_ip6_zone:
            parts = list(reversed(list(map(lambda n: n.decode(), qname.label))))
            addr = ":".join(
                ["".join(parts[n : n + 4]) for n in range(0, len(parts), 4)]
            )
        else:
            addr = ".".join(reversed(list(map(lambda n: n.decode(), qname.label))))
        try:
            addr = ipaddress.ip_address(addr)
        except ValueError:
            return None, None

        zones = models.ReverseDNSZone.objects.order_by("-zone_root_prefix")
        for zone in zones:
            try:
                zone_network = ipaddress.ip_network(
                    (zone.zone_root_address, zone.zone_root_prefix)
                )
            except ValueError:
                continue

            if addr in zone_network:
                return zone, addr, zone_network

        return None, None

    def network_to_apra(self, network: IP_NETWORK) -> DNSLabel:
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

    def find_records(
        self,
        model: typing.Type[models.DNSZoneRecord],
        rname: DNSLabel,
        zone: models.DNSZone,
    ):
        search_name = ".".join(map(lambda n: n.decode(), rname.label))
        return model.objects.filter(record_name=search_name, zone=zone)

    def find_reverse_records(
        self,
        model: typing.Type[models.ReverseDNSZoneRecord],
        addr: IP_ADDR,
        zone: models.ReverseDNSZone,
    ):
        return model.objects.filter(record_address=str(addr), zone=zone)

    def make_resp(self, res: dnslib.DNSRecord) -> dns_pb2.DnsPacket:
        return dns_pb2.DnsPacket(msg=bytes(res.pack()))

    def lookup_referral(
        self, dns_res: dnslib.DNSRecord, record_name: DNSLabel, zone: models.DNSZone,
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
                self.lookup_additional_addr(dns_res, ns)
        if not ns_found:
            dns_res.header.rcode = RCODE.NXDOMAIN

    def lookup_cname(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.DNSZone,
        query_name: DNSLabel,
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
                func(dns_res, record_name, zone, cname_record.alias)
        else:
            self.lookup_referral(dns_res, record_name, zone)

    def lookup_addr(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.DNSZone,
        query_name: DNSLabel,
    ):
        records = self.find_records(models.AddressRecord, record_name, zone)
        for record in records:
            address = ipaddress.ip_address(record.address)
            if type(address) == ipaddress.IPv4Address and dns_res.q.qtype == QTYPE.A:
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
                dns_res.add_answer(
                    dnslib.RR(
                        query_name,
                        QTYPE.AAAA,
                        rdata=dnslib.AAAA(address.compressed),
                        ttl=record.ttl,
                    )
                )
        else:
            self.lookup_cname(dns_res, record_name, zone, query_name, self.lookup_addr)

    def lookup_additional_addr(
        self, dns_res: dnslib.DNSRecord, query_name: DNSLabel,
    ):
        zone, record_name = self.find_zone(query_name)
        records = self.find_records(models.AddressRecord, record_name, zone)
        for record in records:
            address = ipaddress.ip_address(record.address)
            if type(address) == ipaddress.IPv4Address:
                dns_res.add_ar(
                    dnslib.RR(
                        query_name,
                        QTYPE.A,
                        rdata=dnslib.A(address.compressed),
                        ttl=record.ttl,
                    )
                )
            elif type(address) == ipaddress.IPv6Address:
                dns_res.add_ar(
                    dnslib.RR(
                        query_name,
                        QTYPE.AAAA,
                        rdata=dnslib.AAAA(address.compressed),
                        ttl=record.ttl,
                    )
                )

    def lookup_mx(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.DNSZone,
        query_name: DNSLabel,
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
        else:
            self.lookup_cname(dns_res, record_name, zone, query_name, self.lookup_mx)

    def lookup_ns(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.DNSZone,
        query_name: DNSLabel,
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
        else:
            self.lookup_cname(dns_res, record_name, zone, query_name, self.lookup_ns)

    def lookup_txt(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.DNSZone,
        query_name: DNSLabel,
    ):
        records = self.find_records(models.TXTRecord, record_name, zone)
        for record in records:
            dns_res.add_answer(
                dnslib.RR(
                    query_name,
                    QTYPE.TXT,
                    rdata=dnslib.TXT(record.data.encode()),
                    ttl=record.ttl,
                )
            )
        else:
            self.lookup_cname(dns_res, record_name, zone, query_name, self.lookup_txt)

    def lookup_srv(
        self,
        dns_res: dnslib.DNSRecord,
        record_name: DNSLabel,
        zone: models.DNSZone,
        query_name: DNSLabel,
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
        else:
            self.lookup_cname(dns_res, record_name, zone, query_name, self.lookup_txt)

    def lookup_ptr(
        self,
        dns_res: dnslib.DNSRecord,
        addr: IP_ADDR,
        zone: models.ReverseDNSZone,
        query_name: DNSLabel,
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
        else:
            address_records = models.AddressRecord.objects.filter(
                address=str(addr), auto_reverse=True
            )
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

    def handle_query(self, dns_req: dnslib.DNSRecord):
        dns_res = dns_req.reply()

        if dns_req.header.opcode != OPCODE.QUERY:
            dns_res.header.rcode = RCODE.REFUSED
            return dns_res

        query_name = dns_req.q.qname
        is_rdns = self.is_rdns(query_name)

        if is_rdns:
            zone, record_name, zone_network = self.find_rzone(query_name)
        else:
            zone, record_name = self.find_zone(query_name)
        if not zone:
            dns_res.header.rcode = RCODE.NXDOMAIN
            return dns_res

        if not is_rdns:
            if dns_req.q.qtype == QTYPE.SOA:
                pass
            elif dns_req.q.qtype in [QTYPE.A, QTYPE.AAAA]:
                self.lookup_addr(dns_res, record_name, zone, query_name)
            elif dns_req.q.qtype == QTYPE.MX:
                self.lookup_mx(dns_res, record_name, zone, query_name)
            elif dns_req.q.qtype == QTYPE.NS:
                self.lookup_ns(dns_res, record_name, zone, query_name)
            elif dns_req.q.qtype == QTYPE.TXT:
                self.lookup_txt(dns_res, record_name, zone, query_name)
            elif dns_req.q.qtype == QTYPE.SRV:
                self.lookup_srv(dns_res, record_name, zone, query_name)
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
            dns_res.add_auth(
                dnslib.RR(
                    zone.zone_root,
                    QTYPE.SOA,
                    rdata=dnslib.SOA(
                        "ns1.as207960.net",
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
        else:
            if dns_req.q.qtype == QTYPE.SOA:
                pass
            elif dns_req.q.qtype == QTYPE.PTR:
                self.lookup_ptr(dns_res, record_name, zone, query_name)
            network = self.network_to_apra(zone_network)
            dns_res.add_auth(
                dnslib.RR(
                    network,
                    QTYPE.SOA,
                    rdata=dnslib.SOA(
                        "ns1.as207960.net",
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

        return dns_res

    def Query(self, request: dns_pb2.DnsPacket, context):
        try:
            dns_req = dnslib.DNSRecord.parse(request.msg)
        except dnslib.DNSError:
            dns_res = dnslib.DNSRecord()
            dns_res.header.rcode = RCODE.FORMERR
            return self.make_resp(dns_res)

        try:
            dns_res = self.handle_query(dns_req)
        except:
            traceback.print_exc()
            dns_res = dns_req.reply()
            dns_res.header.rcode = RCODE.SERVFAIL

        return self.make_resp(dns_res)
