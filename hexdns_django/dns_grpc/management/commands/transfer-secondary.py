from django.core.management.base import BaseCommand
from dns_grpc import models
import socket
import struct
import dnslib


class Command(BaseCommand):
    help = 'Updates records from primary name servers'

    def handle(self, *args, **options):
        for zone in models.SecondaryDNSZone.objects.all():
            try:
                addrs = socket.getaddrinfo(zone.primary, 53, family=socket.AF_UNSPEC, proto=socket.IPPROTO_TCP)
            except OSError as e:
                zone.error = True
                zone.save()
                print(f"Can't get address of {zone.primary}: {e}")
                continue
            sock = None
            for addr in addrs:
                try:
                    sock = socket.socket(addr[0], addr[1])
                    sock.settimeout(15)
                    sock.connect(addr[4])
                    break
                except OSError as e:
                    print(f"Error connecting to {addr[4]}: {e}")
                    sock = None
                    pass

            if sock is None:
                zone.error = True
                zone.save()
                print(f"Can't connect to {zone.primary}")
                continue

            try:
                soa_query = dnslib.DNSRecord.question(zone.zone_root, "SOA", "IN").pack()
                sock.sendall(struct.pack("!H", len(soa_query)))
                sock.sendall(soa_query)
                response_len_bytes = sock.recv(2)
                response_len = struct.unpack("!H", response_len_bytes)[0]
                response_bytes = sock.recv(response_len)
                soa_response = dnslib.DNSRecord.parse(response_bytes)
                if len(soa_response.rr) != 1:
                    zone.error = True
                    zone.save()
                    print(f"Invalid SOA response from {zone.primary}")
                    sock.close()
                    continue
                serial = soa_response.rr[0].rdata.times[0]
                if serial == zone.serial:
                    zone.error = False
                    zone.save()
                    print(f"Identical serial on {zone.zone_root}, not updating")
                    sock.close()
                    continue
            except (OSError, ValueError, dnslib.DNSError) as e:
                zone.error = True
                zone.save()
                print(f"Failed to sync from {zone.primary}: {e}")
                continue

            try:
                axfr_query = dnslib.DNSRecord.question(zone.zone_root, "AXFR", "IN").pack()
                sock.sendall(struct.pack("!H", len(axfr_query)))
                sock.sendall(axfr_query)
                seen_soa = 0
                rrs = []
                while True:
                    response_len_bytes = sock.recv(2)
                    response_len = struct.unpack("!H", response_len_bytes)[0]
                    response_bytes = sock.recv(response_len)
                    axfr_response = dnslib.DNSRecord.parse(response_bytes)
                    if axfr_response.header.rcode != dnslib.RCODE.NOERROR:
                        zone.error = True
                        zone.save()
                        print(f"Failed to sync from {zone.primary}: {axfr_response.header.rcode}")
                        break
                    for rr in axfr_response.rr:
                        if rr.rtype == dnslib.QTYPE.SOA and rr.rname == zone.zone_root:
                            seen_soa += 1
                        if rr.rclass == dnslib.CLASS.IN and (rr.rtype != dnslib.QTYPE.SOA or seen_soa <= 1):
                            data = dnslib.DNSBuffer()
                            rr.rdata.pack(data)
                            rrs.append(models.SecondaryDNSZoneRecord(
                                zone=zone,
                                record_name=str(rr.rname),
                                ttl=rr.ttl,
                                rtype=int(rr.rtype),
                                rdata=data.data
                            ))
                    if seen_soa >= 2:
                        break
            except (OSError, ValueError, dnslib.DNSError) as e:
                zone.error = True
                zone.save()
                print(f"Failed to sync from {zone.primary}: {e}")
                continue

            if seen_soa == 2:
                zone.secondarydnszonerecord_set.all().delete()
                for rr in rrs:
                    rr.save()
                zone.serial = serial
                zone.error = False
                zone.save()
                print(f"Successfully updated from {zone.primary}")
            else:
                zone.error = True
                zone.save()
                print(f"Invalid number of SOAs from {zone.primary}")

            sock.close()
