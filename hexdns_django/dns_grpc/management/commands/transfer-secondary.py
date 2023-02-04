from django.core.management.base import BaseCommand
from dns_grpc import models, tasks
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
                print(f"Can't get address of {zone.primary}: {e}")
                zone.error = True
                zone.error_message = f"Can't get address of {zone.primary}"
                zone.save()
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
                print(f"Can't connect to {zone.primary}")
                zone.error = True
                zone.error_message = f"Can't connect to {zone.primary}"
                zone.save()
                continue

            try:
                soa_query = dnslib.DNSRecord.question(zone.zone_root, "SOA", "IN").pack()
                sock.sendall(struct.pack("!H", len(soa_query)))
                sock.sendall(soa_query)
                response_len_bytes = sock.recv(2)
                try:
                    response_len = struct.unpack("!H", response_len_bytes)[0]
                except struct.error:
                    print(f"Invalid SOA response from {zone.primary}")
                response_bytes = sock.recv(response_len)
                soa_response = dnslib.DNSRecord.parse(response_bytes)
                if len(soa_response.rr) != 1:
                    print(f"Invalid SOA response from {zone.primary}")
                    zone.error = True
                    zone.error_message = f"Invalid SOA response from {zone.primary}"
                    zone.save()
                    sock.close()
                    continue
                serial = soa_response.rr[0].rdata.times[0]
                if serial == zone.serial:
                    print(f"Identical serial on {zone.zone_root}, not updating")
                    zone.error = False
                    zone.save()
                    sock.close()
                    continue
            except (OSError, ValueError, dnslib.DNSError) as e:
                print(f"Failed to sync from {zone.primary}: {e}")
                zone.error = True
                zone.save()
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
                        print(f"Failed to sync from {zone.primary}: {dnslib.RCODE.get(axfr_response.header.rcode)}")
                        zone.error = True
                        zone.error_message = f"Failed to sync from {zone.primary}: " \
                                             f"got response {dnslib.RCODE.get(axfr_response.header.rcode)}"
                        zone.save()
                        continue
                    for rr in axfr_response.rr:
                        if rr.rtype == dnslib.QTYPE.SOA and rr.rname == zone.zone_root:
                            seen_soa += 1
                        if rr.rclass == dnslib.CLASS.IN and (rr.rtype != dnslib.QTYPE.SOA or seen_soa <= 1):
                            rrs.append(models.SecondaryDNSZoneRecord(
                                zone=zone,
                                record_text=rr.toZone(),
                            ))
                    if seen_soa >= 2:
                        break
            except (OSError, ValueError, dnslib.DNSError, struct.error) as e:
                print(f"Failed to sync from {zone.primary}: {e}")
                zone.error = True
                zone.save()
                continue

            if seen_soa == 2:
                zone.secondarydnszonerecord_set.all().delete()
                for rr in rrs:
                    rr.save()
                zone.serial = serial
                zone.error = False
                zone.error_message = None
                zone.save()
                tasks.update_szone.delay(zone.id)
                print(f"Successfully updated from {zone.primary}")
            else:
                print(f"Invalid number of SOAs from {zone.primary}")
                zone.error = True
                zone.error_message = f"Invalid number of SOAs received from {zone.primary}"
                zone.save()

            sock.close()
