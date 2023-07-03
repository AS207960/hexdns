import dnslib
import grpc
import ipaddress
import dns_grpc.grpc
from django.utils import timezone
from .proto import axfr_pb2, axfr_pb2_grpc
from . import models


def grpc_hook(server):
    axfr_pb2_grpc.add_AXFRServiceServicer_to_server(AXFRServiceServicer(), server)


class AXFRServiceServicer(axfr_pb2_grpc.AXFRServiceServicer):
    def GetTSIGSecret(self, request: axfr_pb2.TSIGRequest, context):
        key_name = dnslib.DNSLabel(request.key_name)
        zone, label = dns_grpc.grpc.DnsServiceServicer.find_zone(key_name)

        if not zone:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details('Unknown zone')
            return

        tsig_key = models.DNSZoneAXFRSecrets.objects\
            .filter(id=str(label).strip(".")).first()

        if not tsig_key:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details('Unknown key')
            return

        tsig_key.last_used = timezone.now()
        tsig_key.save()

        return axfr_pb2.TSIGSecret(
            secret=tsig_key.secret
        )

    def CheckIPACL(self, request: axfr_pb2.IPACLRequest, context):
        zone_name = dnslib.DNSLabel(request.zone_name)
        zone, _ = dns_grpc.grpc.DnsServiceServicer.find_zone(zone_name)

        if not zone:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details('Unknown zone')
            return

        if request.WhichOneof("ip_addr") == "v4":
            ip = ipaddress.IPv4Address(request.v4)
        elif request.WhichOneof("ip_addr") == "v6":
            ip = ipaddress.IPv6Address(request.v6)
        else:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details('Invalid IP')
            return

        for acl in zone.dnszoneaxfripacl_set.all():
            if ip in acl.network:
                acl.last_used = timezone.now()
                acl.save()

                return axfr_pb2.IPACLResponse(
                    allowed=True
                )

        return axfr_pb2.IPACLResponse(
            allowed=False
        )
