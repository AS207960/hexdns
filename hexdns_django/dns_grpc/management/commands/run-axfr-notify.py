from django.core.management.base import BaseCommand
from django.conf import settings
import pika
import socket
import threading
import struct
import dnslib
import dns_grpc.models
import dns_grpc.proto.axfr_pb2

DNS_IP = "127.0.0.1"
DNS_PORT = 5353


class Command(BaseCommand):
    help = 'Sidecar for the AXFR server to send NOTIFYs to external secondary servers'
    parameters = None

    def handle(self, *args, **options):
        self.parameters = pika.URLParameters(settings.RABBITMQ_RPC_URL)
        connection = pika.BlockingConnection(parameters=self.parameters)
        channel = connection.channel()

        channel.queue_declare(queue='hexdns_axfr_notify', durable=True)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((DNS_IP, DNS_PORT))
        sock.listen(1)
        print("NOTIFY handler now running", flush=True)
        while True:
            conn, addr = sock.accept()
            print(f"connection from {addr}")
            if addr[0] != '127.0.0.1':
                conn.close()
                continue

            x = threading.Thread(target=self.notify_conn, args=(conn,), daemon=True)
            x.start()

    def notify_conn(self, conn):
        while True:
            data_len = conn.recv(2)
            if not data_len:
                break
            data_len, = struct.unpack("!H", data_len)
            data = bytearray()
            while len(data) < data_len:
                data.extend(conn.recv(data_len - len(data)))

            try:
                packet = dnslib.DNSRecord.parse(data)
            except dnslib.DNSError:
                break

            if packet.header.opcode == dnslib.OPCODE.NOTIFY and len(packet.questions) > 0:
                dns_name = packet.questions[0].qname

                response = dnslib.DNSRecord(
                    header=dnslib.DNSHeader(id=packet.header.id, opcode=dnslib.OPCODE.NOTIFY, qr=True, aa=True, rd=False),
                    q=dnslib.DNSQuestion(dns_name, dnslib.QTYPE.SOA)
                )
                response_data = response.pack()
                conn.send(struct.pack("!H", len(response_data)))
                conn.send(response_data)

                zone = dns_grpc.models.DNSZone.objects.filter(
                    zone_root=str(dns_name).rstrip(".")
                ).first()
                if not zone:
                    continue

                targets = list(zone.dnszoneaxfrnotify_set.all())

                if len(targets) == 0:
                    continue

                connection = pika.BlockingConnection(parameters=self.parameters)
                channel = connection.channel()

                for target in targets:
                    msg = dns_grpc.proto.axfr_pb2.Notify(
                        server=target.server,
                        port=target.port,
                        zone=zone.zone_root,
                    )
                    channel.basic_publish(
                        exchange='', routing_key='hexdns_axfr_notify',
                        body=msg.SerializeToString(),
                        properties=pika.BasicProperties(
                            delivery_mode=pika.spec.PERSISTENT_DELIVERY_MODE
                        )
                    )

                channel.close()
                connection.close()

            break
        conn.close()