import time

import pika
import libknot.control
import os
import mmap
import hashlib
import socket
import threading
import dnslib
import struct

libknot.Knot(os.getenv("LIBKNOT_PATH", "/usr/lib/x86_64-linux-gnu/libknot.so.13"))
DNS_IP = "127.0.0.1"
DNS_PORT = 5353


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind((DNS_IP, DNS_PORT))
    sock.listen(1)

    parameters = pika.URLParameters(os.getenv("RABBITMQ_RPC_URL"))

    x = threading.Thread(target=notify_thread, args=(sock, parameters), daemon=True)
    x.start()

    connection = pika.BlockingConnection(parameters=parameters)
    channel = connection.channel()

    channel.exchange_declare(exchange='hexdns_primary_reload', exchange_type='fanout', durable=True)
    channel.exchange_declare(exchange='hexdns_secondary_reload', exchange_type='fanout', durable=True)

    queue = channel.queue_declare(queue='', exclusive=True)
    channel.queue_bind(exchange='hexdns_primary_reload', queue=queue.method.queue)

    channel.basic_qos(prefetch_count=0)
    channel.basic_consume(queue=queue.method.queue, on_message_callback=callback_reload, auto_ack=False)

    print("RPC handler now running", flush=True)
    try:
        channel.start_consuming()
    except (KeyboardInterrupt, SystemExit):
        print("Exiting...", flush=True)
        sock.close()


def direct_file_hash(filename: str) -> str:
    offset = 0
    m = hashlib.sha256()

    if hasattr(os, "O_DIRECT"):
        fd = os.open(filename, os.O_RDONLY | os.O_DIRECT)
    else:
        fd = os.open(filename, os.O_RDONLY)

    file_size = os.lseek(fd, 0, os.SEEK_END)

    try:
        while offset < file_size:
            block_size = min(file_size - offset, 2**20)
            with mmap.mmap(fd, block_size, offset=offset, access=mmap.ACCESS_READ) as mm:
                offset += len(mm)
                if not mm:
                    break
                m.update(mm)
    finally:
        os.close(fd)

    return m.hexdigest()


def callback_reload(channel, method, properties, body: bytes):
    body = body.decode()
    file_hash, zone = body.split(":", 1)

    zone_file_hashes = []

    zone_file = f"/zones/{zone}zone"
    zone_file_signed = f"/zones/{zone}zone.signed"

    if os.path.exists(zone_file):
        zone_file_hashes.append(direct_file_hash(zone_file))
    if os.path.exists(zone_file_signed):
        zone_file_hashes.append(direct_file_hash(zone_file_signed))

    if len(zone_file_hashes) == 0:
        time.sleep(1)
        channel.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
        return

    if all(h != file_hash for h in zone_file_hashes):
        time.sleep(1)
        channel.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
        return

    print(f"Reloading {zone}", flush=True)
    ctl = libknot.control.KnotCtl()
    ctl.connect("/rundir/knot.sock")

    try:
        ctl.send_block(cmd="zone-reload", zone=zone)
        ctl.receive_block()
        print(f"Reloaded {zone}", flush=True)
        channel.basic_ack(delivery_tag=method.delivery_tag)
    except libknot.control.KnotCtlError as e:
        if e.data and e.data[libknot.control.KnotCtlDataIdx.ERROR] == "no such zone found":
            channel.basic_ack(delivery_tag=method.delivery_tag)
        else:
            channel.basic_reject(delivery_tag=method.delivery_tag)
    finally:
        try:
            ctl.send(libknot.control.KnotCtlType.END)
            ctl.close()
        except libknot.control.KnotCtlError:
            pass


def notify_thread(sock, parameters):
    print("NOTIFY handler now running", flush=True)
    while True:
        conn, addr = sock.accept()
        print(f"connection from {addr}")
        if addr[0] != '127.0.0.1':
            conn.close()
            continue

        x = threading.Thread(target=notify_conn, args=(conn, parameters), daemon=True)
        x.start()


def notify_conn(conn, parameters):
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

            connection = pika.BlockingConnection(parameters=parameters)
            channel = connection.channel()
            channel.basic_publish(exchange='hexdns_secondary_reload', routing_key='', body=str(dns_name).encode())
            channel.close()
            connection.close()

            response = dnslib.DNSRecord(
                header=dnslib.DNSHeader(id=packet.header.id, opcode=dnslib.OPCODE.NOTIFY, qr=True, aa=True, rd=False),
                q=dnslib.DNSQuestion(dns_name, dnslib.QTYPE.SOA)
            )
            response_data = response.pack()
            conn.send(struct.pack("!H", len(response_data)))
            conn.send(response_data)

        break
    conn.close()


if __name__ == "__main__":
    main()
