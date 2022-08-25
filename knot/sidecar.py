import pika
import libknot.control
import os
import socket
import threading
import dnslib
import struct

libknot.Knot(os.getenv("LIBKNOT_PATH", "/usr/lib/x86_64-linux-gnu/libknot.so.11"))
DNS_IP = "127.0.0.1"
DNS_PORT = 5353


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((DNS_IP, DNS_PORT))
    sock.listen(1)

    parameters = pika.URLParameters(os.getenv("RABBITMQ_RPC_URL"))

    x = threading.Thread(target=notify_thread, args=(sock, parameters), daemon=True)
    x.start()

    connection = pika.BlockingConnection(parameters=parameters)
    channel = connection.channel()

    channel.exchange_declare(exchange='hexdns_primary_reload', exchange_type='fanout', durable=True)
    channel.exchange_declare(exchange='hexdns_primary_resign', exchange_type='fanout', durable=True)
    channel.exchange_declare(exchange='hexdns_secondary_reload', exchange_type='fanout', durable=True)

    queue = channel.queue_declare(queue='', exclusive=True)
    resign_queue = channel.queue_declare(queue='', exclusive=True)
    channel.queue_bind(exchange='hexdns_primary_reload', queue=queue.method.queue)
    channel.queue_bind(exchange='hexdns_primary_resign', queue=resign_queue.method.queue)

    channel.basic_qos(prefetch_count=0)
    channel.basic_consume(queue=queue.method.queue, on_message_callback=callback_reload, auto_ack=False)
    channel.basic_consume(queue=resign_queue.method.queue, on_message_callback=callback_resign, auto_ack=False)

    print("RPC handler now running", flush=True)
    try:
        channel.start_consuming()
    except (KeyboardInterrupt, SystemExit):
        print("Exiting...", flush=True)
        sock.close()


def callback_reload(channel, method, properties, body: bytes):
    zone = body.decode()
    print(f"Reloading {zone}", flush=True)
    ctl = libknot.control.KnotCtl()
    ctl.connect("/rundir/knot.sock")

    try:
        ctl.send_block(cmd="zone-reload", zone=zone)
        ctl.receive_block()
        print(f"Reloaded {zone}", flush=True)
        channel.basic_ack(delivery_tag=method.delivery_tag)
    except libknot.control.KnotCtlError:
        if e.data[libknot.control.KnotCtlDataIdx.ERROR] == "no such zone found":
            pass
        else:
            channel.basic_reject(delivery_tag=method.delivery_tag)
    finally:
        try:
            ctl.send(libknot.control.KnotCtlType.END)
            ctl.close()
        except libknot.control.KnotCtlError:
            pass


def callback_resign(channel, method, properties, body: bytes):
    zone = body.decode()
    print(f"Reloading {zone}", flush=True)
    ctl = libknot.control.KnotCtl()
    ctl.connect("/rundir/knot.sock")

    try:
        ctl.send_block(cmd="zone-sign", zone=zone)
        ctl.receive_block()
        print(f"Reloaded {zone}", flush=True)
        channel.basic_ack(delivery_tag=method.delivery_tag)
    except libknot.control.KnotCtlError as e:
        if e.data[libknot.control.KnotCtlDataIdx.ERROR] == "no such zone found":
            pass
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
