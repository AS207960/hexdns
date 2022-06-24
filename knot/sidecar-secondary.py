import pika
import os
import socket
import dnslib
import struct

TCP_IP = '127.0.0.1'
TCP_PORT = 53


def main():
    parameters = pika.URLParameters(os.getenv("RABBITMQ_RPC_URL"))
    connection = pika.BlockingConnection(parameters=parameters)
    channel = connection.channel()

    channel.exchange_declare(exchange='hexdns_secondary_reload', exchange_type='fanout', durable=True)

    queue = channel.queue_declare(queue='', exclusive=True)
    channel.queue_bind(exchange='hexdns_secondary_reload', queue=queue.method.queue)

    channel.basic_qos(prefetch_count=0)
    channel.basic_consume(queue=queue.method.queue, on_message_callback=callback, auto_ack=False)

    print("RPC handler now running", flush=True)
    try:
        channel.start_consuming()
    except (KeyboardInterrupt, SystemExit):
        print("Exiting...", flush=True)


def callback(channel, method, properties, body: bytes):
    zone = body.decode()
    print(f"Notifying {zone}", flush=True)

    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((TCP_IP, TCP_PORT))

        request = dnslib.DNSRecord(
            header=dnslib.DNSHeader(opcode=dnslib.OPCODE.NOTIFY, qr=False, aa=True, rd=False),
            q=dnslib.DNSQuestion(zone, dnslib.QTYPE.SOA)
        )
        request_data = request.pack()
        conn.send(struct.pack("!H", len(request_data)))
        conn.send(request_data)
        conn.close()

        print(f"Notified {zone}", flush=True)
        channel.basic_ack(delivery_tag=method.delivery_tag)
    except OSError:
        channel.basic_reject(delivery_tag=method.delivery_tag)


if __name__ == "__main__":
    main()
