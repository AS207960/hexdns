import pika
import libknot.control
import os

libknot.Knot(os.getenv("LIBKNOT_PATH", "/usr/lib/x86_64-linux-gnu/libknot.so.11"))


def main():
    parameters = pika.URLParameters(os.getenv("RABBITMQ_RPC_URL"))
    connection = pika.BlockingConnection(parameters=parameters)
    channel = connection.channel()

    channel.exchange_declare(exchange='hexdns_primary_reload', exchange_type='fanout', durable=True)

    queue = channel.queue_declare(queue='', exclusive=True)
    channel.queue_bind(exchange='hexdns_primary_reload', queue=queue.method.queue)

    channel.basic_qos(prefetch_count=0)
    channel.basic_consume(queue=queue.method.queue, on_message_callback=callback, auto_ack=False)

    print("RPC handler now running", flush=True)
    try:
        channel.start_consuming()
    except (KeyboardInterrupt, SystemExit):
        print("Exiting...", flush=True)


def callback(channel, method, properties, body: bytes):
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
        channel.basic_reject(delivery_tag=method.delivery_tag)
    finally:
        ctl.send(libknot.control.KnotCtlType.END)
        ctl.close()


if __name__ == "__main__":
    main()
