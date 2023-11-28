from django.core.management.base import BaseCommand
from django.conf import settings
from django.utils import timezone
import pika
from dns_grpc import models, tasks
import dns_grpc.proto.billing_pb2


class Command(BaseCommand):
    help = 'Runs the RPC client on rabbitmq'

    def handle(self, *args, **options):
        parameters = pika.URLParameters(settings.RABBITMQ_RPC_URL)
        connection = pika.BlockingConnection(parameters=parameters)
        channel = connection.channel()

        channel.queue_declare(queue='hexdns_sub_billing_notif', durable=True)
        channel.queue_declare(queue='hexdns_disable_dnssec', durable=True)
        channel.queue_declare(queue='hexdns_enable_dnssec', durable=True)

        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(queue='hexdns_sub_billing_notif', on_message_callback=self.sub_callback, auto_ack=False)
        channel.basic_consume(
            queue='hexdns_disable_dnssec', on_message_callback=self.dnssec_disable_callback, auto_ack=False
        )
        channel.basic_consume(
            queue='hexdns_enable_dnssec', on_message_callback=self.dnssec_enable_callback, auto_ack=False
        )

        print("RPC handler now running")
        try:
            channel.start_consuming()
        except (KeyboardInterrupt, SystemExit):
            print("Exiting...")
            return

    @staticmethod
    def sub_callback(channel, method, properties, body):
        msg = dns_grpc.proto.billing_pb2.SubscriptionNotification()
        msg.ParseFromString(body)

        account = models.Account.objects.filter(
            subscription_id=msg.subscription_id).first()  # type: models.DomainRegistrationOrder
        if not account:
            channel.basic_ack(delivery_tag=method.delivery_tag)
            return

        if msg.state == dns_grpc.proto.billing_pb2.SUB_PENDING:
            account.subscription_active = False
            account.save()
        elif msg.state == dns_grpc.proto.billing_pb2.SUB_CANCELLED:
            account.subscription_id = None
            account.subscription_active = False
            account.save()
        elif msg.state in (
                dns_grpc.proto.billing_pb2.SUB_ACTIVE,
                dns_grpc.proto.billing_pb2.SUB_PAST_DUE
        ):
            account.subscription_active = True
            account.save()

        tasks.update_catalog.delay()

        channel.basic_ack(delivery_tag=method.delivery_tag)

    @staticmethod
    def dnssec_disable_callback(channel, method, properties, body):
        domain_name = body.decode("utf-8")

        zone = models.DNSZone.objects.filter(zone_root__iexact=domain_name).first()
        if not zone:
            channel.basic_ack(delivery_tag=method.delivery_tag)
            return

        zone.cds_disable = True
        zone.last_modified = timezone.now()
        zone.save()
        tasks.update_fzone.delay(zone.id)

        channel.basic_ack(delivery_tag=method.delivery_tag)

    @staticmethod
    def dnssec_enable_callback(channel, method, properties, body):
        domain_name = body.decode("utf-8")

        zone = models.DNSZone.objects.filter(zone_root__iexact=domain_name).first()
        if not zone:
            channel.basic_ack(delivery_tag=method.delivery_tag)
            return

        zone.cds_disable = False
        zone.last_modified = timezone.now()
        zone.save()
        tasks.update_fzone.delay(zone.id)

        channel.basic_ack(delivery_tag=method.delivery_tag)
