from django.core.management.base import BaseCommand
from django.conf import settings
from django.db import transaction
from django.contrib.auth import get_user_model
import pika
import decimal
from dns_grpc import models, views
import dns_grpc.proto.billing_pb2


class Command(BaseCommand):
    help = 'Runs the RPC client on rabbitmq'

    def handle(self, *args, **options):
        parameters = pika.URLParameters(settings.RABBITMQ_RPC_URL)
        connection = pika.BlockingConnection(parameters=parameters)
        channel = connection.channel()

        channel.queue_declare(queue='hexdns_sub_billing_notif', durable=True)

        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(
            queue='hexdns_sub_billing_notif', on_message_callback=self.sub_callback, auto_ack=False)

        print("RPC handler now running")
        try:
            channel.start_consuming()
        except (KeyboardInterrupt, SystemExit):
            print("Exiting...")
            return

    def sub_callback(self, channel, method, properties, body):
        msg = dns_grpc.proto.billing_pb2.SubscriptionNotification()
        msg.ParseFromString(body)
        print(msg)

        account = models.Account.objects.filter(
            subscription_id=msg.subscription_id).first()  # type: models.DomainRegistrationOrder
        if not account:
            channel.basic_ack(delivery_tag=method.delivery_tag)
            return

        if msg.state in (
                dns_grpc.proto.billing_pb2.SubscriptionNotification.PENDING,
                dns_grpc.proto.billing_pb2.SubscriptionNotification.CANCELLED
        ):
            account.subscription_active = False
            account.save()
        elif msg.state in (
                dns_grpc.proto.billing_pb2.SubscriptionNotification.ACTIVE,
                dns_grpc.proto.billing_pb2.SubscriptionNotification.PAST_DUE
        ):
            account.subscription_active = True
            account.save()

        channel.basic_ack(delivery_tag=method.delivery_tag)
