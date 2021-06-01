import time
from django.apps import AppConfig
from django.conf import settings
import pika
import pika.exceptions
import threading


class DnsGrpcConfig(AppConfig):
    name = "dns_grpc"


class _InnerPikaClient:
    internal_lock = threading.Lock()

    def __init__(self):
        self.setup_connection()
        thread = threading.Thread(target=self.__hb_thread)
        thread.setDaemon(True)
        thread.start()

    def setup_connection(self):
        pika_parameters = pika.URLParameters(settings.RABBITMQ_RPC_URL)
        self.__connection = pika.BlockingConnection(parameters=pika_parameters)
        self.channel = self.__connection.channel()

    def __hb_thread(self):
        while True:
            try:
                with self.internal_lock:
                    self.__connection.process_data_events()
                time.sleep(0.1)
            except pika.exceptions.ChannelClosed:
                continue


class PikaClient:
    def __init__(self):
        self.storage = threading.local()

    def __get_client(self):
        existing_client = getattr(self.storage, "client", None)
        if existing_client:
            return existing_client
        new_client = _InnerPikaClient()
        self.storage.client = new_client
        return new_client

    def get_channel(self, cb):
        client = self.__get_client()
        try:
            with client.internal_lock:
                cb(client.channel)
        except pika.exceptions.ChannelClosed:
            with client.internal_lock:
                client.setup_connection()
                cb(client.channel)
