import ssl

import pika
from pika import connection

from Models.alert_model import Alert


class RabbitMqController:
    def __init__(self):
        self.address = "b-1a801484-0559-42b6-af8b-d16dd2535eef.mq.eu-central-1.amazonaws.com"
        self.user = "myuser"
        self.password = "mypassword1mypassword1"
        self.queue = 'alerts'
        self.credentials = pika.PlainCredentials(self.user, self.password)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.load_verify_locations('cacert.pem')
        self.connection = pika.BlockingConnection(
                        pika.ConnectionParameters(
                            host=self.address,
                            port=5671,
                            credentials=self.credentials,
                            blocked_connection_timeout=300,
                            ssl_options=pika.SSLOptions(self.context))
                        )
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue=self.queue)

    def send_alert(self, alert: Alert):
        """
        Send an alert to RabbitMQ
        :param alert: Alert obj
        :return:
        """
        self.channel.basic_publish(exchange='',
                              routing_key='alerts',
                              body="{"
                                   f"name:{alert.name},"
                                   f"information:{alert.information}"
                                   "}")

    def get_alert(self):
        """
        Get Alert from RabbitMQ
        :return:
        """
        _, _, ret = self.channel.basic_get(queue=self.queue, auto_ack=True)
        alert = None
        if ret is not None:
            ret = ret.decode('ascii')
            ret = ret.split(',')
            name = ret[0].split('name:')[1]
            information = ret[1].split('information:')[1].replace('}',"")
            alert = Alert(name,information)
        return alert

