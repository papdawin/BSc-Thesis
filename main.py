import socket
from threading import Thread
from Analysis import *
from Proxy import *
from Data import config
import json

class WAFProxy:
    def __init__(self, start_address: str, end_address: str, start_port: int, end_port: int, message_size: int):
        self.start_address = start_address
        self.start_port = start_port
        self.message_size = message_size
        self.server_instance = ServerInstanceHandler(end_address, end_port, message_size)
    def client_proxy_connection(self, client_connection: ClientInstanceHandler) -> None:
        client_connection.forward_comm(self.server_instance)
    def handle_communication(self):
        while True:
            try:
                client_connection = ClientInstanceHandler(self.start_address, self.start_port, self.message_size)
                Thread(target=self.client_proxy_connection, args=[client_connection]).start()
            except InvalidIPException:
                pass


if __name__ == '__main__':
    p = WAFProxy(
        start_address=config['base']['accept_from'],
        end_address=config['base']['local_IP'],
        start_port=int(config['base']['in_port']),
        end_port=int(config['base']['out_port']),
        message_size=2**12
    )
    p.handle_communication()

