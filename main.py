import socket
import threading
from threading import Thread
from listBasedAnalyzer import ListBasedAnalyzer
from instanceHandler import ServerInstanceHandler, ClientInstanceHandler
import json

class WAFProxy:
    def __init__(self, start_address: str, end_address: str, start_port: int, end_port: int, message_size: int, config_location: str = 'config.json'):
        self.analyzer = None
        self.init_analyzer(config_location)
        self.start_address = start_address
        self.start_port = start_port
        self.message_size = message_size
        self.server_instance = ServerInstanceHandler(end_address, end_port, message_size)
    def init_analyzer(self, config_location):
        with open(config_location, 'r') as f:
            config = json.load(f)
            self.analyzer = ListBasedAnalyzer()
            self.analyzer.set_options(config)
            self.analyzer.set_ruleset()
    def client_proxy_connection(self, client_connection: ClientInstanceHandler) -> None:
        client_connection.forward_comm(self.server_instance, self.analyzer)
    def handle_communication(self):
        while True:
            client_connection = ClientInstanceHandler(self.start_address,self.start_port, self.message_size)
            Thread(target=self.client_proxy_connection, args=[client_connection]).start()


if __name__ == '__main__':
    p = WAFProxy("", "127.0.0.1", 80, 3000, 2**12, 'config.json')
    p.handle_communication()