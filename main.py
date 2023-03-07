import socket
from ListBasedAnalyzer import ListBasedAnalyzer
from instanceHandler import ServerInstanceHandler
import json

class WAFProxy:
    def __init__(self, start_address: str, end_address: str, start_port: int, end_port: int, message_size: int):
        print("Initializing WAF...")
        self.init_analyzer()
        self.analyzer = None
        self.start_address = start_address
        self.start_port = start_port
        self.message_size = message_size
        self.server_instance = ServerInstanceHandler(end_address, end_port, message_size)
        self.client_socket = None
        self.server_instance.connect_server_socket()
    def init_analyzer(self):
        with open('config.json', 'r') as f:
            config = json.load(f)
            self.analyzer = ListBasedAnalyzer()
            self.analyzer.set_options(config)
    def connect_client_to_proxy(self) -> socket.socket:
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.client_socket.bind((self.start_address, self.start_port))
        self.client_socket.listen(5)
        client_conn, addr = self.client_socket.accept()
        return client_conn
    def __del__(self):
        self.server_instance.close_socket()
        if self.client_socket:
            self.client_socket.close()
    def handle_client(self, client_conn: socket.socket, message_size: int) -> None:
        # print(f"Handling in {current_thread().name}")
        while True:
            try:
                data_from_client = client_conn.recv(message_size)
                analyzer = ListBasedAnalyzer()
                analyzer.analyze_parts(data_from_client)
            except socket.error:
                break
            data_from_server = self.server_instance.forward_message(data_from_client.decode())
            client_conn.sendall(b''.join(data_from_server))
        client_conn.close()
    def handle_communication(self):
        while True:
            client_conn = self.connect_client_to_proxy()
            client_conn.settimeout(1.0)
            self.handle_client(client_conn, self.message_size)
            # threading.Thread(target=self.handle_client, args=[client_conn, self.message_size]).start()


if __name__ == '__main__':
    p = WAFProxy("", "127.0.0.1", 8080, 80, 2**12)
    p.handle_communication()

