from Analysis import *
import socket
import sys
import threading

class InstanceHandler:
    def __init__(self, address, port, message_size):
        self.address = address
        self.port = port
        self.message_size = message_size
        self.socket = None
    def close_socket(self):
        # check if socket exists
        if self.socket:
            self.socket.close()

class SingletonMeta(type):
    _instances = {}
    _lock = threading.Lock()
    def __call__(cls, *args, **kwargs):
        with cls._lock:
            if cls not in cls._instances:
                instance = super().__call__(*args, **kwargs)
                cls._instances[cls] = instance
        return cls._instances[cls]

class ServerInstanceHandler(InstanceHandler, metaclass=SingletonMeta):
    def __init__(self, address, port, message_size):
        super().__init__(address, port, message_size)
    def connect_server_socket(self):
        self.close_socket()
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.address, self.port))
            self.socket.settimeout(3)
        except socket.error:
            sys.exit("Target not listening, terminating process...")
    def receive(self) -> bytes:
        response = self.socket.recv(self.message_size)
        content_length = ((response.partition(b"Content-Length:")[2]).partition(b"\r\n")[0]).decode()
        if len(content_length) > 0:  # Van CL header
            content_length = int(content_length)
            while True:
                if content_length == len(response.partition(b"\r\n\r\n")[2]):
                    break
                response += self.socket.recv(self.message_size)
            return response
        else:  # Nincs CL header
            while True:
                try:
                    data_part = self.socket.recv(self.message_size)
                    response += data_part
                    if not data_part:
                        break
                except socket.error:
                    break
            return response
    def forward_message(self, message: str, start_port) -> bytes:
        self.connect_server_socket()
        if not start_port == 80:
            message.replace(str(start_port), str(self.port))
        else:
            host = (message.partition("Host: ")[2]).partition("\r\n")[0]
            message = message.replace(host, f"{host}:{self.port}")
        self.socket.sendall(message.encode())
        return self.receive()

class ClientInstanceHandler(InstanceHandler):
    def __init__(self, address, port, message_size):
        super().__init__(address, port, message_size)
        self.client_conn = None
        self.connect_client_socket()
    def connect_client_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.address, self.port))
        self.socket.listen(1)
        self.client_conn, self.address = self.socket.accept()
        if not is_IP_safe(self.address):
            self.client_conn.close()
            raise InvalidIPException()
        self.client_conn.settimeout(3)
    def forward_comm(self, server_instance):
        while True:
            try:
                data_from_client = self.client_conn.recv(self.message_size)
                is_safe = analyze_request(data_from_client, self.address)
                if not is_safe:
                    break  # hangs up, sends no response
            except socket.error:
                break
            data_from_server = server_instance.forward_message(data_from_client.decode(), self.port)
            self.client_conn.sendall(data_from_server)
        self.client_conn.close()
        self.close_socket()
