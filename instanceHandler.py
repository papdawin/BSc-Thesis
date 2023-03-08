import socket
import socketserver
import sys
from threading import Lock

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

class SingletonMeta(type): # Thread-safe
    _instances = {}
    _lock: Lock = Lock()
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
    def forward_message(self, message: str) -> bytes:
        self.connect_server_socket()
        self.socket.sendall(message.encode())
        return self.receive()


class ClientInstanceHandler(socketserver.StreamRequestHandler):
    def __init__(self, address, port, message_size):
        super().__init__(address, port, message_size)
