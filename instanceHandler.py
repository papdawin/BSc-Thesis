import socket
import socketserver
import sys

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

class ServerInstanceHandler(InstanceHandler):
    def __init__(self, address, port, message_size):
        super().__init__(address, port, message_size)
    def connect_server_socket(self):
        self.close_socket()
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.address, self.port))
            self.socket.settimeout(0.1)
        except socket.error:
            sys.exit("Target not listening, terminating process...")
    def receive(self) -> list:
        response = []
        while True:
            try:
                data_part = self.socket.recv(self.message_size)
                response.append(data_part)
                if not data_part:
                    break
            except socket.error:
                break
            print(list(response))
        return response
    def forward_message(self, message: str) -> list:
        self.connect_server_socket()
        self.socket.sendall(message.encode())
        return self.receive()


class ClientInstanceHandler(socketserver.StreamRequestHandler):
    def __init__(self, address, port, message_size):
        super().__init__(address, port, message_size)
