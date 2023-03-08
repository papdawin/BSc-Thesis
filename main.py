import socket
from listBasedAnalyzer import ListBasedAnalyzer
from instanceHandler import ServerInstanceHandler
import json

class WAFProxy:
    def __init__(self, start_address: str, end_address: str, start_port: int, end_port: int, message_size: int, config_location: str = 'config.json'):
        self.analyzer = None
        self.init_analyzer(config_location)
        self.start_address = start_address
        self.start_port = start_port
        self.message_size = message_size
        self.server_instance = ServerInstanceHandler(end_address, end_port, message_size)
        self.server_instance.connect_server_socket()
        # print("[Initialized WAF]")
    def init_analyzer(self, config_location):
        with open(config_location, 'r') as f:
            config = json.load(f)
            self.analyzer = ListBasedAnalyzer()
            self.analyzer.set_options(config)
            print(f"Loaded config from: [{config_location}]")
    def __del__(self):
        self.server_instance.close_socket()
        if self.client_socket:
            self.client_socket.close()
    def connect_client_to_proxy(self) -> socket.socket:
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.client_socket.bind((self.start_address, self.start_port))
        self.client_socket.listen(5)
        client_conn, addr = self.client_socket.accept()
        return client_conn
    def handle_client(self, client_conn: socket.socket, message_size: int) -> None:
        # print(f"Handling in {current_thread().name}")
        while True:
            try:
                data_from_client = client_conn.recv(message_size)
                # analyzer = ListBasedAnalyzer()
                # analyzer.analyze_parts(data_from_client)
            except socket.error:
                break
            data_from_server = self.server_instance.forward_message(data_from_client.decode())
            client_conn.sendall(data_from_server)
        client_conn.close()
    def handle_communication(self):
        while True:
            client_conn = self.connect_client_to_proxy()
            client_conn.settimeout(1.0)
            self.handle_client(client_conn, self.message_size)
            # threading.Thread(target=self.handle_client, args=[client_conn, self.message_size]).start()

#
# from threading import Lock, Thread
#
#
# class SingletonMeta(type):
#     _instances = {}
#     _lock: Lock = Lock()
#     def __call__(cls, *args, **kwargs):
#         with cls._lock:
#             if cls not in cls._instances:
#                 instance = super().__call__(*args, **kwargs)
#                 cls._instances[cls] = instance
#         return cls._instances[cls]
# class Singleton(metaclass=SingletonMeta):
#     value: str = None
#     def __init__(self, value: str) -> None:
#         self.value = value
# def test_singleton(value: str) -> None:
#     singleton = Singleton(value)
#     print(singleton.value)

if __name__ == '__main__':
    p = WAFProxy("", "127.0.0.1", 8080, 3000, 2**12)
    p.handle_communication()
    # print("If you see the same value, then singleton was reused (yay!)\n"
    #       "If you see different values, "
    #       "then 2 singletons were created (booo!!)\n\n"
    #       "RESULT:\n")
    #
    # process1 = Thread(target=test_singleton, args=("FOO",))
    # process2 = Thread(target=test_singleton, args=("BAR",))
    # process1.start()
    # process2.start()