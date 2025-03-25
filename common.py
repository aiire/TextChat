import json
import socket

DEFAULT_HOST = 'localhost' # The default host is the host's device
DEFAULT_PORT = 5000

class User:
    def __init__(self, username: str, client_socket: socket.socket, address: tuple[str, int]):
        self.nickname = username
        self.socket = client_socket
        self.address = address
        self.is_authenticated = False

    def __repr__(self):
        return f"User(username={self.nickname}, address={self.address}, authenticated={self.is_authenticated})"

def encode_packet(data):
    return json.dumps(data).encode()


