import socket
import json
import struct


# Converting to bytes to send.

class Client():
    def __init__(self, host, port, app):
        self.host = host
        self.port = port
        self.message = None
        self.app = app


    def send_payload(self, socket, message):
        print(f"sending message {message}")
        encoded = json.JSONEncoder().encode(message).encode("utf-8")
        byte_stream = struct.pack("<i", len(encoded)) + encoded
        socket.sendall(byte_stream)

    def process_packet(self, sock):
        header = sock.recv(4)
        (body_size,) = struct.unpack("<i", header)
        data = sock.recv(body_size)
        packet = json.loads(data.decode("utf-8"))
        packet = packet[0]
        print(f"Got data {packet}")
        if packet["Type"] == "Message":
            self.app.showmessage(packet["Message"])

    def listen(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.host, self.port))
            while True:
                if self.message is not None:
                    print(f"Client message: sending {self.message}")
                    self.send_payload(sock, self.message)
                    self.message = None
                    self.process_packet(sock)
