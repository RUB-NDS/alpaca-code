import select
import time

from utils.logging import _info, _debug


def read_tls_packet(conn):
    record_layer = conn.recv(5)
    read_bytes = required_bytes = int.from_bytes(record_layer[3:5], 'big')
    if not read_bytes:
        raise Exception

    per_recv = 1000
    data = b''
    while read_bytes > 0:
        data += conn.recv(min(per_recv, read_bytes))
        read_bytes = required_bytes - len(data)
    #_debug("mitmproxy.tls ", f"TLS [{len((record_layer + data))}] {record_layer + data}")
    return record_layer + data


def forward_tls_handshake_and_data(addr, client_socket, server_socket):
    while True:
        try:
            ready = select.select([client_socket, server_socket], [], [], 4)
            if not ready[0]:
                break
            for x in ready[0]:
                if x == client_socket:
                    a = read_tls_packet(client_socket)
                    server_socket.send(a)
                else:
                    client_socket.sendall(read_tls_packet(server_socket))
        except:
            _info("mitmproxy.tls ", f"TLS FORWARD ENDED")
            break
