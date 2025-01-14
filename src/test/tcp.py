class TcpConnection:
    def __init__(self):
        self.state = "initial"
        pass


tcp_connections = dict()


# in some tests, we're not performing a TCP handshake, but that
# shouldn't matter, so we can ignore it with this method
def tcp_handshake_ignore(src: str, dst: str, sport: int, dport: int):
    conn = TcpConnection()
    conn.state = "ack"
    tcp_connections[(src, dst, sport, dport)] = conn
