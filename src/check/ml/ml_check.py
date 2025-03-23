import pandas as pd
from time import time
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6

from src.machine_learning.trainer import MLTrainer
from src.logging.logger import Logger
from src.check.check import Check


class MLCheck(Check):
    def __init__(self):
        super().__init__()

    @classmethod
    def check(cls, packet):
        connection_df = MLCheck.__create_df(packet)

        # prediction with the loaded model
        prediction = MLTrainer.get_integration_model().predict(connection_df)
        Logger.debug(
            f"Prediction for connection (protocol_type: {connection_df['protocol_type'][0]}, flag: {connection_df['flag'][0]}, service: {connection_df['service'][0]}, duration: {connection_df['duration'][0]}, src_bytes: {connection_df['src_bytes'][0]}, dst_bytes: {connection_df['dst_bytes'][0]}) => {prediction[0]}"
        )
        if prediction[0] != "normal":
            Logger.log_prediction(connection_df, prediction[0])

    @classmethod
    def __create_df(cls, packet) -> pd.DataFrame:
        from src.check.tcp.connection import tcp_connections, TcpConnection, service_map

        if IP in packet:
            src, dst = packet[IP].src, packet[IP].dst
        else:
            src, dst = packet[IPv6].src, packet[IPv6].dst
        sport, dport = packet[TCP].sport, packet[TCP].dport
        # unique key for this TCP connection
        key = (min(src, dst), max(src, dst), min(sport, dport), max(sport, dport))
        if key in tcp_connections:
            connection = tcp_connections[key]
        else:
            connection = TcpConnection(src, dport)
            tcp_connections[key] = connection
        protocol_type = "tcp"
        duration = int(time() - connection.begin)
        # connection was terminated correctly or reset
        # TODO: duration in seconds?
        duration = int(time() - connection.begin)
        # TODO: figure out what the other flags mean
        if "R" in packet[TCP].flags:
            flag = "REJ"
        else:
            flag = "SF"
        if connection.port in service_map:
            service = service_map[connection.port]
        else:
            service = "private"

        src_bytes = connection.src_bytes
        dst_bytes = connection.dst_bytes

        connection_info = {
            "protocol_type": [protocol_type],
            "flag": [flag],
            "service": [service if "https" != service else "http"],
            "duration": [duration],
            "src_bytes": [src_bytes],
            "dst_bytes": [dst_bytes],
        }

        return pd.DataFrame.from_dict(connection_info)
