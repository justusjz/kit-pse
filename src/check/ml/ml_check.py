import pandas as pd
from time import time
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6

from src.machine_learning.trainer import MLTrainer
from src.logging.logger import Logger
from src.check.check import Check


class MLCheck:
    @classmethod
    def check(
        cls,
        proto: str,
        flag: str,
        service: str,
        duration: float,
        src_bytes: int,
        dst_bytes: int,
        land: int,
        urgent: int,
    ):
        connection_df = pd.DataFrame(
            {
                "protocol_type": [proto],
                "flag": [flag],
                "service": [service],
                "duration": [duration],
                "src_bytes": [src_bytes],
                "dst_bytes": [dst_bytes],
            }
        )
        # prediction with the loaded model
        prediction = MLTrainer.get_integration_model().predict(connection_df)
        Logger.debug(
            f"Prediction for connection (protocol_type: {connection_df['protocol_type'][0]}, flag: {connection_df['flag'][0]}, service: {connection_df['service'][0]}, duration: {connection_df['duration'][0]}, src_bytes: {connection_df['src_bytes'][0]}, dst_bytes: {connection_df['dst_bytes'][0]}) => {prediction[0]}"
        )
        if prediction[0] != "normal":
            Logger.log_prediction(connection_df, prediction[0])
