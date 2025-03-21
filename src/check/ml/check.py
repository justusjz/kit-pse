from joblib import load
from src.check.ml.training import train_model
from src.logging.logger import Logger
from src.conf import MODEL_PATH
import os
import pandas as pd


def load_model():
    if os.path.exists(MODEL_PATH):
        Logger.info(f"load model from: {MODEL_PATH}")
        return load(MODEL_PATH)
    else:
        Logger.info("Model not found, start new training...")
        # train automatically a new model (Warning: this can take some time)
        train_model(MODEL_PATH)
        # load the model again after the training
        if os.path.exists(MODEL_PATH):
            return load(MODEL_PATH)
        else:
            raise FileNotFoundError("No model found after the training.")


model = load_model()


def ml_check_connection(
    protocol_type: str,
    flag: str,
    service: str,
    duration: int,
    src_bytes: int,
    dst_bytes: int,
):
    """
    Predict a given connection.
    (Duration is in seconds)
    """
    connection = pd.DataFrame(
        {
            "protocol_type": [protocol_type],
            "flag": [flag],
            "service": [service],
            "duration": [duration],
            "src_bytes": [src_bytes],
            "dst_bytes": [dst_bytes],
        }
    )

    # prediction with the loaded model
    prediction = model.predict(connection)
    Logger.debug(
        f"Prediction for connection (protocol_type: {protocol_type}, flag: {flag}, service: {service}, duration: {duration}, src_bytes: {src_bytes}, dst_bytes: {dst_bytes}) => {prediction[0]}"
    )
    if prediction[0] != "normal":
        Logger.log_prediction(
            protocol_type, flag, service, duration, src_bytes, dst_bytes, prediction[0]
        )

    return prediction[0]
