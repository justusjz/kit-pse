from joblib import load
from src.check.ml.training import train_model
from src.logging.logger import Logger
import os
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "nsl_model_pipeline.joblib")


def load_model():
    if os.path.exists(MODEL_PATH):
        print("load model from: ", MODEL_PATH)
        return load(MODEL_PATH)
    else:
        print("Model not found, start new training...")
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

    print(
        f"Prediction for connection (protocol_type: {protocol_type}, flag: {flag}, service: {service}, duration: {duration}, src_bytes: {src_bytes}, dst_bytes: {dst_bytes}) => {prediction[0]}"
    )
    if prediction[0] != "normal":
        Logger.log_prediction(
            protocol_type, flag, service, duration, src_bytes, dst_bytes, prediction[0]
        )

    return prediction[0]


# debug
sample_normal = {
    "protocol_type": "tcp",
    "flag": "SF",
    "service": "http",
    "duration": 0,
    "src_bytes": 181,
    "dst_bytes": 5450,
}

result = ml_check_connection(
    protocol_type=sample_normal["protocol_type"],
    flag=sample_normal["flag"],
    service=sample_normal["service"],
    duration=sample_normal["duration"],
    src_bytes=sample_normal["src_bytes"],
    dst_bytes=sample_normal["dst_bytes"],
)
print("Result sample_normal connection:", result)
