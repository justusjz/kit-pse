import pandas as pd
import os
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, MinMaxScaler
from sklearn.pipeline import Pipeline
from sklearn.neural_network import MLPClassifier
from joblib import dump
from src.utils.download import download_file
from src.conf import (
    TEST_URL,
    TRAIN_URL,
    TRAIN_FILE,
    TEST_FILE,
    MAX_ITER,
    HIDDEN_LAYER_SIZES,
    MODEL_PATH,
    RANDOM_STATE,
)

# download nsl training data
download_file(TRAIN_URL, TRAIN_FILE)
download_file(TEST_URL, TEST_FILE)


def train_model(path: str):
    """Train a new model with preprocessor (pipe) and save it under
    the given path as a joblib file"""
    # read nsl training data
    train_data = pd.read_csv(TRAIN_FILE, header=None)
    test_data = pd.read_csv(TEST_FILE, header=None)
    train_data = pd.concat(
        [train_data, test_data], ignore_index=True
    )  # use also test data for the final model

    # define all columns
    columns = [
        "duration",
        "protocol_type",
        "service",
        "flag",
        "src_bytes",
        "dst_bytes",
        "land",
        "wrong_fragment",
        "urgent",
        "hot",
        "num_failed_logins",
        "logged_in",
        "num_compromised",
        "root_shell",
        "su_attempted",
        "num_root",
        "num_file_creations",
        "num_shells",
        "num_access_files",
        "num_outbound_cmds",
        "is_host_login",
        "is_guest_login",
        "count",
        "srv_count",
        "serror_rate",
        "srv_serror_rate",
        "rerror_rate",
        "srv_rerror_rate",
        "same_srv_rate",
        "diff_srv_rate",
        "srv_diff_host_rate",
        "dst_host_count",
        "dst_host_srv_count",
        "dst_host_same_srv_rate",
        "dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate",
        "dst_host_serror_rate",
        "dst_host_srv_serror_rate",
        "dst_host_rerror_rate",
        "dst_host_srv_rerror_rate",
        "outcome",
        "level",
    ]

    train_data.columns = columns

    # used features and label for the modell
    used_features = [
        "protocol_type",
        "flag",
        "service",
        "duration",
        "src_bytes",
        "dst_bytes",
        "outcome",
    ]
    train_data = train_data[used_features]

    # split features and label
    X_train = train_data.drop(["outcome"], axis=1)
    y_train = train_data["outcome"]

    # define categorical and numerical features
    categorical_features = ["protocol_type", "service", "flag"]
    numerical_features = ["duration", "src_bytes", "dst_bytes"]

    # convert numerical features and handle missing values
    X_train[numerical_features] = X_train[numerical_features].apply(
        pd.to_numeric, errors="coerce"
    )
    X_train.fillna(0, inplace=True)

    # create preprocessor: OneHotEncoder for categorical and MinMaxScaler for numerical features
    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features),
            ("num", MinMaxScaler(), numerical_features),
        ]
    )

    # create pipeline: preprocessing + classification (MLPClassifier)
    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            (
                "classifier",
                MLPClassifier(
                    hidden_layer_sizes=HIDDEN_LAYER_SIZES,
                    max_iter=MAX_ITER,
                    random_state=RANDOM_STATE,
                ),
            ),
        ]
    )

    # train model
    pipeline.fit(X_train, y_train)
    print("Finished model training.")

    # save model (Joblib-File)
    dump(pipeline, path)
    print(f"Saved model under {path}.")


if __name__ == "__main__":
    train_model(MODEL_PATH)
