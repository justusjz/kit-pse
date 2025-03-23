import os

from pandas.core.groupby import DataFrameGroupBy
from joblib import load, dump
from src.machine_learning.model_enum import ModelEnum
from src.logging.logger import Logger
import pandas as pd
from pandas import DataFrame
from scipy.io import arff
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score
from src.conf import (
    ML_DATASET_PATH,
    FEATURES_NUMBER,
    MODEL_FILE_EXTENSION,
    INTEGRATION_MODEL_PATH,
    TEST_SIZE,
    RANDOM_STATE,
    TRAINED_MODELS_DIR,
)

"""
Main entry in Anomaly Detection. 
Train the models with specified data source and algorithm.
"""


class MLTrainer:
    def train(
        self,
        ml_model_name: str,
        auto_features: bool = False,
        features: list[str] = None,
        dataset_path: str = ML_DATASET_PATH,
    ):
        """
        Train the model with specified data source and algorithm.
        :param auto_features: take best features automatically in script
        :param ml_model_name: name of the ML model to be trained.
        :param features: list of feature names from the datasource
        :param dataset_path: path to dataset
        :return:
        """
        try:
            model = ModelEnum.get(ml_model_name)
        except ValueError:
            raise Exception("Invalid model name")

        if features is None or auto_features:
            features_number = FEATURES_NUMBER
        else:
            features_number = len(features)
        # Set display options to show all columns and rows
        pd.set_option("display.max_columns", None)  # Show all columns

        data, meta = arff.loadarff(dataset_path)

        Logger.debug(str(meta))

        # Convert arff to pandas DF
        df = DataFrame(data)
        Logger.debug(
            "\n".join(
                [
                    "Data Head:",
                    str(df.head()),
                    str(df.info()),
                    str(df.describe().round(2)),
                ]
            )
        )

        # Log null value in attributes
        Logger.debug("\n".join(["Is null stats:", str(df.isnull().sum())]))

        df = self.normalize_data(df)
        if auto_features:
            data = self.analyze_data(df)
            x, y = self.select_features(data, df, features_number)
        else:
            # TODO: Change this hardcoded value
            features = self.convert_features_names(df, features)
            x, y = df[features], df["cat__class_b'normal'"]

        x_train, x_test, y_train, y_test = self.split_data(x, y)

        model = self.train_model(x_train, x_test, y_train, y_test, model.model_class())
        # self.train_model(x_train, x_test, y_train, y_test, SGDClassifier())
        self.save_model(model)

    @staticmethod
    def normalize_data(df: DataFrame) -> DataFrame:
        """
        Preprocessing the data to rescale numerical data into a standard range.
        :param pd.DataFrame df: dataset data
        :return pd.DataFrame scaled dataset data
        """

        # Separate categorical and numerical columns
        numerical_cols = df.select_dtypes(include=["int64", "float64"]).columns
        categorical_cols = df.select_dtypes(include=["object"]).columns

        # Create a ColumnTransformer to preprocess the data. Normalize numerical and categorical columns.
        preprocessor = ColumnTransformer(
            transformers=[
                (
                    "num",
                    StandardScaler(),
                    numerical_cols,
                ),
                (
                    "cat",
                    OneHotEncoder(),
                    categorical_cols,
                ),
            ]
        )

        scaled_data = preprocessor.fit_transform(df)
        df_scaled = pd.DataFrame(
            scaled_data, columns=preprocessor.get_feature_names_out()
        )

        Logger.debug(
            "\n".join(
                [
                    "Normalized data:",
                    str(df_scaled.describe().round(2)),
                    str(df_scaled.info()),
                ]
            )
        )

        return df_scaled

    @staticmethod
    def analyze_data(df: DataFrame) -> DataFrameGroupBy:
        """
        Sort and group data by features difference
        :param DataFrame df: dataset data
        :return DataFrameGroupBy grouped data with the highest difference mean value
        """
        del df["cat__class_b'anomaly'"]
        data = df.groupby("cat__class_b'normal'").mean().T
        data["diff"] = abs(data.iloc[:, 0] - data.iloc[:, 1])
        data = data.sort_values(by=["diff"], ascending=False)
        return data

    @staticmethod
    def select_features(
        data: DataFrameGroupBy, df: DataFrame, feat_number: int
    ) -> tuple[DataFrame, DataFrame]:
        """
        Selection the best representative features
        :param DataFrame df: dataset data
        :param int feat_number: number of features to select
        :return tuple[DataFrame, DataFrame] the list of selected features, positive axis
        """
        features = list(data.index[:feat_number])
        Logger.debug("\n".join(["Best features:", str(data.head(feat_number))]))
        X = df[features]
        # TODO: Change this hardcoded value
        y = df["cat__class_b'normal'"]
        return X, y

    @staticmethod
    def convert_features_names(df: DataFrame, orig_ft: list[str]) -> list[str]:
        converted_features = []
        for col in df.columns:
            for ft in orig_ft:
                if ft in col:
                    converted_features.append(col)

        return converted_features

    @staticmethod
    def split_data(
        x: DataFrame, y: DataFrame
    ) -> tuple[DataFrame, DataFrame, DataFrame, DataFrame]:
        """
        Split data into training and test set
        :param DataFrame x: feature axis
        :param DataFrame y: positive/target axis
        :return tuple[DataFrame, DataFrame, DataFrame, DataFrame, DataFrame] trained and test Frames
        """
        x_train, x_test, y_train, y_test = train_test_split(
            x, y, test_size=TEST_SIZE, random_state=RANDOM_STATE
        )
        return x_train, x_test, y_train, y_test

    @staticmethod
    def train_model(x_train, x_test, y_train, y_test, model):
        """
        Train the model with specified data source.
        :param x_train: features train set
        :param x_test: features test set
        :param y_train: target train set
        :param y_test: target test set
        :param model: ML model
        :return:
        """
        model.fit(x_train, y_train)

        return model

        y_pred = model.predict(x_test)

        """
        Check results
        """
        model_matrix = confusion_matrix(y_test, y_pred, labels=[1, 0])
        model_matrix_df = DataFrame(model_matrix)
        print(model_matrix_df)

        model_accuracy = accuracy_score(y_test, y_pred)
        print(f"Accuracy: {model_accuracy}")

    def save_model(self, model) -> None:
        """
        Saving trained model in directory with algorithm name.
        :param model: trained model
        """
        model_path = self.create_model_path(model)
        dump(model, model_path)
        Logger.info(f"Saved model under {model_path}.")

    @staticmethod
    def create_model_path(model):
        return os.path.join(
            TRAINED_MODELS_DIR, str(model).replace("()", "") + MODEL_FILE_EXTENSION
        )

    @classmethod
    def get_integration_model(cls):
        """
        Get trained model for integration purpose
        :return: machine learning model
        """
        Logger.info(f"load model from: {INTEGRATION_MODEL_PATH}")
        return load(INTEGRATION_MODEL_PATH)

    @staticmethod
    def get_supported_model() -> list[str]:
        """
        Getting list with names of supported ml models
        :return: list with names
        """
        return [model.name for model in ModelEnum]


if __name__ == "__main__":
    MLTrainer().train()
