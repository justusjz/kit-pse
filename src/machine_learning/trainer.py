import os

from pandas.core.groupby import DataFrameGroupBy

from src.logging.logger import Logger
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from pandas import DataFrame
from scipy.io import arff
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score

SOURCE_PATH = os.getenv("SOURCE_PATH")
FEATURES_NUMBER = int(os.getenv("FEATURES_NUMBER"))

"""
Main entry in Anomaly Detection. 
Train the models with specified data source and algorithm.
"""


class MLTrainer:
    def train(
        self,
        data_source_path: str = SOURCE_PATH,
        features_number: int = FEATURES_NUMBER,
    ):
        # Set display options to show all columns and rows
        pd.set_option("display.max_columns", None)  # Show all columns

        data, meta = arff.loadarff(data_source_path)

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
        data = self.analyze_data(df)
        x, y = self.select_features(data, df, features_number)
        x_train, x_test, y_train, y_test = self.split_data(x, y)

        self.train_model(x_train, x_test, y_train, y_test, LogisticRegression())
        self.train_model(x_train, x_test, y_train, y_test, SGDClassifier())

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
            scaled_data,
            columns=numerical_cols.tolist()
            + preprocessor.named_transformers_["cat"]
            .get_feature_names_out(categorical_cols)
            .tolist(),
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
        del df["class_b'anomaly'"]
        data = df.groupby("class_b'normal'").mean().T
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
        y = df["class_b'normal'"]
        return X, y

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
            x, y, test_size=0.3, random_state=42
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

        y_pred = model.predict(x_test)

        """
        Check results
        """
        model_matrix = confusion_matrix(y_test, y_pred, labels=[1, 0])
        model_matrix_df = DataFrame(model_matrix)
        print(model_matrix_df)

        model_accuracy = accuracy_score(y_test, y_pred)
        print(f"Accuracy: {model_accuracy}")


if __name__ == "__main__":
    MLTrainer().train()
