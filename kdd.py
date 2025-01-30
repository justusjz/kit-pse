import matplotlib
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns


from sklearn.datasets import fetch_kddcup99
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import classification_report
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score

matplotlib.use("MacOSX")  # change matplot backend

X, y = fetch_kddcup99(
    percent10=True,
    download_if_missing=True,
    data_home="kdd_data",
    as_frame=True,
    return_X_y=True,
)

categorical_features = ["protocol_type", "service", "flag"]
numerical_features = [col for col in X.columns if col not in categorical_features]
# convert numerical columns
X[numerical_features] = X[numerical_features].apply(pd.to_numeric, errors="coerce")
# fill out missing values, replace nan with 0
X.fillna(0, inplace=True)

preprocessor = ColumnTransformer(
    transformers=[
        ("cat", OneHotEncoder(), categorical_features),
        ("num", MinMaxScaler(), numerical_features),
    ]
)

X_processed = preprocessor.fit_transform(X)

y = y.str.decode("utf-8")  # convert labels from bytes to strings

print("data shape X:", X.shape)
print("data shape X_processed:", X_processed.shape)
print("target shape:", y.shape)

X_train, X_test, y_train, y_test = train_test_split(
    X_processed, y, test_size=0.2, random_state=42
)

gnb_clf = GaussianNB()
gnb_clf.fit(X_train, y_train)
gnb_pred = gnb_clf.predict(X_test)
gnb_acc = accuracy_score(y_test, gnb_pred)
print("gnb Accuracy:", gnb_acc)

mlpc = MLPClassifier()
mlpc.fit(X_train, y_train)
mlpc_pred = mlpc.predict(X_test)
mlpc_acc = accuracy_score(y_test, mlpc_pred)
print("mlpc Accuracy:", mlpc_acc)
mlpc_report = classification_report(y_test, mlpc_pred, zero_division=0)
print("MLPC Report:\n", mlpc_report)


knn_clf = KNeighborsClassifier()
knn_clf.fit(X_train, y_train)
knn_pred = knn_clf.predict(X_test)
knn_acc = accuracy_score(y_test, knn_pred)
print("knn Accuracy:", knn_acc)


# visualize report as heatmap
report = classification_report(y_test, mlpc_pred, output_dict=True, zero_division=0)
df_report = pd.DataFrame(report).transpose()

sns.heatmap(
    df_report.iloc[:-1, :3],  # Ignores the “support” column
    annot=True,
    cmap="Greens",
    fmt=".2f",
)
plt.title("Classification Report (MLP)")
plt.show()
