from enum import Enum
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier


class ModelEnum(Enum):
    LOGISTIC_REGRESSION = ("LogisticRegression", LogisticRegression)
    DECISION_TREE = ("DecisionTree", DecisionTreeClassifier)
    RANDOM_FOREST = ("RandomForest", RandomForestClassifier)
    SGD_Classifier = ("SGDClassifier", SGDClassifier)
    NaiveBayes = ("NaiveBayes", GaussianNB)
    KNN = ("KNN", KNeighborsClassifier)
    MLP = ("MLP", MLPClassifier)
    SVM = ("SVM", SVC)

    def __init__(self, name: str, model_class):
        self._name = name
        self.model_class = model_class

    @classmethod
    def get(cls, name):
        """Retrieve an Enum member by its name."""
        for member in cls:
            if member.name == name:
                return member
        raise ValueError(f"No model found with name: {name}")
