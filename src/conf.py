import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "..", "ml_artifact", "model")
TRAINED_MODELS_DIR = os.path.join(MODELS_DIR, "trained_model")
INTEGRATION_MODEL_PATH = os.path.join(MODELS_DIR, "integration", "MLPClassifier.joblib")
MODEL_FILE_EXTENSION = ".joblib"

# Machine learning dataset
TRAIN_URL = "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain+.txt"  # url for the training set
TEST_URL = "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest+.txt"  # url for the test set
ML_DATASET_PATH = os.path.join(
    BASE_DIR, "..", "ml_artifact", "dataset", "KDDTrain+.arff"
)
TEST_FILE = os.path.join(BASE_DIR, "KDDTest+.txt")
TRAIN_FILE = os.path.join(BASE_DIR, "KDDTrain+.txt")


# Machine learning model training
RANDOM_STATE = 42
TEST_SIZE = 0.3
FEATURES_NUMBER = 11
HIDDEN_LAYER_SIZES = (100, 100, 100)
MAX_ITER = 500

# Preprocessor
PREPROCESSOR_PATH = os.path.join(
    BASE_DIR, "..", "ml_artifact", "preprocessor", "preprocessor.pkl"
)

# network sniffing
SNIFF_INTERFACE = ""
SNIFF_FILTER = ""

# ip spoofing check
RESERVED_IPS = [""]
CHECK_IP_SPOOFING = False

# Logger
CLEAR_LOG = True
LOG_LEVEL = "INFO"

# Slack
SLACK_TOKEN = "xoxb-8483461898407-8491121059078-NOUMpcXk5vvk57XtN8aUt8Nw"
SLACK_CHANNEL_NAME = "ids-kit-pse"
