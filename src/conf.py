# config.py
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_FILENAME = "nsl_model_pipeline.joblib"
MODEL_PATH = os.path.join(BASE_DIR, "nsl_model_pipeline.joblib")

# data urls and local path
TRAIN_URL = "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain+.txt"  # url for the training set
TEST_URL = "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest+.txt"  # url for the test set
TRAIN_FILE = os.path.join(BASE_DIR, "KDDTrain+.txt")
TEST_FILE = os.path.join(BASE_DIR, "KDDTest+.txt")

# model configuration
HIDDEN_LAYER_SIZES = (100, 100, 100)
MAX_ITER = 500
RANDOM_STATE = 42

# network sniffing config
SNIFF_INTERFACE = ""
SNIFF_FILTER = ""

# ip spoofing check conf
RESERVED_IPS = [""]
CHECK_IP_SPOOFING = False
