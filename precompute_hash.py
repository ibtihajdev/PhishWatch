import hashlib
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'Project_Webapp', 'django Integration', 'django Integration', 'django_admin', 'api', 'XGBoostClassifier.pickle.dat')

with open(MODEL_PATH, "rb") as f:
    file_hash = hashlib.sha256(f.read()).hexdigest()
    print(f"EXPECTED_MODEL_HASH='{file_hash}'")
