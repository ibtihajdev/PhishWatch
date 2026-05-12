import os
import hashlib
from django.apps import AppConfig
from django.core.exceptions import ImproperlyConfigured

def check_model_integrity(model_path):
    expected_hash = os.environ.get('EXPECTED_MODEL_HASH', '4a6860863eb47187c8bcb757ef4abdca2eea3574ad4a9e5501ecb90497abcda9')
    
    if not os.path.exists(model_path):
        raise ImproperlyConfigured(f"CRITICAL: ML Model not found at {model_path}")

    with open(model_path, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    if file_hash != expected_hash:
        raise ImproperlyConfigured(
            "CRITICAL SECURITY ALERT: The ML model hash does not match the expected signature. "
            "The model file may have been tampered with. Server startup aborted."
        )

class ApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api'

    def ready(self):
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        MODEL_PATH = os.path.join(BASE_DIR, 'XGBoostClassifier.pickle.dat')
        check_model_integrity(MODEL_PATH)
