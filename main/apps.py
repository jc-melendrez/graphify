from django.apps import AppConfig
import firebase_admin
from firebase_admin import credentials
from django.conf import settings

class MainConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'main'

    def ready(self):
        # Only initialize if it hasn't been already
        if not firebase_admin._apps:
            cred = credentials.Certificate(str(settings.BASE_DIR / 'serviceAccountKey.json'))
            firebase_admin.initialize_app(cred)
            print("--- FIREBASE INITIALIZED SUCCESSFULLY ---")