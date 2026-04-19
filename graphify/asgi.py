import os
import firebase_admin
from firebase_admin import credentials
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'graphify.settings')

# This check ensures it ONLY runs in the main process, not the reloader
if not firebase_admin._apps and os.environ.get('RUN_MAIN') != 'true':
    try:
        cred = credentials.Certificate("serviceAccountKey.json")
        firebase_admin.initialize_app(cred)
        print("--- FIREBASE ADMIN INITIALIZED (SINGLE INSTANCE) ---")
    except Exception as e:
        print(f"Firebase Init Error: {e}")

application = get_asgi_application()