from dotenv import load_dotenv
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# API Keys
VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# Flask Server Settings
HOST = "127.0.0.1"
PORT = 5000

# Flask secret key
SECRET_KEY = os.getenv("SECRET_KEY", "your-default-fallback-secret")
