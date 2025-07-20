import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_secret_key'
    SCAN_RESULTS_DIR = 'reports'
    ALLOWED_TARGETS = ['example.com', '192.168.1.0/24']  # Разрешённые цели