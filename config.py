import os

class Config:
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'f5ebc8036f89c065bef342e1f9e1c7fca6782c546325071d878d98499d1c16df')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///attendance.db')  # SQLite for local development
