import os

class Config:
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'yibambe')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///attendance.db')  # SQLite for local development
