from flask import Flask,session,request
from flask_session import Session
import socket
from datetime import timedelta
from blueprints import register_blueprints
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from models import *
from initializeDatabase import initialize_admin_settings
from flask import make_response
from routes import routes
from flask_cors import CORS

# Setup Flask app
app = Flask(__name__)
CORS(app)
hostname = socket.gethostname()
IpAddr = socket.gethostbyname(hostname)
# print(IpAddr)

# Configure application
app.secret_key = 'f5ebc8036f89c065bef342e1f9e1c7fca6782c546325071d878d98499d1c16df'
app.permanent_session_lifetime = timedelta(minutes=5) # Set session timeout
app.config['SESSION_COOKIE_SECURE'] = False  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['WTF_CSRF_ENABLED'] = False # For cross-device access

# Initialize the database and migration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///attendance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # To disable unnecessary tracking

db.init_app(app)    # Initialize SQLAlchemy with the Flask app

# Initialize the Migrate instance
migrate = Migrate(app, db)

with app.app_context():
    db.create_all()  # Create tables if they don't exist
    initialize_admin_settings()  # Initialize AdminSettings

# Register Blueprints
register_blueprints(app)
app.register_blueprint(routes)

# Session refresh for admin
@app.before_request
def refresh_session():
    if request.path.startswith('/admin') and 'admin_logged_in' in session:
        # print(f"{session['admin_logged_in']}: Refreshing admin")
        session.modified = True  # Refresh session timeout



# ---------------- RUN APPLICATION ---------------- #

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False, threaded=True)
