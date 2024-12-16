from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, time
from sqlalchemy import Date

db = SQLAlchemy()


class Users(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    middle_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50), nullable=False)
    state_code = db.Column(db.String(10), unique=True, nullable=False)
    registration_date = db.Column(db.Date, nullable=False, default=datetime.now().date)

    # Define the relationship with AttendanceLog. Cascade deletes Attendance Logs 
    # automatically once a user is deleted
    attendance_logs = db.relationship('AttendanceLog', back_populates='user', lazy=True, cascade="all, delete-orphan")

class AttendanceLog(db.Model):
    __tablename__ = 'attendance_log'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False) # Foreign Key linking to Users table
    sign_in_time = db.Column(db.Time, nullable=False, default=datetime.now)
    # ip_address = db.Column(db.String(50), nullable=False)
    meeting_date = db.Column(db.Date, nullable=False, index=True)
    
    # Relationship with Users
    user = db.relationship('Users', back_populates='attendance_logs')

class LateLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_date = db.Column(db.Date, nullable=False, default=datetime.now().date) # Take only date
    state_code = db.Column(db.String(10), nullable=False, index=True)
    request_type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), nullable=False)
    
class AdminSettings(db.Model):
    __tablename__ = 'settings'
    
    id = db.Column(db.Integer, primary_key=True)
    early_arrival_start = db.Column(db.Time, nullable=True)
    late_arrival_start = db.Column(db.Time, nullable=True)
    late_arrival_end = db.Column(db.Time, nullable=True)
    lateness_fine =db.Column(db.Float, nullable=True)
    monthly_due = db.Column(db.Float, nullable=True)
    account_name = db.Column(db.String(100), nullable=True)
    account_number = db.Column(db.String(20), nullable=True)
    bank_name = db.Column(db.String(100), nullable=True)
    admin_username = db.Column(db.String(50), nullable=True)
    admin_password = db.Column(db.String(255), nullable=True)
    
    
    






