from flask import Blueprint, request, jsonify
from models import AdminSettings, db
from datetime import datetime
import bcrypt
from werkzeug.security import generate_password_hash, check_password_hash

# Create a Blueprint
forms_bp = Blueprint('forms', __name__)

@forms_bp.route('/change_login', methods=['GET', 'POST'])
def change_login():
    if request.method == "POST" :
        username = request.form['username'].lower()
        password = request.form['passwd']
        print(username)
        print(password)
        if not username or not password:
            return jsonify(success=False, message="Missing username or password!")
        
        # Query database
        settings = AdminSettings.query.first()
        
        # Hash password for data protection
        hashed_password = hash_password(password)
        
        # Save received details to database
        settings.admin_username = username
        settings.admin_password = hashed_password
        
        db.session.commit()
        print("Login Updated!")
        
        # Process feedback
        return jsonify(success=True, message="Login details updated successfully!")
    
    else:
        return 405
    
@forms_bp.route('/attend_time_update', methods=['GET', 'POST'])
def attend_time_update():
    if request.method == "POST" :
        early_start = request.form['early_start']
        late_start = request.form['late_start']
        late_end = request.form['late_end']
        # print(early_start)
        # print(late_start)
        # print(late_end)
        
        if not all([early_start, late_start, late_end]):
            return jsonify(success=False, message="Missing a key field!")
        
        try:
            # Convert string times to Python time objects
            early_start = datetime.strptime(early_start, "%H:%M").time()
            late_start = datetime.strptime(late_start, "%H:%M").time()
            late_end = datetime.strptime(late_end, "%H:%M").time()
            # print(early_start)
            # print(late_start)
            # print(late_end)

        except ValueError as e:
            print(f"Error parsing time string: {e}")
            raise
        
        # Save received info to database
        settings = AdminSettings.query.first()
        settings.early_arrival_start = early_start
        settings.late_arrival_start = late_start
        settings.late_arrival_end = late_end
        db.session.commit()
        print("Time updated!")
    
        # Process feedback
        return jsonify(success=True, message="Time updated successfully!")
    
    else:
        return """<html>NOT POST METHOD</html>"""
    
@forms_bp.route('/late_fee_update', methods=['GET', 'POST'])
def late_fee_update():
    if request.method == "POST" :
        late_fee = request.form['late-fee']
        print(late_fee)
        if not late_fee:
            return jsonify(success=False, message="Missing a key field!")
        
        # Save received details to database
        settings = AdminSettings.query.first()
        settings.lateness_fine = late_fee
        db.session.commit()
        print("Lateness Fine updated!")
        
        # Process feedback
        return jsonify(success=True, message="Fee updated successfully!")
    
    else:
        return """<html>NOT POST METHOD</html>"""
    
@forms_bp.route('/due_amount_update', methods=['GET', 'POST'])
def due_amount_update():
    if request.method == "POST" :
        due_fee = request.form['due-fee']
        print(due_fee)
        if not due_fee:
            return jsonify(success=False, message="Missing a key field!")
        
        # Save received details to database
        settings = AdminSettings.query.first()
        settings.monthly_due = due_fee
        db.session.commit()
        print("Monthly Due Fee updated!")
        
        # Process feedback
        return jsonify(success=True, message="Due amount updated successfully!")
    
    else:
        return """<html>NOT POST METHOD</html>"""
    
@forms_bp.route('/account_details', methods=['GET', 'POST'])
def account_details():
    if request.method == "POST" :
        acct_num = request.form['acct-num']
        acct_name = request.form['acct-name']
        bank_name = request.form['bank-name']
        print(acct_num)
        print(acct_name)
        print(bank_name)
        if not all([acct_num, acct_name, bank_name]):
            return jsonify(success=False, message="Missing a key field!")
        
        # Save received info to database
        settings = AdminSettings.query.first()
        settings.account_name = acct_name
        settings.account_number = acct_num
        settings.bank_name = bank_name
        db.session.commit()
        print("Account details updated!")
        
        # Process feedback
        return jsonify(success=True, message="Account Details updated successfully!")
    
    else:
        return """<html>NOT POST METHOD</html>"""
    
# Function to hash a password
def hash_password(password):
    # Hash the password with scrypt
    hashed_password = generate_password_hash(password, method="scrypt")
    return hashed_password

# Function to verify a password
def check_password(password, hashed_password):
    return scrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# Function to ensure database record exists
def get_or_create_admin_settings():
    settings = AdminSettings.query.first()
    if not settings:
        settings = AdminSettings()  # Create default settings if none exist
        db.session.add(settings)
        db.session.commit()
    return settings