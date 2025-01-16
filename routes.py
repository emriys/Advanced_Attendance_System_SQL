from flask import Flask,request,Response,render_template,session,redirect,url_for,jsonify,send_file,flash,Blueprint
from flask_session import Session
import pandas as pd
from datetime import datetime,time,timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
from models import *
from blueprints.forms import *
import csv
from io import BytesIO
from fpdf import FPDF
from flask import make_response
import xlsxwriter
import tempfile
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.units import inch
from sqlalchemy import or_
from werkzeug.security import check_password_hash
from functools import wraps

# Create a blueprint
routes = Blueprint('routes', __name__)

# Initialize admin authentication
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if ('admin_logged_in' not in session) or (not session['admin_logged_in']):
            flash("You must be logged in as an admin to access this page.", "warning")
            return redirect(url_for('routes.admin'))
        return f(*args, **kwargs)
    return decorated_function

# ---------------- ROUTES ---------------- #

@routes.route('/')
@routes.route('/home')
def index():
    return render_template("index.html")

@routes.route('/history')
def history():
    return render_template ("error.html")
    return render_template ("history.html")
    # return ("successful")

@routes.route('/register', methods=['GET','POST'])
def register():
    form = MemberRegisterForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(state_code=form.state_code.data.upper()).first()
        if user :
            return jsonify({'success':False,"message":'User already exists'})
        else:
            user_data = {
                'first_name':form.first_name.data.capitalize().strip(),
                'middle_name':form.middle_name.data.capitalize().strip(),
                'last_name':form.last_name.data.upper().strip(),
                'gender':form.gender.data.capitalize().strip(),
                'local_gov':form.local_gov_area.data.capitalize().strip(),
                'state_code':form.state_code.data.upper().strip()
            }
            print(f"'{user_data['first_name']}'")
            print(f"'{user_data['middle_name']}'")
            print(f"'{user_data['last_name']}'")
            print(user_data['gender'])
            print(user_data['local_gov'])
            print(user_data['state_code'])
        
            confirm = check_user_reg_exists(user_data=user_data)
            if confirm :
                print("New User Added 2.")
                return jsonify({'success':True,"message":'Registration successful'})
            else :
                return jsonify({'success':False,"message":'Server Error: Could not add user'})
        
    return render_template('register.html', title='Register', form=form)

@routes.route('/signin', methods=['GET', 'POST'])
def signin():
    # Sign in clicked 
    # colllect details 
    # check if user registered 
    form = SigninForm()
    if request.method == "POST" and form.validate_on_submit():
        # Define attendance time ranges
        settings = AdminSettings.query.first()
        early_start = settings.early_arrival_start
        late_start = settings.late_arrival_start
        late_end = settings.late_arrival_end
        print(early_start)
        print(late_start)
        print(late_end)
        
        last_name = form.last_name.data.upper() # Last name
        statecode = form.state_code.data.upper()
        print(last_name)
        print(statecode)
        
        confirm_reg = check_user_reg_exists(statecode=statecode, last_name=last_name)
        if not confirm_reg :
            return jsonify({'success':False,"message":'Not A Registered Member'})
        else :
            # Check if user attendance is registered already
            attendanceStatus = check_user_attendance_exists(statecode)

            if attendanceStatus != "":
                return jsonify({'success':False,"message":attendanceStatus})
                
            else:
                # If late, handle late sign-in
                current_time = datetime.now().time()
                
                # if late_start <= current_time <= late_end:
                # if late_end <= current_time:
                # if current_time <= late_start:
                if late_start <= current_time:
                    amount = settings.lateness_fine
                    
                    # Check if user already in late list
                    late_status = check_latefile(statecode)
                    if not late_status:
                        new_late_log = LateLog(
                            transaction_date=datetime.now().date(),
                            state_code=statecode,
                            request_type="Late Sign-In",
                            amount=amount,
                            status="Pending"
                        )
                        db.session.add(new_late_log)
                        db.session.commit()
                    return payment(statecode)
                
                # elif late_end <= current_time:
                elif early_start <= current_time < late_start:
                    # Regular sign-in (early sign-in)
                    confirm_attendance = record_attendance(confirm_reg)
        
                    if confirm_attendance:
                        return render_template("thankyouregister.html")
                    else:
                        return """<h1>Server Error!</h1> <h4><p>Failed to log attendance</p></h4>""", 500
                
                else:
                    regErrorMsg = "Sign-in time elapsed or not yet reached!"
                    return jsonify({'success':False,"message":regErrorMsg})
           
    return render_template("signin.html", form=form)

@routes.route('/late/signin', methods=['GET', 'POST'])
def late_reg():
    if request.method == 'POST':
        statecode = request.form['statecode']
        
        # Check user in database
        user = Users.query.filter_by(state_code=statecode).first()
        
        # Check if user attendance is registered already
        attendanceStatus = check_user_attendance_exists(statecode)
        if attendanceStatus != "":
            return jsonify({'success':False,"message":attendanceStatus})
        
        # Add late attendnace to database
        if user:
            confirm_attendance = record_attendance(user)
        
        if confirm_attendance:
            # Remove the user from the LateLog database
            pop_latecomer(statecode)
            return render_template("thankyouregister.html")
        else:
            return """<h1>Server Error!</h1> <h4><p>Failed to log attendance</p></h4>""", 500

@routes.route('/admin', methods=['GET', 'POST'])
def admin():
    if ('admin_logged_in' in session) :
        return redirect(url_for('routes.admindash'))
    
    if request.method == "POST":
        username = request.form['adminusr'].strip().lower()
        password = request.form['adminpwd']
        
        # Fetch the stored admin credentials
        admin_settings = AdminSettings.query.first()
        
        if not admin_settings:
            return jsonify({'error': 'Server Error.'}), 500
        
        # Verify the username and password
        if username == admin_settings.admin_username and check_password_hash(admin_settings.admin_password, password):
            session.permanent = True
            session['admin_logged_in'] = True
            return jsonify({"success":True, "message":"Login successful!"}), 200  # Response with success status
        else:
            return jsonify({"success":False, "message":"Invalid credentials!"}), 200  # Response with failure status

    return render_template('adminlogin.html')

@routes.route('/admin/dashboard', methods=['GET', 'POST'])
@admin_required
def admindash():
    if 'admin_logged_in' not in session:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for('routes.admin'))

    # Check if the request is an AJAX request by inspecting headers
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    if is_ajax:
        # Query the late logs for the latecomer requests and respond to the AJAX request
        logs = LateLog.query.all()
        pending_requests = [
            {
                'transaction_date': log.transaction_date.strftime('%Y-%m-%d'),
                'state_code': log.state_code,
                'request_type': log.request_type,
                'amount': log.amount,
                'status': log.status
            }
            for log in logs
        ]
        # print(pending_requests)

        #filter_by(status="Pending").all()
        return jsonify(pending_requests)
    
    # If the request is not an AJAX request
    # Get all pending latecomer requests from the LateLog table
    pending_requests = LateLog.query.all()
    #filter_by(status="Pending").all()

    return render_template('admindashboard.html', pending_requests=pending_requests)

@routes.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    if 'admin_logged_in' not in session:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for('routes.admin'))
    
    # Get Admin Settings from the database and update webpage
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    if is_ajax:
        settings = getSettings()
        print(settings["meeting_day"])
        # print(settings)
        return jsonify(settings)

    return render_template ("adminsettings.html")

@routes.route('/admin/attendance_logs', methods=['GET', 'POST'])
@admin_required
def attendance_logs():
    if 'admin_logged_in' not in session:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for('routes.admin'))
    
    # Check if the request is an AJAX request by inspecting headers
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    if is_ajax:
        # Get the date from the query parameter (default to today's date if not provided)
        meeting_date = request.args.get('start_date')
        meeting_date2 = request.args.get('end_date')
        print("Received Range: ")
        print(meeting_date)
        print(meeting_date2)
        # print(meeting_date)
        
        # If no date is provided, default to today's date
        if not all([meeting_date, meeting_date2]):
            meeting_date = meeting_date2 = datetime.now().date()
            # Query the attendance logs for the given date and respond to the AJAX request
            attendance_request = get_attendance_data(meeting_date)
            # print(meeting_date)
        
        if meeting_date == meeting_date2:
            attendance_request = attendance_request = get_attendance_data(meeting_date)
        
        # If a date range is provided, get data across the range
        if meeting_date != meeting_date2:
            attendance_request = collect_attendance_data_for_range(meeting_date, meeting_date2)
        
        
        # print(attendance_request)
        if len(attendance_request) <= 0:
            return jsonify({"success": False, "message": "No attendance records found for this date range."}), 200

        return jsonify(attendance_request)

    # If the request is not an AJAX request, return attendance for the day
    meeting_date = datetime.now().date()
    attendance_today = get_attendance_data(meeting_date)
    # print(attendance_today)

    return render_template('view_attendance.html', attendance_data=attendance_today)

@routes.route('/logout')
@admin_required
def logout():
    session.pop('admin_logged_in', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('routes.admin'))

@routes.route('/admin/clear_latelog', methods=['GET', 'POST'])
@admin_required
def clearLatelog():
    if 'admin_logged_in' not in session:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for('routes.admin'))
    
    # action = request.args.get('statecodeSelect')
    if request.method == "POST":
        statecode = request.form["statecode"]
        print(statecode)
        if statecode == "All":
            try:
                db.session.query(LateLog).delete()  # Deletes all rows
                db.session.commit()  # Commit the transaction
                print("All LateLog entries have been cleared.")
                return jsonify({"message":"All LateLog entries cleared."}), 200
            except Exception as e:
                db.session.rollback()  # Roll back in case of an error
                print(f"An error occurred: {e}")
        
        elif statecode :
            try:
                # Clear specific state code entries
                deleted_rows = LateLog.query.filter_by(state_code=statecode).delete()
                db.session.commit()

                if deleted_rows > 0:
                    return jsonify({"message": f"LateLogs for state code {statecode} cleared successfully."}), 200
                else:
                    return jsonify({"message": f"No records found for state code {statecode}."}), 200
            except Exception as e:
                db.session.rollback()  # Roll back in case of an error
                print(f"An error occurred: {e}")
                return jsonify(message="Invalid request."), 400

    return render_template("clearLateLog.html")

@routes.route('/admin/clear-user', methods=["GET", 'POST'])
@admin_required
def clear_user_logs():
    if 'admin_logged_in' not in session:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for('routes.admin'))
    
    if request.method == "POST":
        action = request.form["action"]
        statecode = request.form["statecode"].upper()
        last_name = request.form["last_name"]
        print(action)
        print(statecode)
        print(last_name)

        if statecode and last_name:
            try:
                # Query for the user
                user = Users.query.filter(
                    Users.state_code == statecode,  # Case-insensitive
                    Users.last_name.ilike(last_name)
                ).first()
                
                if not user:
                    print("User not found")
                    return jsonify({"success":False, "message":"User not found"}), 200
                
                elif action =='attendance':
                    # Delete all associated attendance logs
                    deleted_rows = AttendanceLog.query.filter_by(user_id=user.id).delete()
                    db.session.commit()
                    
                    if deleted_rows > 0:
                        print("All Attendance entries have been cleared.")
                        return jsonify({"message":f"All Attendance entries cleared for {statecode}."}), 200
                    else:
                        return jsonify({"message": f"No records found for state code {statecode}."}), 200
                    
                elif action == "delete":
                    # Delete all associated attendance logs
                    attd_deleted_rows = AttendanceLog.query.filter_by(user_id=user.id).delete()
                    db.session.commit()
                    
                    # Delete user record
                    deleted_rows = Users.query.filter(
                        Users.state_code == statecode,  # Case-insensitive
                        Users.last_name.ilike(last_name)
                    ).delete()
                    db.session.commit()
                    
                    if deleted_rows > 0  or attd_deleted_rows > 0:
                        # print("User records deleted from database.")
                        return jsonify({"message":f"All records of {statecode} deleted successfully."}), 200
                    else:
                        return jsonify({"message": f"No records found for state code {statecode}."}), 200
                    
            except Exception as e:
                db.session.rollback()
                return jsonify(success=False, message=f"An error occurred: {str(e)}"), 500

    return render_template("clearuser.html")

@routes.route('/get_details', methods=['GET'])
@admin_required
def getDetails():
    # GETS THE AMOUNT FROM THE USER DATABASE AND 
    # UPDATES THE ADMIN DASHBOARD REQUESTS TABLE
    
    # Get the user status from the query parameters
    stateCode = request.args.get('stateCode').upper()
    latecomer_details = LateLog.query.filter_by(state_code=stateCode).first()
    
    if latecomer_details:
        amount = latecomer_details.amount
        return jsonify({'success': True, 'message': amount}), 200
        # return jsonify(amount)
    
    return jsonify({'success': False, 'message': 'User not found'}), 404

@routes.route('/status_update', methods=['POST'])
@admin_required
def update_latecomer():
    statecode = request.form['state_code'].upper()
    status = request.form['status'].capitalize()
    amount = request.form['amount']
        
    if not statecode:
        return jsonify({'success': False, 'message': 'State code is required'}), 400
    
    try:
        # Query the LateLog table to find the user
        Latecomer = LateLog.query.filter_by(state_code=statecode, status="Pending").first()

        if not Latecomer:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        # Update the status of payment in the LateLog table
        if Latecomer and status=="Approved" and amount != "":
            Latecomer.status = status
            Latecomer.amount = 0
            db.session.commit()
            return jsonify({'success': True, 'message': f'Approved'}), 200
        elif status == "Pending" :
            # pass
            return jsonify({'success': True, 'message': f'Still Pending'}), 200
 
    except Exception as e:
        db.session.rollback()  # Rollback in case of error
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 500
    
    
    return redirect(url_for('routes.admindash'))

@routes.route('/payment/late-signin', methods=['GET', 'POST'])
def payment(statecode):
    # Check Latecomer
    latecomer = LateLog.query.filter_by(state_code=statecode).first()
    
    # Check admin settings for payment details
    settings = AdminSettings.query.first()

    # Check if the statecode exists in the database
    if latecomer:
        amount = latecomer.amount
        # return jsonify({"success":True,"message":"Sent latecomer"})
        return render_template("paymentpage.html", 
                               statecode=statecode, 
                               amount=amount, 
                               bankname=settings.bank_name,
                               acctname=settings.account_name, 
                               acctnum=settings.account_number)
    else :
        return jsonify({"success":False,"message":"Couldn't find latecomer"}) # Failure status error

@routes.route('/check_status', methods=['GET'])
def check_status():
    # Get 'statecode' from query parameters
    statecode = request.args.get('statecode').upper()

    # Validate 'statecode' input
    if not statecode:
        return jsonify({"error": "Statecode is required"}), 400

    try:
        # Query the database for the status
        latecomer = LateLog.query.filter_by(state_code=statecode).first()

        # Check if the statecode exists in the database
        if latecomer:
            return jsonify({"status": latecomer.status}), 200
        else:
            return jsonify({"error": "Statecode not found"}), 404

    except SQLAlchemyError as e:
        # Handle database connection or query errors
        return jsonify({"error": str(e)}), 500

# Use this to handle Monthly Due requests
@routes.route('/admin/pending_due_requests', methods=['GET'])
def pending_due_requests():
    pending_requests = LateSignIn.query.filter_by(status="Pending").all()
    return jsonify([{
        "state_code": req.state_code,
        "date": req.date,
        "amount": req.amount,
        "status": req.status
    } for req in pending_requests])

@routes.route('/payment/monthly-due')
def pay_monthly_due():
    return render_template ("error.html")

@routes.route('/export_attendance', methods=['GET', 'POST'])
@admin_required
def export_attendance():

    format = request.args.get('format')
    meeting_date = request.args.get('start_date')
    meeting_date2 = request.args.get('end_date')
    print("Received: ")
    print(format)
    print(meeting_date)
    print(meeting_date2)
    
    if not all([format, meeting_date, meeting_date2]):
        return jsonify({'error': 'Missing required parameters'}), 400

    if format not in ['csv', 'xlsx', 'pdf']:
        return jsonify({'error': 'Invalid format selected. Allowed formats are csv, xlsx, pdf'}), 400

    attendance_data = collect_attendance_data_for_range(meeting_date, meeting_date2)
    print('Collect')
    print(attendance_data)
    date_range = get_date_range(meeting_date, meeting_date2)
    data = preprocess_attendance_data_for_range(attendance_data,date_range)
    print("Data")
    print(data)
        
    if meeting_date != meeting_date2:
        meeting_date=f"{meeting_date}_to_{meeting_date2}"
    else : meeting_date = meeting_date
    
    # Generate the file in the requested format
    if format == 'csv':
        file_buffer = generate_csv_with_title(data, meeting_date)
        # file_buffer = generate_csv(data)
        mimetype = 'text/csv'
        extension = 'csv'
    elif format == 'xlsx':
        file_buffer = generate_xlsx_range(data, meeting_date)
        mimetype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        extension = 'xlsx'
    elif format == 'pdf':
        # file_buffer = generate_pdf_for_range(data, meeting_date)
        return generate_pdf_with_wrapping_range(data, meeting_date)
        # return generate_pdf_with_reportlab(data, meeting_date)
        mimetype = 'application/pdf'
        extension = 'pdf'
    else:
        return jsonify({'error': 'Invalid format selected'}), 400

    # For BytesIO and io.BytesIO, send directly from memory
    return send_file(
        file_buffer,
        mimetype=mimetype,
        as_attachment=True,
        download_name=f"NIESAT_attendance_{meeting_date}.{extension}"
    )

@routes.route('/user_attendance_log', methods=['POST'])
def user_logs():
    user_logs = user.attendance_logs  # `user` is an instance of Users
    for log in user_logs:
        print(log.meeting_date, log.sign_in_time, log.ip_address)

@routes.route('/thankyou')
def thankyou():
    return render_template('thankyouregister.html')


# ---------------- FUNCTIONS ---------------- #

def check_user_reg_exists(user_data=None,statecode=None,last_name=None, **kwargs):
    if statecode and last_name :
        print(last_name)
        print(statecode)
        try:
            # Query for the user
            user = Users.query.filter_by(
                state_code=statecode,
                last_name=last_name
            ).first()

            # RETURN RESPONSE
            if not user:
                print("None")
                return False
            else:
                return user

        except IntegrityError:
            db.session.rollback()  # Rollback the transaction
            print("IntegrityError: User might already exist. Querying again...")
            # Re-query the user in case of integrity error, 
            # check again using case-insensitive format
            return Users.query.filter(
                Users.state_code == user_data['state_code'],
                Users.first_name.ilike(user_data['first_name']),  # Case-insensitive
                Users.last_name.ilike(user_data['last_name'])
            ).first()
    
    if user_data :
        # Normalize input for consistent comparison
        print(user_data['first_name'])
        print(user_data['middle_name'])
        print(user_data['last_name'])
        print(user_data['gender'])
        print(user_data['local_gov'])
        print(user_data['state_code'])
        try:
            # Query for the user
            new_user = Users.query.filter_by(
                state_code=user_data['state_code'],
                first_name=user_data['first_name'],
                last_name=user_data['last_name']
            ).first()

            # If the user does not exist, create a new one
            if not new_user:
                new_user = Users(
                    first_name=user_data['first_name'],
                    middle_name=user_data['middle_name'],
                    last_name=user_data['last_name'],
                    gender=user_data['gender'],
                    local_gov=user_data['local_gov'],
                    state_code=user_data['state_code'],
                    registration_date=datetime.now().date()
                )
                db.session.add(new_user)
                db.session.commit()
                print("New User Added.")
            return new_user

        except IntegrityError:
            db.session.rollback()  # Rollback the transaction
            print("IntegrityError: User might already exist. Querying again...")
            # Re-query the user in case of integrity error, 
            # check again using case-insensitive format
            return Users.query.filter(
                Users.state_code == user_data['state_code'],
                Users.first_name.ilike(user_data['first_name']),  # Case-insensitive
                Users.last_name.ilike(user_data['last_name'])
            ).first()

        except Exception as e:
            print(f"An unexpected error occurred: {str(e)}")
            db.session.rollback()
            return None

def check_user_attendance_exists(statecode):
    # Check if the state code is already in the day's attendance
    
    meeting_date = datetime.now().date()  # Default to today's date
    user_exists = Users.query.filter_by(state_code=statecode).first()
    if user_exists:
        attendance_logged = AttendanceLog.query.filter_by(user_id=user_exists.id, meeting_date=meeting_date).first()
        if attendance_logged:
            return f"StateCode, {statecode}, already logged for today!"
    
    return ""

def record_attendance(user):
    print(f"Record ID: {user.id}")
    # Record user attendance for the day
    new_attendance = AttendanceLog(
        user_id=user.id,  # Assuming `user` is an instance of Users
        sign_in_time=datetime.now().time(),
        # ip_address=request.remote_addr,
        meeting_date=datetime.now().date()
    )
    db.session.add(new_attendance)
    db.session.commit()
    print("User attendance added.")
    
    return True
    
def update_latecomer_status(stateCode):
    # Find the late log for the state code
    late_log = LateLog.query.filter_by(state_code=stateCode).first()
    
    if late_log:
        late_log.amount = 0
        late_log.status = "Approved"
        db.session.commit()

def check_latefile(statecode):
    # Check if statecode is in the LateLog table
    late_log = LateLog.query.filter_by(state_code=statecode).first()
    
    if late_log:
        return True
    return False

def get_client_IP():
    # global client_ip
    if request.headers.getlist("X-Forwarded-For") :
        client_ip = request.headers.getlist("X-Forwarded-For")[0]
        print(1)
        return client_ip
    else :
        client_ip = request.remote_addr
        print(2)
        return client_ip

def pop_latecomer(statecode):
    # Remove user from LateLog after fine fee payment is confirmed
    Latecomer = LateLog.query.filter_by(state_code=statecode, status="Approved").first()
    db.session.delete(Latecomer)
    db.session.commit()

def get_attendance_data(meeting_date):
    # Get attendance data for one particular day
    meeting_date = meeting_date
    # meeting_date = datetime.now().date()
    
    if not meeting_date:
        meeting_date = datetime.now().date()
        
    log_query = AttendanceLog.query.join(Users).add_columns(
        Users.first_name, Users.middle_name, Users.last_name, Users.state_code, Users.gender,
        AttendanceLog.meeting_date
    )
    
    if meeting_date:
        log_query = log_query.filter(AttendanceLog.meeting_date == meeting_date)

    logs = log_query.all()

    attendance_data = [
        {
            'first_name': log.first_name,
            'middle_name': log.middle_name,
            'last_name': log.last_name,
            'state_code': log.state_code,
            'meeting_date': log.meeting_date.strftime('%Y-%m-%d'),
            # 'gender': log.gender,
            'gender': getattr(log, 'gender', 'N/A')  # Provide a fallback value
        }
        for log in logs
    ]
    # print(attendance_data)
    
    return attendance_data



def getSettings():
    # Get Admin Settings
    settings = AdminSettings.query.first()
    
    # print(f"Early Start: {settings.early_arrival_start}")
    # print(f"Late Start: {settings.late_arrival_start}")
    # print(f"Late End: {settings.late_arrival_end}")
    
    settings_data = {
        # "early_start": settings.early_arrival_start,
        # "late_start": settings.late_arrival_start,
        # "late_end": settings.late_arrival_end,
        "lateness_fine": settings.lateness_fine,
        "monthly_due": settings.monthly_due,
        "account_name": settings.account_name,
        "account_number": settings.account_number,
        "bank_name": settings.bank_name,
        "admin_username": settings.admin_username,
        "meeting_day": settings.meeting_day
    }
    print(f"Meeting_day: {settings.meeting_day}")
    
    return settings_data

def preprocess_data(data):
    # Preprocess Data for pdf generation
    formatted_data = []
    for i, record in enumerate(data, start=1):
        full_name = f"{record['first_name']} {record['middle_name']} {record['last_name']}"
        state_code = record.get('state_code', 'N/A')
        gender = record.get('gender', 'N/A')
        formatted_data.append({
            'S/N': i,
            'NAME': full_name,
            'STATE CODE': state_code,
            'SEX': gender
        })
    return formatted_data

def generate_csv(data):
    # Preprocess data
    formatted_data = preprocess_data(data)
    
    # Convert formatted data to DataFrame
    df = pd.DataFrame(formatted_data)
    
    # Create a CSV in memory
    csv_data = df.to_csv(index=False)
    return BytesIO(csv_data.encode('utf-8'))

def generate_xlsx(data, meeting_date):
    # Preprocess data
    formatted_data = preprocess_data(data)
    
    # Convert formatted data to DataFrame
    df = pd.DataFrame(formatted_data)
    
    # Create an in-memory buffer to store the Excel file
    excel_buffer = BytesIO()
    with pd.ExcelWriter(excel_buffer, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name=f'Attendance - {meeting_date}')
        
        # Access the workbook and worksheet objects
        workbook = writer.book
        worksheet = writer.sheets[f'Attendance - {meeting_date}']
        
        # Calculate dynamic column widths
        for i, col in enumerate(df.columns):
            max_length = max(
                [len(str(value)) for value in df[col]] + [len(str(col))]
            )  # Include header length
            worksheet.set_column(i, i, max_length + 2)  # Add padding
        
    # Move to the start of the buffer before returning
    excel_buffer.seek(0)
    return excel_buffer

def generate_xlsx_range(data, meeting_date):
    # Create an in-memory buffer for the Excel file
    excel_buffer = BytesIO()
    
    # Add the serial number column to the data
    data = [{"S/N": i + 1, **record} for i, record in enumerate(data)]
    
    with pd.ExcelWriter(excel_buffer, engine='xlsxwriter') as writer:
        df = pd.DataFrame(data)
        df.to_excel(writer, index=False, startrow=4, sheet_name='Attendance')

        # Access the workbook and worksheet
        workbook = writer.book
        worksheet = writer.sheets['Attendance']

        # Add a title and merge cells for it
        title = (f"NIGERIA INNOVATIVE ENGINEERS SCIENTIST AND APPLIED TECHNOLOGIST (NIESAT)"
                 f"\nCOMMUNITY DEVELOPMENT SERVICE GROUP ATTENDANCE for {meeting_date}")
        worksheet.merge_range("A1:R3", title, workbook.add_format({
            'align': 'center', 'valign': 'vcenter', 'bold': True, 'font_size': 18, 'text_wrap':True
        }))
        
        # Write the headers manually below the title
        # for col_num, col_name in enumerate(df.columns):
        #     worksheet.write(2, col_num, col_name, workbook.add_format({'font_size': 12,'bold': True,'align': 'center', 'valign': 'vcenter'}))

        # Adjust column widths dynamically
        for col_num, col_name in enumerate(df.columns):
            max_length = max(df[col_name].astype(str).apply(len).max(), len(col_name)) + 2
            worksheet.set_column(col_num, col_num, max_length)

        # Wrap text for the "NAME" column
        name_format = workbook.add_format({'font': 'Book Antiqua', 'font_size':11})
        worksheet.set_column('C:C', 20, name_format)

    excel_buffer.seek(0)
    return excel_buffer


def generate_pdf(data, meeting_date):
    # Initialize PDF
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    
    # Title
    pdf.cell(200, 10, txt=f"Attendance Logs - {meeting_date}", ln=True, align='C')

    # Add table headers
    pdf.cell(40, 10, txt="First Name", border=1, align='C')
    pdf.cell(40, 10, txt="Middle Name", border=1, align='C')
    pdf.cell(40, 10, txt="Last Name", border=1, align='C')
    pdf.cell(40, 10, txt="State Code", border=1, align='C')
    pdf.cell(40, 10, txt="Meeting Date", border=1, align='C')
    pdf.ln()  # Newline after the headers

    # Add each attendance record
    for record in data:
        pdf.cell(40, 10, txt=record['first_name'], border=1, align='C')
        pdf.cell(40, 10, txt=record['middle_name'], border=1, align='C')
        pdf.cell(40, 10, txt=record['last_name'], border=1, align='C')
        pdf.cell(40, 10, txt=record['state_code'], border=1, align='C')
        pdf.cell(40, 10, txt=record['meeting_date'], border=1, align='C')
        pdf.ln()  # Newline after each record
    
    # Create a temporary file with flask then return the temporary file
    tmp_file = tempfile.NamedTemporaryFile(delete=False)
    pdf.output(tmp_file.name) # Write PDF to the temporary file
    tmp_file.seek(0) # Go to the start of the file
    # For temp_file, send in-memory temporary file
    return send_file(
        tmp_file.name,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f"attendance_{meeting_date}.pdf"
    )
    return tmp_file

def generate_pdf_with_reportlab(data, meeting_date):
    
    # Create a BytesIO buffer to hold the PDF content
    pdf_buffer = BytesIO()

    # Initialize the ReportLab canvas
    c = canvas.Canvas(pdf_buffer, pagesize=letter)

    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(200, 750, f"Attendance Logs - {meeting_date}")

    # Calculate dynamic column widths
    headers = ["S/N", "NAME", "STATE CODE", "SEX"]
    column_data = [[str(index), 
                    f"{record['first_name']} {record['middle_name']} {record['last_name']}", 
                    record['state_code'], 
                    record['gender']
                ] for index, record in enumerate(data, start=1)]
    
    column_data.insert(0, headers)  # Include headers in column data for width calculation
    
    padding = 10 # Padding for eacg column
    max_widths = [
        max(len(str(row[col])) for row in column_data) * 7 + padding  # Estimate width per character
        for col in range(len(headers))
    ]
    
        # Enforce a minimum width for each column to avoid overcrowding
    min_widths = [30, 100, 80, 40]
    column_widths = [max(mw, min_w) for mw, min_w in zip(max_widths, min_widths)]
    
    # Calculate x_positions dynamically
    # x_positions = [sum(max_widths[:i]) + 50 for i in range(len(max_widths))]
    x_positions = [sum(column_widths[:i]) + 50 for i in range(len(headers))]

    # Draw table headers
    c.setFont("Helvetica-Bold", 12)
    y_position = 700
    for i, header in enumerate(headers):
        c.drawString(x_positions[i], y_position, header)

    # Draw a line under the headers
    # c.line(50, y_position - 5, x_positions[-1] + max_widths[-1], y_position - 5)
    # Draw a line under the headers
    c.line(50, y_position - 5, x_positions[-1] + column_widths[-1], y_position - 5)

    # Draw Table content
    c.setFont("Helvetica", 12)
    y_position -= 30
    for index, record in enumerate(data, start=1):
        if y_position < 50:  # Start a new page if space runs out
            c.showPage()
            c.setFont("Helvetica", 12)
            y_position = 750

        # Draw data rows
        row = [str(index), 
               f"{record['first_name']} {record['middle_name']} {record['last_name']}", 
               record['state_code'], 
               record['gender']]
        
        for i, cell in enumerate(row):
            c.drawString(x_positions[i], y_position, str(cell))
        
        y_position -= 20

    # Finalize the PDF
    c.save()

    # Rewind the buffer to the beginning
    pdf_buffer.seek(0)
    
    # Return the PDF as a response
    return Response(
        pdf_buffer,
        mimetype='application/pdf',
        headers={
            "Content-Disposition": f"attachment; filename=NIESAT_attendance_log_{meeting_date}.pdf"
        }
    )

def generate_pdf_with_wrapping(data, meeting_date):
    # Create a BytesIO buffer
    pdf_buffer = BytesIO()

    # Initialize the document
    doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)

    # Define styles
    styles = getSampleStyleSheet()
    normal_style = styles["Normal"]

    # Prepare table data
    headers = ["S/N", "NAME", "STATE CODE", "SEX"]
    table_data = [headers]  # Add headers

    # Add data rows
    for index, record in enumerate(data, start=1):
        row = [
            str(index),
            Paragraph(f"{record['first_name']} {record['middle_name']} {record['last_name']}", normal_style),
            record['state_code'],
            record['gender']
        ]
        table_data.append(row)
        
    # Add data rows
    # for index, record in enumerate(data, start=1):
        # row = [
        #     str(index),
        #     Paragraph(f"{record['NAME']}", normal_style),
        #     record['STATE CODE'],
        #     record['GENDER'],
        # ]
        # table_data.append(row)

    # Create the table
    table = Table(table_data, colWidths=[0.5 * inch, 2.5 * inch, 1.5 * inch, 1 * inch])

    # Style the table
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),  # Header background
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  # Header text color
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),  # Center align all cells
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),  # Header font
        ('FONTSIZE', (0, 0), (-1, -1), 10),  # Font size for all cells
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),  # Padding for header row
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),  # Row background
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),  # Grid lines
    ]))

    # Build the document
    elements = [
        Paragraph(f"Attendance Logs - {meeting_date}", styles['Title']),
        table
    ]
    doc.build(elements)

    # Rewind the buffer
    pdf_buffer.seek(0)

    # Return the PDF as a response
    return Response(
        pdf_buffer,
        mimetype='application/pdf',
        headers={
            "Content-Disposition": f"attachment; filename=NIESAT_attendance_log_{meeting_date}.pdf"
        }
    )

def collect_attendance_data_for_range(date1, date2):
    # Generate the date range
    date_range = get_date_range(date1, date2)
    print("Date Range:", date_range)
    all_attendance_data = []

    # Loop through each date and fetch attendance logs
    for date in date_range:
        logs = AttendanceLog.query.join(Users).add_columns(
            Users.first_name, Users.middle_name, Users.last_name, Users.gender,
            Users.state_code, AttendanceLog.meeting_date
        ).filter(AttendanceLog.meeting_date == date).all()
        
        # Append logs to attendance data
        for log in logs:
            try:
                all_attendance_data.append({
                    "first_name": log.first_name,
                    "middle_name": log.middle_name or "",  # Handle missing middle name
                    "last_name": log.last_name,
                    "state_code": log.state_code,
                    "gender": log.gender,
                    "meeting_date": log.meeting_date.strftime("%Y-%m-%d")
                })
            except AttributeError as e:
                print(f"Error processing log: {log}. Error: {e}")

    print("Collected Attendance Data:", all_attendance_data)
    return all_attendance_data


def get_date_range(date1, date2):
    start_date = datetime.strptime(date1, "%Y-%m-%d")
    end_date = datetime.strptime(date2, "%Y-%m-%d")

    # Generate all dates in the range
    date_range = [(start_date + timedelta(days=i)).strftime("%Y-%m-%d") 
                  for i in range((end_date - start_date).days + 1)]
    return date_range

def preprocess_attendance_data_for_range(attendance_data, date_range):
    # Dictionary to store users and their attendance
    users = {}
    # serial_number = 1
    for record in attendance_data:
        user_key = f"{record['first_name']} {record['middle_name']} {record['last_name']}"
        if user_key not in users:
            users[user_key] = {
                # "S/N": serial_number,
                "NAME": user_key,
                "STATE CODE": record["state_code"],
                "GENDER": record["gender"],
                **{date: "A" for date in date_range}  # Default to "A" (Absent)
            }
        # Mark present for the specific date
        users[user_key][record["meeting_date"]] = "P"
        # serial_number+=1

    # Convert dictionary to list of dictionaries
    return list(users.values())

def generate_csv_with_title(data, meeting_date):
    # Create a CSV buffer
    csv_buffer = BytesIO()

    # Define the column order
    dynamic_dates = sorted({key for record in data for key in record.keys() if key not in ["S/N", "NAME", "STATE CODE", "GENDER"]})
    columns = ['S/N', 'NAME', 'STATE CODE', 'GENDER'] + dynamic_dates

    # Prepare the title
    title = (f"NIGERIA INNOVATIVE ENGINEERS SCIENTIST AND APPLIED TECHNOLOGIST (NIESAT)\n"
             f"COMMUNITY DEVELOPMENT SERVICE GROUP ATTENDANCE for {meeting_date}")

    # Write the CSV
    writer = csv.writer(csv_buffer, quoting=csv.QUOTE_MINIMAL)
    # Add the title as the first row(s)
    writer.writerow([title])  # Title row
    writer.writerow([])  # Blank row for spacing
    writer.writerow(columns)  # Header row

    # Add data rows
    for idx, record in enumerate(data, start=1):
        row = [idx]  # Start with serial number
        row += [record.get(key, "N/A") for key in ['NAME', 'STATE CODE', 'GENDER'] + dynamic_dates]
        writer.writerow(row)

    # Move the buffer position back to the start
    csv_buffer.seek(0)

    return csv_buffer


def generate_pdf_with_wrapping_range(data, meeting_date):
    # Create a BytesIO buffer
    pdf_buffer = BytesIO()

    # Initialize the document
    doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)

    # Define styles
    styles = getSampleStyleSheet()
    normal_style = styles["Normal"]

    # Extract dynamic dates from the data
    dynamic_dates = sorted({key for record in data for key in record.keys() if key not in ["NAME", "STATE CODE", "GENDER"]})

    # Prepare table headers
    headers = ["S/N", "NAME", "STATE CODE", "SEX"] + dynamic_dates
    table_data = [headers]  # Add headers

    # Add data rows
    for index, record in enumerate(data, start=1):
        row = [
            str(index),  # Serial number
            Paragraph(record["NAME"], normal_style),  # Name
            record["STATE CODE"],  # State code
            record["GENDER"],  # Gender
        ] + [record.get(date, "N/A") for date in dynamic_dates]  # Dynamic dates
        table_data.append(row)

    # Create the table
    col_widths = [0.5 * inch, 2.5 * inch, 1.5 * inch, 1 * inch] + [1 * inch] * len(dynamic_dates)
    table = Table(table_data, colWidths=col_widths)

    # Style the table
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),  # Header background
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  # Header text color
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),  # Center align all cells
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),  # Header font
        ('FONTSIZE', (0, 0), (-1, -1), 10),  # Font size for all cells
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),  # Padding for header row
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),  # Row background
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),  # Grid lines
    ]))

    # Build the document
    elements = [
        Paragraph(f"""NIGERIA INNOVATIVE ENGINEERS SCIENTIST AND APPLIED TECHNOLOGIST (NIESAT)
             <br/>COMMUNITY DEVELOPMENT SERVICE GROUP ATTENDANCE for {meeting_date}""", styles['Title']),
        table
    ]
    doc.build(elements)

    # Rewind the buffer
    pdf_buffer.seek(0)

    # Return the PDF as a response
    return Response(
        pdf_buffer,
        mimetype='application/pdf',
        headers={
            "Content-Disposition": f"attachment; filename=NIESAT_attendance_log_{meeting_date}.pdf"
        }
    )
