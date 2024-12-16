from flask import Flask,request,Response,render_template,session,redirect,url_for,jsonify,send_file,flash, Blueprint
from flask_session import Session
import pandas as pd
from datetime import datetime,time,timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
from models import *
import csv
from io import BytesIO
from fpdf import FPDF
from flask import make_response
import xlsxwriter
import tempfile
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
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
def index():
    return render_template("index.html")

@routes.route('/history')
def history():
    return render_template ("error.html")
    return render_template ("history.html")
    # return ("successful")

@routes.route('/signin', methods=['GET', 'POST'])
def signin():   
    if request.method == "POST":
        # Define attendance time ranges
        settings = AdminSettings.query.first()
        early_start = settings.early_arrival_start
        late_start = settings.late_arrival_start
        late_end = settings.late_arrival_end
        print(early_start)
        print(late_start)
        print(late_end)

        fname = request.form['fname'].strip().capitalize() # First name
        mname = request.form['mname'].strip().capitalize() # Middle name
        sname = request.form['sname'].strip().upper() # Last name
        statecode = request.form['statecode'].strip().upper()
        print(fname)
        print(mname)
        print(sname)
        print(statecode)
        
        signInTD = datetime.now().strftime('%Y-%m-%d %H:%M:%S')[:-3] # SignIn Date and Time
        signInTime = datetime.now().strftime('%H:%M:%S') # SignIn Time
        signInD = datetime.now().strftime('%Y-%m-%d') # SignIn Date
        
        client_ip = get_client_IP()

        # Check if user attendance is registered already
        attendanceStatus = check_user_attendance_exists(statecode)
        # regStatus = check_user_reg_exists(statecode, fname, mname, sname)
        if attendanceStatus != "":
            return render_template("signin.html", regErrorMsg=attendanceStatus)
            
        else:
            # If late, handle late sign-in
            current_time = datetime.now().time()
            # if late_start <= current_time <= late_end:
            if late_end <= current_time:
            # if current_time <= late_start:
            # if late_start <= current_time:
                request_type = "Late sign-in"
                amount = settings.lateness_fine
                status = "Pending"
                
                # Check if user already in late list
                late_status = check_latefile(statecode)
                if not late_status:
                    new_late_log = LateLog(
                        transaction_date=datetime.now().date(),
                        state_code=statecode,
                        request_type=request_type,
                        amount=amount,
                        status=status
                    )
                    db.session.add(new_late_log)
                    db.session.commit()
                return payment(fname, mname, sname, statecode, signInTime, signInTD, client_ip)
            
            # elif late_end <= current_time:
            elif early_start <= current_time < late_start:
                
                # Check if user is already registered in database or add user
                user = check_user_reg_exists(statecode, fname, mname, sname)
                # Regular sign-in (early sign-in)
                confirm_attendance = record_attendance(user)
                # if result["success"]:
                #     confirm_attendance = record_attendance(result["user"])
                # else:
                #     regErrorMsg = result["message"]
                #     return render_template ("signin.html", regErrorMsg=regErrorMsg)
    
                if confirm_attendance:
                    return render_template("thankyouregister.html")
                else:
                    return """<h1>Server Error!</h1> <h4><p>Failed to log attendance</p></h4>""", 500
            
            else:
                regErrorMsg = "Sign-in time elapsed or not yet reached!"
                return render_template ("signin.html", regErrorMsg=regErrorMsg)   
    
    return render_template("signin.html")

@routes.route('/late/signin', methods=['GET', 'POST'])
def late_reg():
    if request.method == 'POST':
        fname = request.form['fname'].strip().capitalize()
        mname = request.form['mname'].strip().capitalize()
        sname = request.form['sname'].strip().upper()
        statecode = request.form['statecode'].strip().upper()
        signInTime = request.form['signInTime']
        signInTD = request.form['signInTD']
        # client_ip = request.form['client_ip']
        client_ip = get_client_IP()
        status = request.form['status']
        
        # Check if user is already registered in database or add user
        user = check_user_reg_exists(statecode, fname, mname, sname)
        # print(user.id)
        
        # if result["success"]:
        #     confirm_attendance = record_attendance(user=result["user"])
        # else:
        #     regErrorMsg = result["message"]
        #     return render_template ("signin.html", regErrorMsg=regErrorMsg)
        
        # Check if user attendance is registered already
        attendanceStatus = check_user_attendance_exists(statecode)

        if attendanceStatus != "":
            return render_template("signin.html", regErrorMsg=attendanceStatus)
        
        # Add late registration to database
        confirm_attendance = record_attendance(user)
        
        if confirm_attendance:
            # Remove the user from the LateLog database
            pop_latecomer(statecode, status)
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
            return jsonify({'error': 'Admin settings not found'}), 500
        
        # Verify the username and password
        if username == admin_settings.admin_username and check_password_hash(admin_settings.admin_password, password):
            session.permanent = True
            session['admin_logged_in'] = True
            flash("Login successful!", "success")
            return redirect(url_for('routes.admindash'))
        else:
            flash("Invalid credentials!", "danger")
            return jsonify(success=False), 401  # Response with failure status and 401 error
        #     return jsonify(success=True), 200  # Response with success status
        # else:
        #     return jsonify(success=False), 401  # Response with failure status and 401 error

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
        meeting_date = request.args.get('date')
        # print(meeting_date)
        
        # If no date is provided, default to today's date
        if not meeting_date:
            meeting_date = datetime.now().date()
            # print(meeting_date)
        
        # Query the attendance logs for the given date and respond to the AJAX request
        attendance_request = get_attendance_data(meeting_date)
        # print(attendance_request)
        if len(attendance_request) <= 0:
            return jsonify({"success": False, "message": "No attendance records found for this date."}), 200

        return jsonify(attendance_request)

    # If the request is not an AJAX request
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
                    deleted_rows = Users.query.filter(
                        Users.state_code == statecode,  # Case-insensitive
                        Users.last_name.ilike(last_name)
                    ).delete()
                    db.session.commit()
                    
                    if deleted_rows > 0:
                        print("User records deleted from database.")
                        return jsonify({"message":f"All records of {statecode} deleted successfully."}), 200
                    else:
                        return jsonify({"message": f"No records found for state code {statecode}."}), 200
                    
            except Exception as e:
                db.session.rollback()
                return jsonify(success=False, message=f"An error occurred: {str(e)}"), 500

    return render_template("clearuser.html")

@routes.route('/get_details', methods=['GET'])
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
def payment(fname, mname, sname, statecode, signInTime, signInTD, client_ip):
    
    latecomer = LateLog.query.filter_by(state_code=statecode).first()

    # Check if the statecode exists in the database
    if latecomer:
        amount = latecomer.amount
        return render_template("paymentpage.html", fname=fname, mname=mname, sname=sname, statecode=statecode, amount=amount)
    else :
        return jsonify(success=False), 404  # Failure status error

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
def export_attendance():
    # try:
        format = request.args.get('format')
        meeting_date = request.args.get('date')
        print("Received: ")
        print(format)
        print(meeting_date)
        
        if not format:
            return jsonify({'error': 'No format specified'}), 400
        if not meeting_date:
            return jsonify({'error': 'No date specified'}), 400
        if format not in ['csv', 'xlsx', 'pdf']:
            return jsonify({'error': 'Invalid format selected. Allowed formats are csv, xlsx, pdf'}), 400
        if not meeting_date:
            return jsonify({'error': 'Please provide a valid meeting date'}), 400

        # Query attendance logs
        data = get_attendance_data(meeting_date)
        
        # Generate the file in the requested format
        if format == 'csv':
            file_buffer = generate_csv(data)
            mimetype = 'text/csv'
            extension = 'csv'
        elif format == 'xlsx':
            file_buffer = generate_xlsx(data, meeting_date)
            mimetype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            extension = 'xlsx'
        elif format == 'pdf':
            return generate_pdf_with_reportlab(data, meeting_date)
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
        
    # except SQLAlchemyError as e:
    #     return jsonify({'error': f'Database error: {str(e)}'}), 500
    # except Exception as e:
    #     return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@routes.route('/user_attendance_log', methods=['POST'])
def user_logs():
    user_logs = user.attendance_logs  # `user` is an instance of Users
    for log in user_logs:
        print(log.meeting_date, log.sign_in_time, log.ip_address)


# ---------------- FUNCTIONS ---------------- #

def check_user_reg_exists(statecode, fname, mname, sname):
    # Normalize input for consistent comparison
    statecode = statecode.strip().upper()
    fname = fname.strip().capitalize()
    mname = mname.strip().capitalize() if mname else "-"
    sname = sname.strip().upper()
    try:
        # Query for the user
        new_user = Users.query.filter_by(
            state_code=statecode,
            first_name=fname,
            last_name=sname
        ).first()

        # If the user does not exist, create a new one
        if not new_user:
            new_user = Users(
                first_name=fname,
                middle_name=mname,
                last_name=sname,
                state_code=statecode,
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
            Users.state_code == statecode,
            Users.first_name.ilike(fname),  # Case-insensitive
            Users.last_name.ilike(sname)
        ).first()

    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        db.session.rollback()
        return None
    
    
    # try :
        # Query for potential matches
        # matches = Users.query.filter(
        #     or_(
        #         Users.state_code == statecode,
        #         Users.first_name.ilike(fname),
        #         Users.last_name.ilike(sname)
        #     )
        # ).all()
        
        # # if not matches:
        # #     print("NOOOOOO MATCHHHHHH 1")
        # #     return {"success": False, "message": "No matching user found"}
        
        # # Count the matching parameters for partial match situations
        # for match in matches:
        #     match_count = sum([
        #         match.state_code == statecode,
        #         match.first_name == fname,
        #         match.last_name == sname
        #     ])
        #     if match_count == 3:
        #         print("MATCHHHHHH")
        #         return {"success": True, "user":match}
        #     elif match_count in [1,2]:
        #         print("PARTIAL MATCHHHHHH")
        #         return {
        #             "success": False,
        #             "message": f"Partial match found ({match_count}/3 details matched). Please verify the entered details."
        #         }
        #     elif match_count == 0:
        #         print("NOOOOOO MATCHHHHHH 2")
        #         new_user = Users(
        #             first_name=fname,
        #             middle_name=mname,
        #             last_name=sname,
        #             state_code=statecode,
        #             registration_date=datetime.now().date()
        #         )
        #         db.session.add(new_user)
        #         db.session.commit()
        #         print("New User Added.")
        #         # return {"success": True, "user":new_user}
        #         return new_user
                
    # except Exception as e:
        # print(f"An unexpected error occurred: {str(e)}")
        # db.session.rollback()
        # return None
    
def check_user_attendance_exists(statecode):
    # Check if the state code is already in the day's attendance
    
    meeting_date = datetime.now().date()  # Default to today's date
    user_exists = Users.query.filter_by(state_code=statecode).first()
    if user_exists:
        attendance_logged = AttendanceLog.query.filter_by(user_id=user_exists.id, meeting_date=meeting_date).first()
        if attendance_logged:
            return f"StateCode, {statecode}, already logged for today!"

    # ip_used = AttendanceLog.query.filter_by(ip_address=client_ip).first()
    # Check if the device (IP address) is already used
    # elif (ip_used):
    #     return "Can't use the same device for more than one signing!"
    
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

def pop_latecomer(statecode, status):
    # Remove user from LateLog after fine fee payment is confirmed
    Latecomer = LateLog.query.filter_by(state_code=statecode, status="Approved").first()
    db.session.delete(Latecomer)
    db.session.commit()

def get_attendance_data(meeting_date):
    meeting_date = meeting_date
    # meeting_date = datetime.now().date()
    
    if not meeting_date:
        meeting_date = datetime.now().date()
        
    log_query = AttendanceLog.query.join(Users).add_columns(
        Users.first_name, Users.middle_name, Users.last_name, Users.state_code, 
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
            'meeting_date': log.meeting_date.strftime('%Y-%m-%d')
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
        "lateness_fine": settings.lateness_fine,
        "monthly_due": settings.monthly_due,
        "account_name": settings.account_name,
        "account_number": settings.account_number,
        "bank_name": settings.bank_name,
        "admin_username": settings.admin_username
    }
    
    return settings_data

def generate_csv(data):
    # Define explicit headers
    # headers = ['First Name', 'Middle Name', 'Last Name', 'State Code', 'Meeting Date']
    
    # Convert data to DataFrame
    df = pd.DataFrame(data)
    # df = pd.DataFrame(data, columns=headers)
    
    # Create a CSV in memory
    csv_data = df.to_csv(index=False)
    return BytesIO(csv_data.encode('utf-8'))

def generate_xlsx(data, meeting_date):
    # Define explicit headers
    # headers = ['First Name', 'Middle Name', 'Last Name', 'State Code', 'Meeting Date']
    
    # Convert data to DataFrame
    df = pd.DataFrame(data)
    # df = pd.DataFrame(data, columns=headers)
    
    # Create an in-memory buffer to store the Excel file
    excel_buffer = BytesIO()
    with pd.ExcelWriter(excel_buffer, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name=f'Attendance - {meeting_date}')
        
    # Move to the start of the buffer before returning
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

    # Table headers
    c.setFont("Helvetica-Bold", 12)
    headers = ["S/N","First Name", "Middle Name", "Last Name", "State Code"]
    x_positions = [50, 100, 200, 300, 450]
    y_position = 700
    for i, header in enumerate(headers):
        c.drawString(x_positions[i], y_position, header)

    # Draw a line under the headers
    c.line(50, y_position - 5, 500, y_position - 5)

    # Table content
    c.setFont("Helvetica", 12)
    y_position -= 30
    for index, record in enumerate(data, start=1):
        if y_position < 50:  # Start a new page if space runs out
            c.showPage()
            c.setFont("Helvetica", 12)
            y_position = 750

        c.drawString(x_positions[0], y_position, str(index))
        c.drawString(x_positions[1], y_position, record['first_name'])
        c.drawString(x_positions[2], y_position, record['middle_name'])
        c.drawString(x_positions[3], y_position, record['last_name'])
        c.drawString(x_positions[4], y_position, record['state_code'])
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
