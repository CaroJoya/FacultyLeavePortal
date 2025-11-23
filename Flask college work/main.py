# main.py - Enhanced Flask application for Faculty Leave Management System
import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import calendar
from datetime import timedelta
import json
from sqlalchemy import text
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import secrets
import random
import string

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///faculty_leaves.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email Configuration - READY FOR APP PASSWORD
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'pcefacultyleaveportal@gmail.com'
app.config['MAIL_PASSWORD'] = 'mepw fogi rdtf eqks'  #  PUT YOUR APP PASSWORD HERE
app.config['MAIL_DEFAULT_SENDER'] = 'PCE Faculty Portal <pcefacultyleaveportal@gmail.com>'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(15), nullable=True)
    designation = db.Column(db.String(50), default='Faculty')
    date_of_joining = db.Column(db.Date, nullable=True)
    employee_id = db.Column(db.String(20), unique=True, nullable=True)

    # Leave balances
    medical_leave_total = db.Column(db.Integer, default=10)
    medical_leave_used = db.Column(db.Integer, default=0)
    medical_leave_left = db.Column(db.Integer, default=10)

    casual_leave_total = db.Column(db.Integer, default=10)
    casual_leave_used = db.Column(db.Integer, default=0)
    casual_leave_left = db.Column(db.Integer, default=10)

    earned_leave_total = db.Column(db.Integer, default=0)
    earned_leave_used = db.Column(db.Integer, default=0)
    earned_leave_left = db.Column(db.Integer, default=0)

    # Overwork tracking
    overwork_hours = db.Column(db.Float, default=0.0)
    pending_overwork_hours = db.Column(db.Float, default=0.0)

    # Password reset fields
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)

    current_year = db.Column(db.Integer, default=lambda: datetime.now().year)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class LeaveRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    leave_type = db.Column(db.String(20), default='full_day')
    leave_category = db.Column(db.String(20), default='casual')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime, nullable=True)
    letter_path = db.Column(db.String(200), nullable=True)
    admin_comments = db.Column(db.Text, nullable=True)

    @property
    def duration(self):
        days = (self.end_date - self.start_date).days + 1
        if self.leave_type == 'half_day':
            return days * 0.5
        return days


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def check_and_migrate_database():
    """Check if database needs migration and apply changes"""
    try:
        db.session.execute(text("SELECT overwork_hours FROM user LIMIT 1"))
        print("Database already has overwork columns in user table")
    except Exception as e:
        print("Database needs migration for overwork system...")
        try:
            db.session.execute(text("ALTER TABLE user ADD COLUMN overwork_hours FLOAT DEFAULT 0.0"))
            db.session.execute(text("ALTER TABLE user ADD COLUMN pending_overwork_hours FLOAT DEFAULT 0.0"))
            db.session.commit()
            print("Successfully added overwork tracking columns to database")
        except Exception as migration_error:
            print(f"Migration failed: {migration_error}")
            db.session.rollback()

    try:
        db.session.execute(text("SELECT admin_comments FROM leave_request LIMIT 1"))
        print("Database already has admin_comments column in leave_request table")
    except Exception as e:
        print("Database needs migration for admin_comments column...")
        try:
            db.session.execute(text("ALTER TABLE leave_request ADD COLUMN admin_comments TEXT"))
            db.session.commit()
            print("Successfully added admin_comments column to leave_request table")
        except Exception as migration_error:
            print(f"Migration failed: {migration_error}")
            db.session.rollback()

    # Check for password reset fields
    try:
        db.session.execute(text("SELECT reset_token FROM user LIMIT 1"))
        print("Database already has password reset columns in user table")
    except Exception as e:
        print("Database needs migration for password reset system...")
        try:
            db.session.execute(text("ALTER TABLE user ADD COLUMN reset_token VARCHAR(100)"))
            db.session.execute(text("ALTER TABLE user ADD COLUMN reset_token_expiration DATETIME"))
            db.session.commit()
            print("Successfully added password reset columns to database")
        except Exception as migration_error:
            print(f"Migration failed: {migration_error}")
            db.session.rollback()

    # Check for new faculty management fields
    try:
        db.session.execute(text("SELECT phone_number FROM user LIMIT 1"))
        print("Database already has faculty management columns")
    except Exception as e:
        print("Database needs migration for faculty management...")
        try:
            db.session.execute(text("ALTER TABLE user ADD COLUMN phone_number VARCHAR(15)"))
            db.session.execute(text("ALTER TABLE user ADD COLUMN designation VARCHAR(50) DEFAULT 'Faculty'"))
            db.session.execute(text("ALTER TABLE user ADD COLUMN date_of_joining DATE"))
            db.session.execute(text("ALTER TABLE user ADD COLUMN employee_id VARCHAR(20)"))
            db.session.commit()
            print("Successfully added faculty management columns to database")
        except Exception as migration_error:
            print(f"Migration failed: {migration_error}")
            db.session.rollback()


def generate_employee_id():
    """Generate unique employee ID"""
    return 'PCE' + ''.join(random.choices(string.digits, k=6))


def generate_random_password():
    """Generate random password for new faculty"""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=8))


def create_admin_user():
    if User.query.filter_by(username='admin').first() is None:
        hashed_pw = generate_password_hash('admin123')
        admin_user = User(
            username='admin',
            password_hash=hashed_pw,
            email='sgovilkar@mes.ac.in',
            full_name='System Administrator',
            department='Administration',
            medical_leave_total=15,
            medical_leave_left=15,
            casual_leave_total=15,
            casual_leave_left=15,
            earned_leave_total=5,
            earned_leave_left=5
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created successfully")


def cleanup_faculty_accounts():
    """Remove all faculty accounts except the legitimate ones and admin"""
    print("Starting faculty account cleanup...")

    legitimate_faculty = [
        'neha.ashok',
        'rashmi.gourkar',
        'sangeetha.selvan',
        'shrushti'
    ]

    all_faculty = User.query.filter(User.username != 'admin').all()
    deleted_count = 0

    for faculty in all_faculty:
        if faculty.username not in legitimate_faculty:
            LeaveRequest.query.filter_by(user_id=faculty.id).delete()
            db.session.delete(faculty)
            deleted_count += 1
            print(f"Deleted non-legitimate faculty account: {faculty.username}")

    db.session.commit()
    print(f"Cleanup completed! Removed {deleted_count} non-legitimate faculty accounts.")
    return deleted_count


def create_faculty_users():
    """Create faculty user accounts for the department"""
    faculty_list = [
        {
            'username': 'neha.ashok',
            'full_name': 'Prof. Neha Ashok',
            'email': 'nehaashok@mes.ac.in',
            'department': 'Computer Science'
        },
        {
            'username': 'rashmi.gourkar',
            'full_name': 'Prof. Rashmi Gourkar',
            'email': 'rashmigourkar@mes.ac.in',
            'department': 'Computer Science'
        },
        {
            'username': 'sangeetha.selvan',
            'full_name': 'Prof. Sangeetha Selvan',
            'email': 'sangeethas@mes.ac.in',
            'department': 'Computer Science'
        },
        {
            'username': 'shrushti',
            'full_name': 'Shrushti',
            'email': 'shrushti24comp@student.mes.ac.in',
            'department': 'Computer Science'
        }
    ]

    for faculty_data in faculty_list:
        if User.query.filter_by(username=faculty_data['username']).first() is None:
            hashed_pw = generate_password_hash('password123')
            faculty = User(
                username=faculty_data['username'],
                password_hash=hashed_pw,
                email=faculty_data['email'],
                full_name=faculty_data['full_name'],
                department=faculty_data['department'],
                medical_leave_total=10,
                medical_leave_left=10,
                casual_leave_total=10,
                casual_leave_left=10,
                earned_leave_total=0,
                earned_leave_left=0
            )
            db.session.add(faculty)
            print(f"Created faculty account: {faculty_data['full_name']}")

    db.session.commit()
    print("All faculty accounts created successfully!")


def update_faculty_emails():
    """Update existing faculty emails to the correct format"""
    print("Starting faculty email update...")

    faculties_to_update = [
        {'name': 'Prof. Neha Ashok', 'email': 'nehaashok@mes.ac.in'},
        {'name': 'Prof. Rashmi Gourkar', 'email': 'rashmigourkar@mes.ac.in'},
        {'name': 'Prof. Sangeetha Selvan', 'email': 'sangeethas@mes.ac.in'}
    ]

    updated_count = 0
    for faculty_data in faculties_to_update:
        faculty = User.query.filter_by(full_name=faculty_data['name']).first()
        if faculty:
            if faculty.email != faculty_data['email']:
                print(f"Updating {faculty_data['name']} from {faculty.email} to {faculty_data['email']}")
                faculty.email = faculty_data['email']
                updated_count += 1
            else:
                print(f"{faculty_data['name']} already has correct email: {faculty.email}")
        else:
            print(f"Faculty {faculty_data['name']} not found!")

    db.session.commit()
    print(f"Email update completed! Updated {updated_count} faculty emails.")
    return updated_count


def validate_password_strength(password):
    """Validate password strength"""
    if len(password) < 6:
        return False, "Password must be at least 6 characters long"
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one number"
    if not any(char.isalpha() for char in password):
        return False, "Password must contain at least one letter"
    return True, "Password is strong"


def send_reset_email(user):
    """Send password reset email to user"""
    try:
        if app.config['MAIL_USERNAME'] == 'pcefacultyleaveportal@gmail.com' and app.config['MAIL_PASSWORD'] == 'YOUR_16_DIGIT_APP_PASSWORD_HERE':
            print("❌ Email not configured - using console fallback")
            token = serializer.dumps(user.email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            print(f"🔗 PASSWORD RESET LINK for {user.email}: {reset_url}")
            return False

        token = serializer.dumps(user.email, salt='password-reset-salt')
        user.reset_token = token
        user.reset_token_expiration = datetime.utcnow() + timedelta(hours=1)
        db.session.commit()

        reset_url = url_for('reset_password', token=token, _external=True)

        msg = Message(
            subject='Password Reset Request - PCE Faculty Portal',
            recipients=[user.email],
            html=f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; }}
                    .content {{ background: #f9f9f9; padding: 20px; }}
                    .button {{ background: #667eea; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; }}
                    .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2>PCE Faculty Portal</h2>
                        <h3>Password Reset Request</h3>
                    </div>
                    <div class="content">
                        <p>Hello <strong>{user.full_name}</strong>,</p>
                        <p>You requested to reset your password for the PCE Faculty Portal.</p>
                        <p>Click the button below to reset your password:</p>
                        <p style="text-align: center;">
                            <a href="{reset_url}" class="button">Reset Your Password</a>
                        </p>
                        <p>This link will expire in 1 hour for security reasons.</p>
                        <p>If you didn't request this reset, please ignore this email.</p>
                    </div>
                    <div class="footer">
                        <p>Pillai College of Engineering (Autonomous)<br>
                        Dr. K. M. Vasudevan Pillai Campus, New Panvel</p>
                    </div>
                </div>
            </body>
            </html>
            """
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


# Create database tables and initialize data
with app.app_context():
    db.create_all()
    check_and_migrate_database()
    create_admin_user()
    cleanup_faculty_accounts()
    create_faculty_users()
    update_faculty_emails()  # NEW: Update existing faculty emails to correct format


def generate_enhanced_leave_letter(user, leave_request, past_leaves, total_medical, total_casual, total_earned):
    """Generate a comprehensive leave letter with past records"""
    if leave_request.leave_type == 'half_day':
        current_duration = ((leave_request.end_date - leave_request.start_date).days + 1) * 0.5
        duration_text = f"{current_duration} days (Half Day)"
    else:
        current_duration = (leave_request.end_date - leave_request.start_date).days + 1
        duration_text = f"{current_duration} days"

    current_date = datetime.now().strftime("%d/%m/%Y")

    past_leaves_table = ""
    for i, past_leave in enumerate(past_leaves[:10]):
        if past_leave.leave_type == 'half_day':
            past_duration = ((past_leave.end_date - past_leave.start_date).days + 1) * 0.5
        else:
            past_duration = (past_leave.end_date - past_leave.start_date).days + 1

        past_leaves_table += f"""
        <tr>
            <td>{i + 1}</td>
            <td>{past_leave.start_date.strftime('%d/%m/%Y')}</td>
            <td>{past_leave.end_date.strftime('%d/%m/%Y')}</td>
            <td>{past_duration}</td>
            <td>{past_leave.leave_category.title()}</td>
            <td>{past_leave.leave_type.replace('_', ' ').title()}</td>
            <td>{past_leave.reason[:50]}{'...' if len(past_leave.reason) > 50 else ''}</td>
        </tr>
        """

    if not past_leaves_table:
        past_leaves_table = """
        <tr>
            <td colspan="7" class="text-center">No previous leave records found for this academic year</td>
        </tr>
        """

    letter_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Leave Application - {user.full_name}</title>
        <style>
            body {{
                font-family: 'Arial', sans-serif;
                margin: 40px;
                line-height: 1.6;
                color: #000;
                background: #fff;
            }}
            .letter-container {{
                max-width: 1000px;
                margin: 0 auto;
                padding: 20px;
                border: 1px solid #ddd;
                background: white;
            }}
            .header {{
                text-align: center;
                margin-bottom: 30px;
                border-bottom: 2px solid #000;
                padding-bottom: 20px;
            }}
            .college-name {{
                font-size: 22px;
                font-weight: bold;
                margin-bottom: 5px;
                color: #2c3e50;
            }}
            .address {{
                font-size: 12px;
                margin-bottom: 10px;
                color: #7f8c8d;
            }}
            .content {{
                margin: 30px 0;
            }}
            .subject {{
                font-weight: bold;
                margin: 20px 0;
                text-decoration: underline;
                font-size: 16px;
            }}
            .footer {{
                margin-top: 50px;
            }}
            .signature {{
                margin-top: 80px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 15px 0;
                font-size: 12px;
            }}
            th, td {{
                padding: 8px;
                border: 1px solid #000;
                text-align: left;
            }}
            th {{
                background-color: #f2f2f2;
                font-weight: bold;
            }}
            .section-title {{
                background: #2c3e50;
                color: white;
                padding: 10px;
                margin: 20px 0 10px 0;
                font-weight: bold;
            }}
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 10px;
                margin: 15px 0;
            }}
            .stat-card {{
                border: 1px solid #ddd;
                padding: 10px;
                text-align: center;
                background: #f8f9fa;
            }}
            .stat-number {{
                font-size: 18px;
                font-weight: bold;
                color: #2c3e50;
            }}
            .print-btn {{
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 10px 20px;
                background: #2c3e50;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                z-index: 1000;
            }}
            @media print {{
                body {{ margin: 0; }}
                .letter-container {{ border: none; padding: 0; }}
                .print-btn {{ display: none; }}
            }}
        </style>
    </head>
    <body>
        <button class="print-btn" onclick="window.print()">🖨️ Print Letter</button>

        <div class="letter-container">
            <div class="header">
                <div class="college-name">Pillai College of Engineering (Autonomous)</div>
                <div class="address">
                    Dr. K. M. Vasudevan Pillai Campus<br>
                    Plot No. 10, Sector 16, New Panvel,<br>
                    Navi Mumbai, Mumbai – 410 206<br>
                    Email: pce@mes.ac.in | Website: www.pce.ac.in
                </div>
            </div>

            <div class="content">
                <p><strong>Date:</strong> {current_date}</p>
                <p><strong>To,</strong><br>
                The Head of Department<br>
                {user.department} Department<br>
                Pillai College of Engineering (Autonomous)<br>
                New Panvel, Navi Mumbai</p>

                <p class="subject">Subject: Application for {leave_request.leave_category.title()} Leave</p>

                <p><strong>Respected Sir/Madam,</strong></p>

                <p>I, <strong>{user.full_name}</strong>, Faculty in the <strong>{user.department}</strong> Department, 
                hereby request your kind permission to grant me {leave_request.leave_category} leave for 
                <strong>{duration_text}</strong> from <strong>{leave_request.start_date.strftime('%d/%m/%Y')}</strong> to 
                <strong>{leave_request.end_date.strftime('%d/%m/%Y')}</strong>.</p>

                <div class="section-title">CURRENT LEAVE APPLICATION DETAILS</div>
                <table>
                    <tr>
                        <td><strong>Faculty Name</strong></td>
                        <td>{user.full_name}</td>
                    </tr>
                    <tr>
                        <td><strong>Department</strong></td>
                        <td>{user.department}</td>
                    </tr>
                    <tr>
                        <td><strong>Employee ID</strong></td>
                        <td>{user.username}</td>
                    </tr>
                    <tr>
                        <td><strong>Leave Category</strong></td>
                        <td>{leave_request.leave_category.title()} Leave</td>
                    </tr>
                    <tr>
                        <td><strong>Leave Type</strong></td>
                        <td>{leave_request.leave_type.replace('_', ' ').title()}</td>
                    </tr>
                    <tr>
                        <td><strong>Duration</strong></td>
                        <td>{leave_request.start_date.strftime('%d/%m/%Y')} to {leave_request.end_date.strftime('%d/%m/%Y')} ({duration_text})</td>
                    </tr>
                    <tr>
                        <td><strong>Reason</strong></td>
                        <td>{leave_request.reason}</td>
                    </tr>
                </table>

                <div class="section-title">LEAVE UTILIZATION SUMMARY (ACADEMIC YEAR {datetime.now().year})</div>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">{total_medical}</div>
                        <div>Medical Leaves Taken</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{total_casual}</div>
                        <div>Casual Leaves Taken</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{total_earned}</div>
                        <div>Earned Leaves Taken</div>
                    </div>
                </div>

                <div class="section-title">PREVIOUS LEAVE HISTORY (LAST 10 RECORDS)</div>
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Start Date</th>
                            <th>End Date</th>
                            <th>Days</th>
                            <th>Category</th>
                            <th>Type</th>
                            <th>Reason</th>
                        </tr>
                    </thead>
                    <tbody>
                        {past_leaves_table}
                    </tbody>
                </table>

                <p>I assure you that I have made necessary arrangements for my academic responsibilities 
                to continue smoothly during my absence. All pending work and classes will be managed 
                as per the department's guidelines.</p>

                <p>Kindly grant me the leave for the mentioned period.</p>

                <div class="signature">
                    <p>Thanking you,</p>
                    <br><br>
                    <p><strong>{user.full_name}</strong><br>
                    Faculty, {user.department}<br>
                    Pillai College of Engineering</p>
                </div>
            </div>

            <div class="footer">
                <hr>
                <div class="section-title">FOR OFFICE USE ONLY</div>
                <table>
                    <tr>
                        <td width="30%"><strong>Leave Approved:</strong></td>
                        <td>
                            □ Yes □ No<br>
                            <strong>Status:</strong> {leave_request.status}<br>
                            {f"<strong>Approved On:</strong> {leave_request.approved_at.strftime('%d/%m/%Y')}" if leave_request.approved_at else ""}
                        </td>
                    </tr>
                    <tr>
                        <td><strong>Remarks:</strong></td>
                        <td>{leave_request.admin_comments if leave_request.admin_comments else "_________________________________"}</td>
                    </tr>
                    <tr>
                        <td><strong>Authorized Signature:</strong></td>
                        <td>_________________________________</td>
                    </tr>
                    <tr>
                        <td><strong>Date:</strong></td>
                        <td>_________________________________</td>
                    </tr>
                </table>
            </div>
        </div>
    </body>
    </html>
    """

    return letter_html


# Routes
@app.route('/welcome')
def welcome():
    return render_template('welcome.html')


@app.route('/')
def index():
    return redirect(url_for('welcome'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_type = request.form.get('user_type', 'faculty')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            if user_type == 'admin' and username != 'admin':
                flash('Invalid admin credentials')
                return render_template('login.html')
            elif user_type == 'faculty' and username == 'admin':
                flash('Please select "Administrator" for admin login')
                return render_template('login.html')

            login_user(user)

            if user_type == 'admin' and username == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))

        flash('Invalid username or password')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


@app.route('/dashboard')
@login_required
def dashboard():
    pending_requests = LeaveRequest.query.filter_by(user_id=current_user.id, status='Pending').count()
    approved_requests = LeaveRequest.query.filter_by(user_id=current_user.id, status='Approved').count()
    return render_template('dashboard.html', pending=pending_requests, approved=approved_requests)


@app.route('/request_leave', methods=['GET', 'POST'])
@login_required
def request_leave():
    if request.method == 'POST':
        start_date_str = request.form['start_date']
        reason = request.form['reason']
        leave_type = request.form.get('leave_type', 'full_day')
        leave_category = request.form.get('leave_category', 'casual')

        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()

            # For half-day leaves, end date must be same as start date
            if leave_type == 'half_day':
                # Use the hidden field if available, otherwise use start_date
                end_date_str = request.form.get('end_date_hidden', start_date_str)
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
                duration = 0.5
            else:
                end_date_str = request.form.get('end_date', start_date_str)
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
                duration = (end_date - start_date).days + 1

            # Additional server-side validation for half-day leaves
            if leave_type == 'half_day' and start_date != end_date:
                flash('Invalid request: For half-day leaves, start and end date must be the same.')
                return render_template('request_leave.html', user=current_user)

            if end_date < start_date:
                flash('End date must be after start date')
                return render_template('request_leave.html', user=current_user)

            # Check balance
            if leave_category == 'medical' and duration > current_user.medical_leave_left:
                flash(f'Insufficient medical leaves. You have {current_user.medical_leave_left} days left.')
                return render_template('request_leave.html', user=current_user)
            elif leave_category == 'casual' and duration > current_user.casual_leave_left:
                flash(f'Insufficient casual leaves. You have {current_user.casual_leave_left} days left.')
                return render_template('request_leave.html', user=current_user)
            elif leave_category == 'earned' and duration > current_user.earned_leave_left:
                flash(f'Insufficient earned leaves. You have {current_user.earned_leave_left} days left.')
                return render_template('request_leave.html', user=current_user)

            # Create leave request
            leave = LeaveRequest(
                user_id=current_user.id,
                start_date=start_date,
                end_date=end_date,
                reason=reason,
                leave_type=leave_type,
                leave_category=leave_category
            )
            db.session.add(leave)
            db.session.commit()

            flash('Leave request submitted successfully. Awaiting approval.')
            return redirect(url_for('dashboard'))
        except ValueError as e:
            flash(f'Invalid date format: {str(e)}')
        except KeyError as e:
            flash(f'Missing form field: {str(e)}. Please fill all required fields.')

    return render_template('request_leave.html', user=current_user)


@app.route('/add_overwork', methods=['POST'])
@login_required
def add_overwork():
    hours = request.form.get('hours', type=float)
    if hours and hours > 0:
        current_user.pending_overwork_hours += hours

        if current_user.pending_overwork_hours >= 5:
            full_days = int(current_user.pending_overwork_hours // 8)
            remaining_hours = current_user.pending_overwork_hours % 8

            half_days = 0
            if remaining_hours >= 5:
                half_days = 1
                remaining_hours -= 5

            total_earned_days = full_days + (half_days * 0.5)
            converted_hours = (full_days * 8) + (half_days * 5)

            current_user.earned_leave_left += total_earned_days
            current_user.earned_leave_total += total_earned_days
            current_user.overwork_hours += converted_hours
            current_user.pending_overwork_hours -= converted_hours

            db.session.commit()

            flash(
                f'✅ Added {hours} hours! Automatically converted {converted_hours} hours to {total_earned_days} earned leave days!',
                'success')

            if current_user.pending_overwork_hours > 0:
                flash(f'📊 You still have {current_user.pending_overwork_hours} hours pending conversion', 'info')
        else:
            db.session.commit()
            needed_hours = 5 - current_user.pending_overwork_hours
            flash(
                f'⏳ Added {hours} overwork hours. Total pending: {current_user.pending_overwork_hours} hours. Need {needed_hours} more hours to convert.',
                'info')
    else:
        flash('❌ Please enter valid hours', 'error')

    return redirect(url_for('dashboard'))


@app.route('/convert_overwork', methods=['POST'])
@login_required
def convert_overwork():
    if current_user.pending_overwork_hours >= 5:
        full_days = int(current_user.pending_overwork_hours // 8)
        remaining_hours = current_user.pending_overwork_hours % 8

        half_days = 0
        if remaining_hours >= 5:
            half_days = 1
            remaining_hours -= 5

        total_earned_days = full_days + (half_days * 0.5)
        converted_hours = (full_days * 8) + (half_days * 5)

        current_user.earned_leave_left += total_earned_days
        current_user.earned_leave_total += total_earned_days
        current_user.overwork_hours += converted_hours
        current_user.pending_overwork_hours -= converted_hours

        db.session.commit()

        flash(f'🎉 Converted {converted_hours} hours to {total_earned_days} earned leave days!', 'success')

        if current_user.pending_overwork_hours > 0:
            flash(f'📊 You still have {current_user.pending_overwork_hours} hours pending conversion', 'info')
    else:
        needed_hours = 5 - current_user.pending_overwork_hours
        flash(f'❌ You need {needed_hours} more hours to convert (minimum 5 hours required)', 'error')

    return redirect(url_for('dashboard'))


@app.route('/stats')
@login_required
def stats():
    now = datetime.now()
    current_year = now.year

    leaves = LeaveRequest.query.filter(
        LeaveRequest.user_id == current_user.id,
        LeaveRequest.status == 'Approved',
        db.extract('year', LeaveRequest.start_date) == current_year
    ).all()

    calendar_data = {}
    for leave in leaves:
        current_date = leave.start_date
        while current_date <= leave.end_date:
            year = current_date.year
            month = current_date.month
            day = current_date.day

            if year not in calendar_data:
                calendar_data[year] = {}
            if month not in calendar_data[year]:
                calendar_data[year][month] = []
            if day not in calendar_data[year][month]:
                calendar_data[year][month].append(day)
            current_date += timedelta(days=1)

    monthly_data = {month: 0 for month in range(1, 13)}
    for leave in leaves:
        current_date = leave.start_date
        while current_date <= leave.end_date:
            if current_date.year == current_year:
                month = current_date.month
                if hasattr(leave, 'leave_type') and leave.leave_type == 'half_day':
                    monthly_data[month] += 0.5
                else:
                    monthly_data[month] += 1
            current_date += timedelta(days=1)

    months = list(range(1, 13))
    month_names = [calendar.month_abbr[i] for i in months]
    leave_days = [monthly_data[month] for month in months]

    return render_template('stats.html',
                           calendar_data=calendar_data,
                           current_year=current_year,
                           month_names=json.dumps(month_names),
                           leave_days=json.dumps(leave_days),
                           calendar=calendar)


@app.route('/status')
@login_required
def status():
    requests = LeaveRequest.query.filter_by(user_id=current_user.id).order_by(LeaveRequest.created_at.desc()).all()
    requests_with_duration = []
    for req in requests:
        if hasattr(req, 'leave_type') and req.leave_type == 'half_day':
            duration = ((req.end_date - req.start_date).days + 1) * 0.5
        else:
            duration = (req.end_date - req.start_date).days + 1
        requests_with_duration.append((req, duration))
    return render_template('status.html', requests_with_duration=requests_with_duration)


@app.route('/history')
@login_required
def history():
    search_start_date = request.args.get('search_start_date')
    search_end_date = request.args.get('search_end_date')

    query = LeaveRequest.query.filter_by(user_id=current_user.id, status='Approved')

    if search_start_date:
        try:
            start_date = datetime.strptime(search_start_date, '%Y-%m-%d').date()
            query = query.filter(LeaveRequest.start_date >= start_date)
        except ValueError:
            flash('Invalid start date format')
    if search_end_date:
        try:
            end_date = datetime.strptime(search_end_date, '%Y-%m-%d').date()
            query = query.filter(LeaveRequest.end_date <= end_date)
        except ValueError:
            flash('Invalid end date format')

    history = query.order_by(LeaveRequest.start_date.desc()).all()
    history_with_duration = []
    for h in history:
        if hasattr(h, 'leave_type') and h.leave_type == 'half_day':
            duration = ((h.end_date - h.start_date).days + 1) * 0.5
        else:
            duration = (h.end_date - h.start_date).days + 1
        history_with_duration.append((h, duration))

    return render_template('history.html', history_with_duration=history_with_duration)


@app.route('/view_letter/<int:request_id>')
@login_required
def view_letter(request_id):
    leave_request = LeaveRequest.query.get_or_404(request_id)

    if leave_request.user_id != current_user.id and current_user.username != 'admin':
        flash('Access denied.')
        return redirect(url_for('dashboard'))

    faculty = User.query.get(leave_request.user_id)

    current_year = datetime.now().year
    past_leaves = LeaveRequest.query.filter(
        LeaveRequest.user_id == faculty.id,
        LeaveRequest.status == 'Approved',
        db.extract('year', LeaveRequest.start_date) == current_year
    ).order_by(LeaveRequest.start_date.desc()).all()

    total_medical = sum(leave.duration for leave in past_leaves if leave.leave_category == 'medical')
    total_casual = sum(leave.duration for leave in past_leaves if leave.leave_category == 'casual')
    total_earned = sum(leave.duration for leave in past_leaves if leave.leave_category == 'earned')

    letter_html = generate_enhanced_leave_letter(
        faculty,
        leave_request,
        past_leaves,
        total_medical,
        total_casual,
        total_earned
    )

    return letter_html


@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not check_password_hash(current_user.password_hash, current_password):
            flash('Current password is incorrect', 'password_change')
            return redirect(url_for('profile'))

        if new_password != confirm_password:
            flash('New password and confirmation password do not match', 'password_change')
            return redirect(url_for('profile'))

        is_strong, message = validate_password_strength(new_password)
        if not is_strong:
            flash(message, 'password_change')
            return redirect(url_for('profile'))

        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        flash('Password changed successfully!', 'password_change')
        return redirect(url_for('profile'))


# NEW: Faculty Self Password Reset Route
@app.route('/reset_my_password', methods=['POST'])
@login_required
def reset_my_password():
    """Allow faculty to reset their own password"""
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Verify current password
        if not check_password_hash(current_user.password_hash, current_password):
            flash('❌ Current password is incorrect', 'error')
            return redirect(url_for('profile'))

        # Check if new passwords match
        if new_password != confirm_password:
            flash('❌ New password and confirmation password do not match', 'error')
            return redirect(url_for('profile'))

        # Validate password strength
        is_strong, message = validate_password_strength(new_password)
        if not is_strong:
            flash(f'❌ {message}', 'error')
            return redirect(url_for('profile'))

        # Update password
        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()

        flash('✅ Password reset successfully! Please login with your new password.', 'success')

        # Logout user after password change for security
        logout_user()
        return redirect(url_for('login'))

    return redirect(url_for('profile'))


# Password Reset Routes
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            try:
                if send_reset_email(user):
                    flash('📧 Password reset instructions have been sent to your email.', 'info')
                else:
                    flash('📧 Email service not configured. Check console for reset link.', 'info')
            except Exception as e:
                flash('❌ Error sending email. Please try again later.', 'error')
                print(f"Email error: {e}")
        else:
            flash('❌ No account found with that email address.', 'error')

        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('❌ Invalid or expired reset link.', 'error')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email, reset_token=token).first()
    if not user or user.reset_token_expiration < datetime.utcnow():
        flash('❌ Invalid or expired reset link.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('❌ Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)

        is_strong, message = validate_password_strength(new_password)
        if not is_strong:
            flash(f'❌ {message}', 'error')
            return render_template('reset_password.html', token=token)

        user.password_hash = generate_password_hash(new_password)
        user.reset_token = None
        user.reset_token_expiration = None
        db.session.commit()

        flash('✅ Password updated successfully! You can now login with your new password.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


# Admin Routes
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.username != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))

    pending_count = LeaveRequest.query.filter_by(status='Pending').count()
    total_faculty = User.query.filter(User.username != 'admin').count()
    approved_this_month = LeaveRequest.query.filter(
        LeaveRequest.status == 'Approved',
        db.extract('month', LeaveRequest.approved_at) == datetime.now().month,
        db.extract('year', LeaveRequest.approved_at) == datetime.now().year
    ).count()

    return render_template('admin_dashboard.html',
                           user=current_user,
                           pending_count=pending_count,
                           total_faculty=total_faculty,
                           approved_this_month=approved_this_month)


@app.route('/admin/pending_requests')
@login_required
def admin_pending_requests():
    if current_user.username != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))

    pending_requests = db.session.query(LeaveRequest, User).join(
        User, LeaveRequest.user_id == User.id
    ).filter(
        LeaveRequest.status == 'Pending'
    ).order_by(LeaveRequest.created_at.desc()).all()

    return render_template('admin_pending_requests.html',
                           pending_requests=pending_requests,
                           user=current_user)


@app.route('/admin/request_details/<int:request_id>')
@login_required
def admin_request_details(request_id):
    if current_user.username != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))

    leave_request = db.session.query(LeaveRequest, User).join(
        User, LeaveRequest.user_id == User.id
    ).filter(LeaveRequest.id == request_id).first()

    if not leave_request:
        flash('Leave request not found.')
        return redirect(url_for('admin_pending_requests'))

    request_obj, faculty = leave_request
    leave_history = LeaveRequest.query.filter_by(
        user_id=faculty.id,
        status='Approved'
    ).order_by(LeaveRequest.start_date.desc()).limit(10).all()

    medical_taken = sum([req.duration for req in LeaveRequest.query.filter_by(
        user_id=faculty.id, status='Approved', leave_category='medical'
    ).all()])

    casual_taken = sum([req.duration for req in LeaveRequest.query.filter_by(
        user_id=faculty.id, status='Approved', leave_category='casual'
    ).all()])

    earned_taken = sum([req.duration for req in LeaveRequest.query.filter_by(
        user_id=faculty.id, status='Approved', leave_category='earned'
    ).all()])

    if request_obj.leave_type == 'half_day':
        current_duration = ((request_obj.end_date - request_obj.start_date).days + 1) * 0.5
    else:
        current_duration = (request_obj.end_date - request_obj.start_date).days + 1

    return render_template('admin_request_details.html',
                           request=request_obj,
                           faculty=faculty,
                           leave_history=leave_history,
                           medical_taken=medical_taken,
                           casual_taken=casual_taken,
                           earned_taken=earned_taken,
                           current_duration=current_duration)


@app.route('/admin/approve_request/<int:request_id>', methods=['POST'])
@login_required
def admin_approve_request(request_id):
    if current_user.username != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))

    leave_request = LeaveRequest.query.get_or_404(request_id)
    admin_comments = request.form.get('admin_comments', '')

    if leave_request.status != 'Pending':
        flash('This request has already been processed.')
        return redirect(url_for('admin_pending_requests'))

    leave_request.status = 'Approved'
    leave_request.approved_at = datetime.utcnow()
    leave_request.admin_comments = admin_comments

    if leave_request.leave_type == 'half_day':
        duration = ((leave_request.end_date - leave_request.start_date).days + 1) * 0.5
    else:
        duration = (leave_request.end_date - leave_request.start_date).days + 1

    faculty = User.query.get(leave_request.user_id)
    if leave_request.leave_category == 'medical':
        faculty.medical_leave_used += duration
        faculty.medical_leave_left -= duration
    elif leave_request.leave_category == 'casual':
        faculty.casual_leave_used += duration
        faculty.casual_leave_left -= duration
    elif leave_request.leave_category == 'earned':
        faculty.earned_leave_used += duration
        faculty.earned_leave_left -= duration

    db.session.commit()

    flash('Leave request approved successfully!')
    return redirect(url_for('admin_pending_requests'))


@app.route('/admin/reject_request/<int:request_id>', methods=['POST'])
@login_required
def admin_reject_request(request_id):
    if current_user.username != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))

    leave_request = LeaveRequest.query.get_or_404(request_id)
    admin_comments = request.form.get('admin_comments', '')

    if leave_request.status != 'Pending':
        flash('This request has already been processed.')
        return redirect(url_for('admin_pending_requests'))

    leave_request.status = 'Rejected'
    leave_request.admin_comments = admin_comments
    db.session.commit()
    flash('Leave request rejected.')
    return redirect(url_for('admin_pending_requests'))


@app.route('/admin/faculty_list')
@login_required
def admin_faculty_list():
    if current_user.username != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))

    faculty_list = User.query.filter(User.username != 'admin').all()
    faculty_stats = []
    for faculty in faculty_list:
        approved_leaves = LeaveRequest.query.filter_by(
            user_id=faculty.id, status='Approved'
        ).count()

        pending_leaves = LeaveRequest.query.filter_by(
            user_id=faculty.id, status='Pending'
        ).count()

        faculty_stats.append({
            'faculty': faculty,
            'approved_leaves': approved_leaves,
            'pending_leaves': pending_leaves
        })

    return render_template('admin_faculty_list.html',
                           faculty_stats=faculty_stats,
                           user=current_user)


@app.route('/admin/cleanup_faculty', methods=['POST'])
@login_required
def admin_cleanup_faculty():
    if current_user.username != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))

    deleted_count = cleanup_faculty_accounts()
    create_faculty_users()

    flash(
        f'Faculty cleanup completed! Removed {deleted_count} non-legitimate accounts and ensured all legitimate accounts exist.',
        'success')
    return redirect(url_for('admin_faculty_list'))


# NEW: Faculty Management Routes
@app.route('/admin/add_faculty', methods=['GET', 'POST'])
@login_required
def admin_add_faculty():
    if current_user.username != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            full_name = request.form['full_name']
            email = request.form['email']
            department = request.form['department']
            phone_number = request.form.get('phone_number', '')
            designation = request.form.get('designation', 'Faculty')
            date_of_joining_str = request.form.get('date_of_joining')

            username = email.split('@')[0].lower()
            temp_password = generate_random_password()
            employee_id = generate_employee_id()

            if User.query.filter_by(email=email).first():
                flash('❌ Faculty with this email already exists!', 'error')
                return render_template('admin_add_faculty.html')

            if User.query.filter_by(username=username).first():
                username = f"{username}{random.randint(100, 999)}"

            date_of_joining = None
            if date_of_joining_str:
                date_of_joining = datetime.strptime(date_of_joining_str, '%Y-%m-%d').date()

            hashed_pw = generate_password_hash(temp_password)
            faculty = User(
                username=username,
                password_hash=hashed_pw,
                email=email,
                full_name=full_name,
                department=department,
                phone_number=phone_number,
                designation=designation,
                date_of_joining=date_of_joining,
                employee_id=employee_id,
                medical_leave_total=10,
                medical_leave_left=10,
                casual_leave_total=10,
                casual_leave_left=10,
                earned_leave_total=0,
                earned_leave_left=0
            )

            db.session.add(faculty)
            db.session.commit()

            login_url = url_for('login', _external=True)
            whatsapp_message = f"""Welcome to PCE Faculty Portal!

👤 Your account has been created:
🏫 Institution: Pillai College of Engineering
📧 Email: {email}
👤 Username: {username}
🔑 Temporary Password: {temp_password}
🔗 Login URL: {login_url}

⚠️ Please change your password after first login.
📞 Contact admin for any assistance."""

            flash('✅ Faculty account created successfully!', 'success')
            return render_template('admin_faculty_created.html',
                                   faculty=faculty,
                                   temp_password=temp_password,
                                   whatsapp_message=whatsapp_message,
                                   login_url=login_url)

        except Exception as e:
            db.session.rollback()
            flash(f'❌ Error creating faculty account: {str(e)}', 'error')

    return render_template('admin_add_faculty.html')


@app.route('/admin/delete_faculty/<int:faculty_id>', methods=['POST'])
@login_required
def admin_delete_faculty(faculty_id):
    if current_user.username != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))

    if faculty_id == current_user.id:
        flash('❌ You cannot delete your own account!', 'error')
        return redirect(url_for('admin_faculty_list'))

    faculty = User.query.get_or_404(faculty_id)

    try:
        LeaveRequest.query.filter_by(user_id=faculty_id).delete()
        db.session.delete(faculty)
        db.session.commit()

        flash(f'✅ Faculty account for {faculty.full_name} deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'❌ Error deleting faculty account: {str(e)}', 'error')

    return redirect(url_for('admin_faculty_list'))


@app.route('/admin/reset_faculty_password/<int:faculty_id>', methods=['POST'])
@login_required
def admin_reset_faculty_password(faculty_id):
    if current_user.username != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))

    faculty = User.query.get_or_404(faculty_id)

    try:
        temp_password = generate_random_password()
        faculty.password_hash = generate_password_hash(temp_password)
        db.session.commit()

        flash(f'✅ Password reset for {faculty.full_name}. New temporary password: {temp_password}', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'❌ Error resetting password: {str(e)}', 'error')

    return redirect(url_for('admin_faculty_list'))


if __name__ == '__main__':
    app.run(debug=True)