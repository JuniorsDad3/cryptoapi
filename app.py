import os
import io
import uuid
import json
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, jsonify
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from google.oauth2 import service_account
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
from flask import g
from security import rate_limiter, file_encryptor, security_audit
from pricing import BillingManager, PricingCalculator


# Import enterprise modules
from security import FileEncryptor, SecurityAudit, RateLimiter
from pricing import PricingCalculator, BillingManager

# -------------------------------
# Load Environment Variables
# -------------------------------
load_dotenv()

# -------------------------------
# Initialize Flask App
# -------------------------------
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'enterprise-secret-key-change-in-production')
billing_mgr = BillingManager()
pricing_calculator = PricingCalculator()

app.billing_mgr = billing_mgr
app.pricing_calculator = pricing_calculator

# -------------------------------
# Enterprise Configuration
# -------------------------------

# Import enterprise modules
from security import FileEncryptor, SecurityAudit, RateLimiter
from pricing import PricingCalculator, BillingManager

# -------------------------------
# Load Environment Variables
# -------------------------------
load_dotenv()

# -------------------------------
# Initialize Flask App
# -------------------------------
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'enterprise-secret-key-change-in-production')
billing_mgr = BillingManager()
pricing_calculator = PricingCalculator()

app.billing_mgr = billing_mgr
app.pricing_calculator = pricing_calculator

# -------------------------------
# Enterprise Configuration
# -------------------------------
class EnterpriseConfig:
    # Security
    UPLOAD_FOLDER = '/tmp/uploads'
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    SESSION_TIMEOUT_MINUTES = 480  # 8 hours
    
    # Allowed file types for enterprise use
    ALLOWED_EXTENSIONS = {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx',
        'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar', '7z', 'tar', 'gz',
        'mp4', 'mp3', 'avi', 'mov', 'wav', 'flac', 'aac',
        'html', 'css', 'js', 'py', 'java', 'cpp', 'c', 'php', 'rb',
        'sql', 'json', 'xml', 'csv', 'tsv', 'log'
    }
    
    # Enterprise Features
    GOOGLE_DRIVE_FOLDER_NAME = 'EnterpriseCloudStorage'
    COMPANY_NAME = os.getenv('COMPANY_NAME', 'iTradeAfrika')
    SUPPORT_EMAIL = os.getenv('SUPPORT_EMAIL', 'itradeafrika@gmail.com')
    SUPPORT_PHONE = os.getenv('SUPPORT_PHONE', '+27-555-itradeafrika')

    PAYMENT_LINKS = {
        'R29.99': 'https://pay.yoco.com/r/4qLlGx',
        'R99.99': 'https://pay.yoco.com/r/mMqNkV',
        'R299.99': 'https://pay.yoco.com/r/mdvlMl'
    }
    
    # Compliance
    AUDIT_RETENTION_DAYS = 2555  # 7 years
    MAX_LOGIN_ATTEMPTS = 5
    PASSWORD_MIN_LENGTH = 8

app.config.from_object(EnterpriseConfig)

# -------------------------------
# Initialize Enterprise Modules
# -------------------------------
try:
    # Security modules
    encryptor = FileEncryptor()
    security_audit = SecurityAudit()
    rate_limiter = RateLimiter()
    
    # Business modules
    pricing_calc = PricingCalculator()
    billing_mgr = BillingManager()
    
    print("✅ Enterprise modules initialized successfully")
    
except Exception as e:
    print(f"❌ Enterprise module initialization failed: {e}")

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# -------------------------------
# Google Drive Setup
# -------------------------------
SERVICE_ACCOUNT_FILE = os.getenv('GOOGLE_SERVICE_ACCOUNT_JSON', 'credentials.json')
SCOPES = ['https://www.googleapis.com/auth/drive']

try:
    credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES
    )
    drive_service = build('drive', 'v3', credentials=credentials)
    
    # Create enterprise folder structure
    app_folder_id = None
    results = drive_service.files().list(
        q=f"name='{app.config['GOOGLE_DRIVE_FOLDER_NAME']}' and mimeType='application/vnd.google-apps.folder'",
        spaces='drive'
    ).execute()
    folders = results.get('files', [])
    
    if not folders:
        folder_metadata = {
            'name': app.config['GOOGLE_DRIVE_FOLDER_NAME'],
            'mimeType': 'application/vnd.google-apps.folder',
            'appProperties': {
                'enterprise_app': 'true',
                'created': datetime.utcnow().isoformat()
            }
        }
        folder = drive_service.files().create(body=folder_metadata, fields='id').execute()
        app_folder_id = folder.get('id')
        print(f"✅ Created enterprise folder: {app.config['GOOGLE_DRIVE_FOLDER_NAME']}")
    else:
        app_folder_id = folders[0]['id']
        print(f"✅ Found existing enterprise folder: {app.config['GOOGLE_DRIVE_FOLDER_NAME']}")

except Exception as e:
    print(f"❌ Error initializing Google Drive: {e}")
    drive_service = None
    app_folder_id = None

# -------------------------------
# Enterprise Data Storage (In-memory for demo - use DB in production)
# -------------------------------
enterprise_users = {}
user_sessions = {}
login_attempts = {}
file_metadata = {}
user_folder_cache = {}

# -------------------------------
# Enhanced Helper Functions
# -------------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def validate_password(password):
    """Enterprise password validation"""
    if len(password) < app.config['PASSWORD_MIN_LENGTH']:
        return False, f"Password must be at least {app.config['PASSWORD_MIN_LENGTH']} characters"
    
    # Add more validation rules as needed
    return True, "Valid"

def get_user_folder_id(user_id):
    """Get or create user-specific encrypted folder"""
    if not drive_service:
        return None

    if user_id in user_folder_cache:
        return user_folder_cache[user_id]

    folder_name = f"user_{user_id}_encrypted"
    query = f"name='{folder_name}' and '{app_folder_id}' in parents and mimeType='application/vnd.google-apps.folder'"
    
    try:
        results = drive_service.files().list(q=query, spaces='drive').execute()
        folders = results.get('files', [])

        if folders:
            folder_id = folders[0]['id']
        else:
            folder_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder',
                'parents': [app_folder_id],
                'appProperties': {
                    'user_id': user_id,
                    'encrypted': 'true',
                    'created': datetime.utcnow().isoformat()
                }
            }
            folder = drive_service.files().create(body=folder_metadata, fields='id').execute()
            folder_id = folder.get('id')

        user_folder_cache[user_id] = folder_id
        return folder_id
        
    except Exception as e:
        print(f"Error getting user folder: {e}")
        return None

def upload_to_drive(file_path, filename, user_id, file_type='general'):
    """Enhanced upload with enterprise features + debug"""
    if not drive_service:
        print("DEBUG: drive_service is None")
        return None, 0

    user_folder_id = get_user_folder_id(user_id)
    print(f"DEBUG: user_folder_id = {user_folder_id}")
    if not user_folder_id:
        print("DEBUG: Failed to get/create user folder")
        return None, 0

    try:
        # Encrypt file before upload
        print(f"DEBUG: Encrypting file {file_path}")
        encrypted_path = encryptor.encrypt_file(file_path)
        print(f"DEBUG: Encrypted file path = {encrypted_path}")

        # Create secure filename
        secure_filename = f"{uuid.uuid4().hex}_{encryptor.hash_filename(filename)}"
        print(f"DEBUG: secure_filename = {secure_filename}")

        file_metadata = {
            'name': secure_filename,
            'parents': [user_folder_id],
            'appProperties': {
                'user_id': user_id,
                'original_filename': filename,
                'file_type': file_type,
                'encrypted': 'true',
                'upload_timestamp': datetime.utcnow().isoformat(),
                'version': '1.0'
            }
        }

        media = MediaFileUpload(encrypted_path, resumable=True)
        file = drive_service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id, size, createdTime'
        ).execute()

        print(f"DEBUG: Uploaded file_id = {file.get('id')} size = {file.get('size', 0)}")

        # Log security event
        security_audit.log_security_event(
            'FILE_UPLOAD', user_id,
            {'filename': filename, 'file_id': file.get('id'), 'size': file.get('size', 0)}
        )

        # Track billing usage
        billing_mgr.track_usage(user_id, 'storage', int(file.get('size', 0)))
        billing_mgr.track_usage(user_id, 'upload', 1)

        return file.get('id'), int(file.get('size', 0))

    except Exception as e:
        print(f"UPLOAD ERROR: {e}")
        security_audit.log_security_event('UPLOAD_ERROR', user_id, {'error': str(e)})
        return None, 0

    finally:
        if 'encrypted_path' in locals() and os.path.exists(encrypted_path):
            os.remove(encrypted_path)
            print(f"DEBUG: Deleted temp encrypted file {encrypted_path}")

def download_from_drive(file_id, user_id):
    """Secure download with enterprise features"""
    if not drive_service:
        return None
    
    try:
        # Verify user has access to this file
        file_info = get_file_metadata(file_id)
        if not file_info or file_info.get('user_id') != user_id:
            security_audit.log_security_event('UNAUTHORIZED_DOWNLOAD', user_id, {'file_id': file_id})
            return None
        
        # Download from Drive
        request_download = drive_service.files().get_media(fileId=file_id)
        file_stream = io.BytesIO()
        downloader = MediaIoBaseDownload(file_stream, request_download)
        
        done = False
        while not done:
            status, done = downloader.next_chunk()
        
        file_stream.seek(0)
        
        # Decrypt the file
        decrypted_stream = encryptor.decrypt_stream(file_stream)
        
        # Log security event and track usage
        security_audit.log_security_event('FILE_DOWNLOAD', user_id, {'file_id': file_id})
        billing_mgr.track_usage(user_id, 'download', 1)
        
        return decrypted_stream
        
    except Exception as e:
        print(f"Download error: {e}")
        security_audit.log_security_event('DOWNLOAD_ERROR', user_id, {'error': str(e)})
        return None

def get_file_metadata(file_id):
    """Get file metadata with error handling"""
    if not drive_service:
        return None
    
    try:
        file = drive_service.files().get(
            fileId=file_id, 
            fields='id, name, size, createdTime, appProperties'
        ).execute()
        return file.get('appProperties', {})
    except:
        return None

def get_user_files(user_id):
    """Get user files with enhanced metadata"""
    if not drive_service:
        return []
    
    user_folder_id = get_user_folder_id(user_id)
    if not user_folder_id:
        return []
    
    try:
        query = f"'{user_folder_id}' in parents and trashed=false"
        results = drive_service.files().list(
            q=query, 
            fields='files(id, name, size, createdTime, appProperties)',
            orderBy='createdTime desc'
        ).execute()
        
        files = []
        for file in results.get('files', []):
            props = file.get('appProperties', {})
            files.append({
                'id': file['id'],
                'filename': props.get('original_filename', 'Unknown'),
                'file_type': props.get('file_type', 'general'),
                'size': int(file.get('size', 0)),
                'uploaded_at': file['createdTime'],
                'encrypted': props.get('encrypted', 'false') == 'true'
            })
        
        return files
        
    except Exception as e:
        print(f"Error getting user files: {e}")
        return []

# -------------------------------
# Enhanced Authentication Decorator
# -------------------------------
def enterprise_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Authentication required. Please log in.', 'warning')
            return redirect(url_for('login'))
        
        # Check session timeout
        user_id = session['user_id']
        if user_id in user_sessions:
            last_activity = user_sessions[user_id]
            timeout_delta = timedelta(minutes=app.config['SESSION_TIMEOUT_MINUTES'])
            if datetime.utcnow() - last_activity > timeout_delta:
                session.clear()
                security_audit.log_security_event('SESSION_TIMEOUT', user_id)
                flash('Session expired. Please log in again.', 'info')
                return redirect(url_for('login'))
        
        # Update activity timestamp
        user_sessions[user_id] = datetime.utcnow()
        
        return f(*args, **kwargs)
    return decorated_function

# -------------------------------
# Enhanced Routes
# -------------------------------
@app.route('/')
def index():
    """Enterprise landing page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    # Get pricing tiers for display
    pricing_tiers = pricing_calculator.get_pricing_tiers()
    return render_template('index.html', config=app.config, pricing_tiers=pricing_tiers)

@app.route('/register', methods=['GET', 'POST'])
@rate_limiter.limit(max_attempts=10, window_seconds=60, by='ip')
def register():
    """Enterprise registration with enhanced validation"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        company = request.form.get('company', '')
        
        # Enhanced validation
        if not all([username, email, password]):
            flash('All fields are required.', 'danger')
            return render_template('register.html', config=app.config)
        
        # Password validation
        is_valid, msg = validate_password(password)
        if not is_valid:
            flash(msg, 'danger')
            return render_template('register.html', config=app.config)
        
        # Check for existing user
        for uid, user in enterprise_users.items():
            if user['email'] == email or user['username'] == username:
                flash('Email or username already exists.', 'danger')
                return render_template('register.html', config=app.config)
        
        # Create enterprise user
        user_id = str(uuid.uuid4())
        enterprise_users[user_id] = {
            'username': username,
            'email': email,
            'company': company,
            'password_hash': generate_password_hash(password),
            'created_at': datetime.utcnow().isoformat(),
            'tier': 'starter',  # Default tier
            'status': 'active'
        }
        
        # Initialize billing
        billing_mgr.create_account(user_id, 'starter')
        
        security_audit.log_security_event('USER_REGISTERED', user_id, {'company': company})
        flash('Enterprise account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', config=app.config)

@app.route('/login', methods=['GET', 'POST'])
@rate_limiter.limit("5 per minute")
def login():
    """Enhanced login with security features"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        
        # Check login attempts
        attempts = login_attempts.get(email, 0)
        if attempts >= app.config['MAX_LOGIN_ATTEMPTS']:
            flash('Too many login attempts. Please try again later.', 'danger')
            security_audit.log_security_event('LOGIN_LOCKOUT', None, {'email': email})
            return render_template('login.html', config=app.config)
        
        # Find user
        user_id = None
        user_data = None
        for uid, user in enterprise_users.items():
            if user['email'] == email:
                user_id = uid
                user_data = user
                break
        
        # Validate credentials
        if user_id and user_data and check_password_hash(user_data['password_hash'], password):
            # Successful login
            session['user_id'] = user_id
            session['username'] = user_data['username']
            session['user_tier'] = user_data['tier']
            session['company'] = user_data.get('company', '')
            
            user_sessions[user_id] = datetime.utcnow()
            login_attempts[email] = 0  # Reset attempts
            
            security_audit.log_security_event('LOGIN_SUCCESS', user_id)
            flash(f'Welcome back, {user_data["username"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Failed login
            login_attempts[email] = attempts + 1
            remaining_attempts = app.config['MAX_LOGIN_ATTEMPTS'] - attempts - 1
            
            security_audit.log_security_event('LOGIN_FAILED', None, {'email': email})
            flash(f'Invalid credentials. {remaining_attempts} attempts remaining.', 'danger')
    
    return render_template('login.html', config=app.config)

@app.route('/logout')
@enterprise_login_required
def logout():
    """Logout user"""
    user_id = session['user_id']
    security_audit.log_security_event('LOGOUT', user_id)
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@enterprise_login_required
def dashboard():
    """Enterprise dashboard with analytics"""
    user_id = session['user_id']
    
    # Get user files with safe defaults
    files = get_user_files(user_id) or []
    
    # Get usage statistics with safe defaults
    usage_stats = billing_mgr.get_usage_stats(user_id)
    if not usage_stats:
        usage_stats = {
            'storage_used_gb': 0,
            'storage_limit_gb': 50,
            'api_calls_used': 0,
            'api_calls_limit': 500,
            'storage_percentage': 0,
            'api_percentage': 0
        }
    
    # Get billing information with safe defaults
    billing_info = billing_mgr.get_billing_info(user_id)
    if not billing_info:
        billing_info = {
            'current_tier': 'starter',
            'next_billing_date': (datetime.utcnow() + timedelta(days=30)).strftime('%Y-%m-%d'),
            'cost_breakdown': {
                'base_price': 29,
                'storage_overage': 0,
                'api_overage': 0,
                'total': 29
            }
        }
    
    # Security overview with safe defaults
    security_events = security_audit.get_recent_events(user_id, limit=5) or []
    
    return render_template('dashboard.html', 
                         files=files, 
                         username=session['username'],
                         company=session.get('company', ''),
                         tier=session.get('user_tier', 'starter'),
                         usage=usage_stats,
                         billing=billing_info,
                         security_events=security_events,
                         config=app.config)

@app.route('/upload', methods=['POST'])
@enterprise_login_required
@rate_limiter.limit("20 per hour")
def upload_file():
    """Secure file upload with enterprise features + debug"""
    user_id = session['user_id']
    print(f"DEBUG: upload_file called for user_id = {user_id}")

    if 'file' not in request.files:
        flash('No file selected.', 'danger')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    file_type = request.form.get('file_type', 'general')
    print(f"DEBUG: Received file {file.filename} of type {file_type}")

    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('dashboard'))

    # Check file size limit
    if file.content_length > app.config['MAX_CONTENT_LENGTH']:
        flash('File size exceeds limit.', 'danger')
        return redirect(url_for('dashboard'))

    if file and allowed_file(file.filename):
        try:
            # Create temp directory
            temp_dir = app.config['UPLOAD_FOLDER']
            os.makedirs(temp_dir, exist_ok=True)
            temp_path = os.path.join(temp_dir, file.filename)
            print(f"DEBUG: Saving file to temp_path = {temp_path}")
            file.save(temp_path)

            # Upload to secure storage
            drive_file_id, file_size = upload_to_drive(temp_path, file.filename, user_id, file_type)
            print(f"DEBUG: drive_file_id = {drive_file_id}, file_size = {file_size}")

            if drive_file_id:
                flash(f'File "{file.filename}" uploaded securely!', 'success')
            else:
                flash('Upload failed. Please try again.', 'danger')

            # Cleanup temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)
                print(f"DEBUG: Deleted temp file {temp_path}")

        except Exception as e:
            print(f"UPLOAD EXCEPTION: {str(e)}")
            flash(f'Upload error: {str(e)}', 'danger')
            security_audit.log_security_event('UPLOAD_ERROR', user_id, {'error': str(e)})
    else:
        allowed_extensions = ', '.join(sorted(app.config['ALLOWED_EXTENSIONS']))
        flash(f'File type not allowed. Supported types: {allowed_extensions}', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/search')
@enterprise_login_required
def search_files():
    """Search files"""
    query = request.args.get('q', '').strip().lower()
    user_id = session['user_id']
    
    if not query:
        flash('Please enter a search term.', 'warning')
        return redirect(url_for('dashboard'))
    
    all_files = get_user_files(user_id)
    matching_files = [f for f in all_files if query in f['filename'].lower()]
    
    return render_template('search.html', 
                         files=matching_files, 
                         query=query, 
                         username=session['username'],
                         config=app.config)

@app.route('/preview/<file_id>')
@enterprise_login_required
def preview_file(file_id):
    """Preview file (same as download but without attachment)"""
    user_id = session['user_id']
    
    # Verify user owns the file
    user_files = get_user_files(user_id)
    file_info = next((f for f in user_files if f['id'] == file_id), None)
    
    if not file_info:
        flash('File not found or access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    file_stream = download_from_drive(file_id, user_id)
    if file_stream:
        return send_file(
            file_stream,
            as_attachment=False,  # Preview instead of download
            download_name=file_info['filename']
        )
    else:
        flash('Preview failed.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/billing')
@enterprise_login_required
def billing():
    """Billing and usage information"""
    user_id = session['user_id']

    # Billing info with defaults
    billing_info = billing_mgr.get_billing_info(user_id) or {}
    billing_info.setdefault("cost_breakdown", {})
    billing_info["cost_breakdown"].setdefault("total", 0)
    billing_info["cost_breakdown"].setdefault("base_price", 0)
    billing_info["cost_breakdown"].setdefault("storage_overage", 0)
    billing_info["cost_breakdown"].setdefault("api_overage", 0)
    billing_info.setdefault("current_tier", "free")
    billing_info.setdefault("next_billing_date", "N/A")

    # Usage stats with defaults
    usage_stats = billing_mgr.get_usage_stats(user_id) or {}
    usage_stats.setdefault("storage_used_gb", 0)
    usage_stats.setdefault("storage_limit_gb", 100)  # default storage limit
    usage_stats.setdefault("api_calls_used", 0)
    usage_stats.setdefault("api_calls_limit", 1000)  # default API limit

    # Calculate percentages to avoid template errors
    usage_stats["storage_percentage"] = (
        (usage_stats["storage_used_gb"] / usage_stats["storage_limit_gb"]) * 100
        if usage_stats["storage_limit_gb"] else 0
    )
    usage_stats["api_percentage"] = (
        (usage_stats["api_calls_used"] / usage_stats["api_calls_limit"]) * 100
        if usage_stats["api_calls_limit"] else 0
    )

    # Invoice history
    invoice_history = billing_mgr.get_invoice_history(user_id) or []

    # Pricing tiers
    pricing_tiers = pricing_calculator.get_pricing_tiers() or {}

    return render_template(
        'billing.html',
        billing=billing_info,
        usage=usage_stats,
        invoices=invoice_history,
        pricing_tiers=pricing_tiers,
        username=session['username'],
        config=app.config
    )


@app.route('/security')
@enterprise_login_required
def security():
    """Security and audit logs"""
    user_id = session['user_id']
    
    security_events = security_audit.get_user_events(user_id, limit=50)
    recent_logins = security_audit.get_recent_logins(user_id, limit=10)
    
    return render_template('security.html',
                         security_events=security_events,
                         recent_logins=recent_logins,
                         username=session['username'],
                         config=app.config)

# -------------------------------
# API Routes for Integration
# -------------------------------
@app.route('/api/v1/files', methods=['GET'])
@enterprise_login_required
def api_get_files():
    """REST API for file listing"""
    user_id = session['user_id']
    files = get_user_files(user_id)
    return jsonify({'files': files})

@app.route('/api/v1/usage', methods=['GET'])
@enterprise_login_required
def api_get_usage():
    """REST API for usage statistics"""
    user_id = session['user_id']
    usage_stats = billing_mgr.get_usage_stats(user_id)
    return jsonify(usage_stats)

# -------------------------------
# Error Handlers
# -------------------------------
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html', config=app.config), 404

@app.errorhandler(500)
def internal_error(error):
    security_audit.log_security_event('SERVER_ERROR', session.get('user_id'), {'error': str(error)})
    return render_template('500.html', config=app.config), 500

# -------------------------------
# Template Filters
# -------------------------------
@app.template_filter('format_size')
def format_size_filter(size_bytes):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"

@app.template_filter('format_date')
def format_date_filter(date_string):
    try:
        dt = datetime.fromisoformat(date_string.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M')
    except:
        return date_string

@app.template_filter('format_currency')
def format_currency_filter(amount):
    return f"${amount:.2f}"

@app.template_filter('number_format')
def number_format_filter(value):
    """Format numbers with commas"""
    return f"{value:,}"

@app.template_filter('css_class')
def css_class_filter(value):
    """Convert values to CSS class names"""
    return value.lower().replace(' ', '-')

@rate_limiter.limit(max_attempts=5, window_seconds=60)
def my_protected_route():
    return "Protected content"

@rate_limiter.limit(
    max_attempts=int(os.getenv('RATE_LIMIT_ATTEMPTS', 5)), 
    window_seconds=int(os.getenv('RATE_LIMIT_WINDOW', 60))
)
def my_protected_route():
    return "Protected content"

# -------------------------------
# Main Execution
# -------------------------------
if __name__ == '__main__':
    # Create necessary directories
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('audit_logs', exist_ok=True)
    
    print("🚀 Enterprise Cloud Storage Starting...")
    print("🔒 Security: AES-256 Encryption ✅")
    print("💰 Pricing: Competitive Tiers ✅") 
    print("📊 Analytics: Usage Tracking ✅")
    print("🌐 API: RESTful Endpoints ✅")
    print("🏢 Multi-tenant: Ready ✅")
    print(f"💼 Company: {app.config['COMPANY_NAME']} ✅")
    
    app.run(debug=True, host='0.0.0.0', port=5000)