from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
import sqlite3
import requests
import secrets
import hmac
import uuid
import re
import os
from dotenv import load_dotenv

load_dotenv()

# --- DEBUG TEST FOR ENV VARIABLES ---
print("DEBUG TWILIO SID:", repr(os.environ.get('TWILIO_ACCOUNT_SID')))
print("DEBUG FLASK_DEBUG:", repr(os.environ.get('FLASK_DEBUG')))

app = Flask(__name__)

# --- CONFIG ---
app.secret_key = os.environ.get('SECRET_KEY', 'dev-only-change-me')
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Debug mode check
DEBUG_MODE = os.environ.get('FLASK_DEBUG', '0') == '1'

DATABASE = 'database.db'

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD_HASH = os.environ.get(
    'ADMIN_PASSWORD_HASH',
    generate_password_hash('admin123')
)

ORDER_STATUSES = ['Placed', 'Confirmed', 'Shipped', 'Out for Delivery', 'Delivered', 'Cancelled']

# --- PHONE OTP VERIFICATION (via Twilio SMS) ---
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN')
TWILIO_FROM_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER') or os.environ.get('TWILIO_FROM_NUMBER')
SMS_OTP_CONFIGURED = bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER)

OTP_EXPIRY_MINUTES = 10
OTP_RESEND_COOLDOWN_SECONDS = 60
OTP_MAX_ATTEMPTS = 5

MAX_QTY_PER_LINE = 10
MAX_CART_LINES = 50


def normalize_phone(phone):
    digits = re.sub(r'\D', '', phone or '')
    if digits.startswith('91') and len(digits) == 12:
        digits = digits[2:]
    elif digits.startswith('0') and len(digits) == 11:
        digits = digits[1:]
    return digits


def is_valid_phone(phone_digits):
    return bool(re.match(r'^\d{10}$', phone_digits or ''))


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def generate_otp():
    return f"{secrets.randbelow(1000000):06d}"


def send_otp_sms(phone_digits, otp_code):
    if not SMS_OTP_CONFIGURED:
        return False, "Phone verification isn't configured on this store yet."

    to_number = f'+91{phone_digits}'
    url = f'https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT_SID}/Messages.json'

    try:
        resp = requests.post(
            url,
            auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
            data={
                'From': TWILIO_FROM_NUMBER,
                'To': to_number,
                'Body': f'Your WEARUP verification code is {otp_code}. '
                        f'It expires in {OTP_EXPIRY_MINUTES} minutes.'
            },
            timeout=10
        )
        if resp.status_code in (200, 201):
            return True, None
        return False, "Couldn't send the verification SMS. Please try again later."
    except requests.RequestException:
        return False, "Couldn't send the verification SMS. Please try again later."


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def get_csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_hex(16)
        session['_csrf_token'] = token
    return token


app.jinja_env.globals['csrf_token'] = get_csrf_token


@app.before_request
def csrf_protect():
    if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return None
    expected = session.get('_csrf_token', '')
    sent = request.form.get('csrf_token') or request.headers.get('X-CSRFToken') or ''
    if expected and hmac.compare_digest(sent.encode(), expected.encode()):
        return None
    message = 'Your session expired. Please refresh the page and try again.'
    if request.is_json:
        return jsonify({'success': False, 'error': message, 'message': message}), 400
    return message, 400


def issue_otp(phone_digits):
    if not SMS_OTP_CONFIGURED and not DEBUG_MODE:
        return False, "Phone verification isn't set up on this store yet.", 503

    conn = get_db_connection()
    try:
        last = conn.execute(
            'SELECT created_at FROM otp_verifications WHERE phone = ? ORDER BY id DESC LIMIT 1',
            (phone_digits,)
        ).fetchone()
        if last:
            last_time = datetime.strptime(last['created_at'], '%Y-%m-%d %H:%M:%S')
            elapsed = (utcnow() - last_time).total_seconds()
            if elapsed < OTP_RESEND_COOLDOWN_SECONDS:
                wait = int(OTP_RESEND_COOLDOWN_SECONDS - elapsed)
                return False, f'Please wait {wait}s before requesting another code.', 429

        otp_code = generate_otp()
        expires_at = (utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)).strftime('%Y-%m-%d %H:%M:%S')
        cursor = conn.execute(
            'INSERT INTO otp_verifications (phone, otp_code, expires_at) VALUES (?, ?, ?)',
            (phone_digits, otp_code, expires_at)
        )
        otp_id = cursor.lastrowid
        conn.commit()

        if SMS_OTP_CONFIGURED:
            sent, error = send_otp_sms(phone_digits, otp_code)
            if not sent:
                conn.execute('DELETE FROM otp_verifications WHERE id = ?', (otp_id,))
                conn.commit()
                if DEBUG_MODE:
                    print(f'[DEV FALLBACK] Login code for +91{phone_digits}: {otp_code}', flush=True)
                    return True, None, 200
                return False, error, 502
        else:
            print(f'[DEV] Login code for +91{phone_digits}: {otp_code}', flush=True)

        return True, None, 200
    finally:
        conn.close()


def check_otp(phone_digits, otp_code):
    conn = get_db_connection()
    try:
        row = conn.execute(
            'SELECT * FROM otp_verifications WHERE phone = ? AND verified = 0 ORDER BY id DESC LIMIT 1',
            (phone_digits,)
        ).fetchone()
        if not row:
            return False, 'No pending verification for this number. Please request a new code.', 400

        expires_at = datetime.strptime(row['expires_at'], '%Y-%m-%d %H:%M:%S')
        if utcnow() > expires_at:
            return False, 'This code has expired. Please request a new one.', 400

        if row['attempts'] >= OTP_MAX_ATTEMPTS:
            return False, 'Too many attempts. Please request a new code.', 429

        conn.execute('UPDATE otp_verifications SET attempts = attempts + 1 WHERE id = ?', (row['id'],))
        conn.commit()

        if not hmac.compare_digest(row['otp_code'].encode(), otp_code.encode()):
            return False, 'Incorrect code. Please try again.', 400

        conn.execute('UPDATE otp_verifications SET verified = 1 WHERE id = ?', (row['id'],))
        conn.commit()
        return True, None, 200
    finally:
        conn.close()


def safe_next(target):
    if target and target.startswith('/') and not target.startswith('//') and '\\' not in target:
        return target
    return url_for('home')


def login_user(user):
    session.clear()
    session['user_id'] = user['id']
    session['user_name'] = user['full_name']
    session['phone'] = user['phone']
    session['pincode'] = user['pincode']
    session['address'] = user['address']


EMAIL_REGEX = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')


def is_valid_email_format(email):
    if not email or len(email) > 254:
        return False
    return bool(EMAIL_REGEX.match(email))


def is_valid_gmail_address(email):
    local_part, _, domain = email.partition('@')
    domain = domain.lower()

    if domain not in ('gmail.com', 'googlemail.com'):
        return True

    if not (6 <= len(local_part) <= 30):
        return False
    if not re.match(r'^[A-Za-z0-9.]+$', local_part):
        return False
    if local_part.startswith('.') or local_part.endswith('.'):
        return False
    if '..' in local_part:
        return False
    return True


def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            original_price REAL,
            discount_percent INTEGER,
            image_url TEXT NOT NULL,
            description TEXT,
            rating REAL DEFAULT 4.0,
            sizes TEXT DEFAULT 'Free Size',
            delivery_days INTEGER DEFAULT 5
        )
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT,
            pincode TEXT NOT NULL DEFAULT '',
            address TEXT NOT NULL DEFAULT ''
        )
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS otp_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT NOT NULL,
            otp_code TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            attempts INTEGER DEFAULT 0
        )
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            reviewer_name TEXT NOT NULL,
            rating INTEGER NOT NULL,
            comment TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id) REFERENCES products (id)
        )
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_group TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            product_id INTEGER,
            title TEXT NOT NULL,
            price REAL NOT NULL,
            size TEXT,
            quantity INTEGER NOT NULL,
            customer_name TEXT,
            customer_phone TEXT,
            delivery_address TEXT NOT NULL,
            pincode TEXT,
            estimated_delivery TEXT,
            status TEXT DEFAULT 'Placed',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (product_id) REFERENCES products (id)
        )
    ''')
    conn.commit()
    conn.close()


init_db()


# --- STOREFRONT ROUTES ---

@app.route('/')
def home():
    category = request.args.get('category')
    conn = get_db_connection()
    if category:
        products = conn.execute('SELECT * FROM products WHERE category = ?', (category,)).fetchall()
    else:
        products = conn.execute('SELECT * FROM products').fetchall()
    conn.close()
    return render_template('index.html', products=products, user_logged_in='user_id' in session, pincode=session.get('pincode', '412207'))


@app.route('/product/<int:product_id>')
def product_detail(product_id):
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()

    if product is None:
        conn.close()
        return "Product not found", 404

    reviews = conn.execute(
        'SELECT * FROM reviews WHERE product_id = ? ORDER BY created_at DESC',
        (product_id,)
    ).fetchall()
    conn.close()

    review_count = len(reviews)
    avg_rating = sum(r['rating'] for r in reviews) / review_count if review_count > 0 else (product['rating'] or 0)
    size_list = [s.strip() for s in (product['sizes'] or '').split(',') if s.strip()]
    delivery_days = product['delivery_days'] or 5
    delivery_date = (datetime.now() + timedelta(days=delivery_days)).strftime('%A, %d %b %Y')

    user_logged_in = 'user_id' in session
    return render_template(
        'product_detail.html',
        product=product,
        reviews=reviews,
        review_count=review_count,
        avg_rating=round(avg_rating, 1),
        size_list=size_list,
        delivery_date=delivery_date,
        user_logged_in=user_logged_in,
        delivery_address=session.get('address') if user_logged_in else None,
        delivery_pincode=session.get('pincode') if user_logged_in else None
    )


@app.route('/cart')
def cart():
    return render_template('cart.html', user_logged_in='user_id' in session, user_address=session.get('address'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = (request.form.get('email') or '').strip().lower()
        phone_raw = request.form.get('phone')
        pincode = request.form.get('pincode')
        address = request.form.get('address')
        phone_digits = normalize_phone(phone_raw)

        if not full_name or not phone_raw or not email or not pincode or not address:
            return render_template('register.html', error="Please fill in all fields.", otp_enabled=SMS_OTP_CONFIGURED or DEBUG_MODE)

        if not is_valid_email_format(email):
            return render_template('register.html', error="Please enter a valid email address.", otp_enabled=SMS_OTP_CONFIGURED or DEBUG_MODE)

        if not is_valid_gmail_address(email):
            return render_template('register.html', error="That Gmail address isn't valid.", otp_enabled=SMS_OTP_CONFIGURED or DEBUG_MODE)

        if not is_valid_phone(phone_digits):
            return render_template('register.html', error="Please enter a valid 10-digit phone number.", otp_enabled=SMS_OTP_CONFIGURED or DEBUG_MODE)

        if (SMS_OTP_CONFIGURED or DEBUG_MODE) and session.get('otp_verified_phone') != phone_digits:
            return render_template('register.html', error="Please verify your phone number with the OTP sent to it before continuing.", otp_enabled=SMS_OTP_CONFIGURED or DEBUG_MODE)

        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (full_name, email, phone, pincode, address) VALUES (?, ?, ?, ?, ?)',
                           (full_name, email, phone_digits, pincode, address))
            conn.commit()
            user_id = cursor.lastrowid

            session['user_id'] = user_id
            session['user_name'] = full_name
            session['phone'] = phone_digits
            session['pincode'] = pincode
            session['address'] = address
            session.pop('otp_verified_phone', None)

            conn.close()
            return redirect(url_for('cart'))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('register.html', error="Email already exists. Please login.", otp_enabled=SMS_OTP_CONFIGURED or DEBUG_MODE)

    return render_template('register.html', otp_enabled=SMS_OTP_CONFIGURED or DEBUG_MODE)


# --- PHONE OTP ROUTES ---

@app.route('/send-otp', methods=['POST'])
def send_otp():
    if not (SMS_OTP_CONFIGURED or DEBUG_MODE):
        return jsonify({'success': False, 'error': "Phone verification isn't set up on this store yet."}), 503

    data = request.get_json(silent=True) or {}
    phone_digits = normalize_phone(data.get('phone') or '')

    if not is_valid_phone(phone_digits):
        return jsonify({'success': False, 'error': 'Please enter a valid 10-digit phone number first.'}), 400

    ok, error, status = issue_otp(phone_digits)
    if not ok:
        return jsonify({'success': False, 'error': error}), status

    return jsonify({'success': True, 'message': f'Verification code sent to +91{phone_digits}.'})


@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json(silent=True) or {}
    phone_digits = normalize_phone(data.get('phone') or '')
    otp_code = (data.get('otp') or '').strip()

    if not phone_digits or not otp_code:
        return jsonify({'success': False, 'error': 'Please enter the code sent to your phone.'}), 400

    ok, error, status = check_otp(phone_digits, otp_code)
    if not ok:
        return jsonify({'success': False, 'error': error}), status

    session['otp_verified_phone'] = phone_digits
    return jsonify({'success': True, 'message': 'Phone number verified!'})


# --- LOGIN ROUTES ---

@app.route('/login')
def login():
    if 'user_id' in session:
        return redirect(safe_next(request.args.get('next')))
    return render_template('login.html', next_url=request.args.get('next', ''), otp_ready=SMS_OTP_CONFIGURED or DEBUG_MODE)


@app.route('/login/send-otp', methods=['POST'])
def login_send_otp():
    if not (SMS_OTP_CONFIGURED or DEBUG_MODE):
        return jsonify({'success': False, 'error': "Login isn't available right now."}), 503

    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    if not is_valid_email_format(email):
        return jsonify({'success': False, 'error': 'Please enter the email address you registered with.'}), 400

    conn = get_db_connection()
    user = conn.execute('SELECT phone FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()

    if user:
        phone_digits = normalize_phone(user['phone'])
        if is_valid_phone(phone_digits):
            ok, error, status = issue_otp(phone_digits)
            if not ok and status == 502:
                return jsonify({'success': False, 'error': error}), 502

    return jsonify({'success': True, 'message': 'If an account exists, a code has been sent.'})


@app.route('/login/verify', methods=['POST'])
def login_verify():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    otp_code = (data.get('otp') or '').strip()

    if not email or not otp_code:
        return jsonify({'success': False, 'error': 'Please enter your email and the code you received.'}), 400

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()

    failed = (jsonify({'success': False, 'error': 'Incorrect or expired code.'}), 400)
    if not user or not user['phone']:
        return failed

    ok, _error, _status = check_otp(normalize_phone(user['phone']), otp_code)
    if not ok:
        return failed

    login_user(user)
    return jsonify({'success': True, 'redirect': safe_next(data.get('next'))})


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login', next=request.path))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()

    if user is None:
        session.clear()
        return redirect(url_for('register'))

    return render_template('profile.html', user=user)


if __name__ == '__main__':
    app.run(debug=True)