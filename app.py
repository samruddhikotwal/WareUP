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

app = Flask(__name__)

# --- CONFIG ---
# Secret key now comes from an environment variable, with a dev-only fallback.
app.secret_key = os.environ.get('SECRET_KEY', 'dev-only-change-me')
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Debug mode is opt-in via an env var. In debug mode ONLY, login codes are printed
# to the server console when Twilio isn't configured, so you can test login locally.
DEBUG_MODE = os.environ.get('FLASK_DEBUG', '0') == '1'

DATABASE = 'database.db'

# Admin credentials: still simple (no separate admins table), but the
# password is now hashed instead of stored/compared in plain text.
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD_HASH = os.environ.get(
    'ADMIN_PASSWORD_HASH',
    generate_password_hash('admin123')  # change this in production
)

# The lifecycle a store staff member can move an order through.
ORDER_STATUSES = ['Placed', 'Confirmed', 'Shipped', 'Out for Delivery', 'Delivered', 'Cancelled']

# --- PHONE OTP VERIFICATION (via Twilio SMS) ---
# Requires a Twilio account (twilio.com) with an SMS-capable "From" number.
# Find these values in the Twilio Console (console.twilio.com):
#   TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN -> Account dashboard
#   TWILIO_FROM_NUMBER -> Phone Numbers -> Manage -> Active numbers
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN')
TWILIO_FROM_NUMBER = os.environ.get('TWILIO_FROM_NUMBER')
SMS_OTP_CONFIGURED = bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER)

OTP_EXPIRY_MINUTES = 10
OTP_RESEND_COOLDOWN_SECONDS = 60
OTP_MAX_ATTEMPTS = 5

# Order limits (enforced server-side)
MAX_QTY_PER_LINE = 10
MAX_CART_LINES = 50


def normalize_phone(phone):
    """Strip everything but digits, and drop a leading '91' or '0' so numbers
    typed as +91XXXXXXXXXX, 0XXXXXXXXX, or XXXXXXXXXX all compare equal."""
    digits = re.sub(r'\D', '', phone or '')
    if digits.startswith('91') and len(digits) == 12:
        digits = digits[2:]
    elif digits.startswith('0') and len(digits) == 11:
        digits = digits[1:]
    return digits


def is_valid_phone(phone_digits):
    return bool(re.match(r'^\d{10}$', phone_digits or ''))


def utcnow():
    """Naive UTC 'now' (matches SQLite's CURRENT_TIMESTAMP) without the deprecated utcnow()."""
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


# --- CSRF PROTECTION ---
# Every POST must carry the per-session token, either as a hidden form field
# named "csrf_token" or (for fetch/JSON calls) in an "X-CSRFToken" header.
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


# --- OTP HELPERS (shared by registration and login) ---
def issue_otp(phone_digits):
    """Create an OTP for a phone number and send it. Returns (ok, error, http_status)."""
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
                # A failed SMS shouldn't burn the user's resend cooldown.
                conn.execute('DELETE FROM otp_verifications WHERE id = ?', (otp_id,))
                conn.commit()
                return False, error, 502
        else:
            print(f'[DEV] Login code for +91{phone_digits}: {otp_code}', flush=True)

        return True, None, 200
    finally:
        conn.close()


def check_otp(phone_digits, otp_code):
    """Check a submitted code against the latest pending OTP. Returns (ok, error, http_status)."""
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
    """Only allow same-site relative paths as a post-login redirect target."""
    if target and target.startswith('/') and not target.startswith('//') and '\\' not in target:
        return target
    return url_for('home')


def login_user(user):
    session.clear()  # fresh session on login (also rotates the CSRF token)
    session['user_id'] = user['id']
    session['user_name'] = user['full_name']
    session['phone'] = user['phone']
    session['pincode'] = user['pincode']
    session['address'] = user['address']


# --- EMAIL VALIDATION ---
# General shape check: local-part@domain.tld (requires an actual dot + letters-only TLD,
# which catches typos like "user@gmail" with no ".com").
EMAIL_REGEX = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')


def is_valid_email_format(email):
    if not email or len(email) > 254:
        return False
    return bool(EMAIL_REGEX.match(email))


def is_valid_gmail_address(email):
    """
    Extra checks for @gmail.com / @googlemail.com addresses, mirroring Google's
    own username rules (6-30 chars, letters/numbers/dots only, no leading,
    trailing, or repeated dots). Addresses on other domains skip this check.
    """
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
    # Create Products Table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            original_price REAL,
            discount_percent INTEGER,
            image_url TEXT NOT NULL,
            description TEXT
        )
    ''')

    # Create Users/Delivery Address Table
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

    # Create OTP Verifications Table (phone number verification at registration)
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

    # Create Reviews Table
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

    # Create Orders Table
    # order_group ties together every line item placed in a single "Place Order" action.
    # customer_name/customer_phone are snapshotted at order time (like delivery_address)
    # so a delivery person always sees the contact info that was current when the order
    # was placed, even if the customer later edits their profile.
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

    # Migration-safe column additions (safe to re-run on an older database.db)
    user_columns = {row['name'] for row in conn.execute('PRAGMA table_info(users)').fetchall()}
    if 'phone' not in user_columns:
        conn.execute('ALTER TABLE users ADD COLUMN phone TEXT')
    conn.commit()

    order_columns = {row['name'] for row in conn.execute('PRAGMA table_info(orders)').fetchall()}
    if 'customer_name' not in order_columns:
        conn.execute('ALTER TABLE orders ADD COLUMN customer_name TEXT')
    if 'customer_phone' not in order_columns:
        conn.execute('ALTER TABLE orders ADD COLUMN customer_phone TEXT')
    conn.commit()

    # Migration-safe column additions for buy-flow info (rating / sizes / delivery estimate).
    # SQLite backfills DEFAULT values onto existing rows, so this is safe on an older database.db too.
    existing_columns = {row['name'] for row in conn.execute('PRAGMA table_info(products)').fetchall()}
    if 'rating' not in existing_columns:
        conn.execute('ALTER TABLE products ADD COLUMN rating REAL DEFAULT 4.0')
    if 'sizes' not in existing_columns:
        conn.execute("ALTER TABLE products ADD COLUMN sizes TEXT DEFAULT 'Free Size'")
    if 'delivery_days' not in existing_columns:
        conn.execute('ALTER TABLE products ADD COLUMN delivery_days INTEGER DEFAULT 5')
    conn.commit()

    # Seed initial sample data if empty
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM products')
    if cursor.fetchone()[0] == 0:
        sample_products = [
            ('Floral Festive Anarkali Kurta Set', 'fashion', 1299.0, 3499.0, 62, 'https://images.unsplash.com/photo-1610030469983-98e550d6193c?auto=format&fit=crop&w=800&q=80', 'Elegant printed Anarkali set crafted with soft cotton fabric, ideal for festive and casual celebrations.', 4.3, 'S,M,L,XL', 4),
            ('Traditional Designer Saree', 'fashion', 1899.0, 4999.0, 62, 'https://images.unsplash.com/photo-1617627143750-d86bc21e42bb?auto=format&fit=crop&w=800&q=80', 'Rich silk blend woven saree with intricate border detailing and unstitched blouse piece.', 4.6, 'Free Size', 5),
            ('Handcrafted Home Decor Lights', 'homeliving', 899.0, 1999.0, 55, 'https://images.unsplash.com/photo-1513519245088-0e12902e5a38?auto=format&fit=crop&w=800&q=80', 'Warm fairy lights string set for living room ambience and festive decoration.', 4.1, 'Free Size', 6)
        ]
        conn.executemany('''
            INSERT INTO products (title, category, price, original_price, discount_percent, image_url, description, rating, sizes, delivery_days)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', sample_products)
        conn.commit()

    # Seed sample reviews if empty (references the seed products above, ids 1-3 on a fresh DB)
    cursor.execute('SELECT COUNT(*) FROM reviews')
    if cursor.fetchone()[0] == 0:
        sample_reviews = [
            (1, 'Ananya R.', 5, 'Fabric quality is amazing and true to size. Wore it for Diwali, got so many compliments!'),
            (1, 'Priya S.', 4, 'Good fit, color is slightly darker than the photo but still lovely.'),
            (2, 'Meera K.', 5, 'Gorgeous saree, the border work looks even better in person.'),
            (2, 'Sneha J.', 4, 'Beautiful drape, delivery was on time.'),
            (3, 'Rohit T.', 4, 'Lights are warm and cozy, perfect for the living room.'),
        ]
        conn.executemany('''
            INSERT INTO reviews (product_id, reviewer_name, rating, comment)
            VALUES (?, ?, ?, ?)
        ''', sample_reviews)
        conn.commit()

    conn.close()


# Initialize Database on Application Start
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

    user_logged_in = 'user_id' in session
    pincode = session.get('pincode', '412207')

    return render_template('index.html', products=products, user_logged_in=user_logged_in, pincode=pincode)


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
    if review_count > 0:
        avg_rating = sum(r['rating'] for r in reviews) / review_count
    else:
        avg_rating = product['rating'] or 0

    size_list = [s.strip() for s in (product['sizes'] or '').split(',') if s.strip()]

    delivery_days = product['delivery_days'] or 5
    delivery_date = (datetime.now() + timedelta(days=delivery_days)).strftime('%A, %d %b %Y')

    user_logged_in = 'user_id' in session
    delivery_address = session.get('address') if user_logged_in else None
    delivery_pincode = session.get('pincode') if user_logged_in else None

    return render_template(
        'product_detail.html',
        product=product,
        reviews=reviews,
        review_count=review_count,
        avg_rating=round(avg_rating, 1),
        size_list=size_list,
        delivery_date=delivery_date,
        user_logged_in=user_logged_in,
        delivery_address=delivery_address,
        delivery_pincode=delivery_pincode
    )


@app.route('/cart')
def cart():
    user_logged_in = 'user_id' in session
    user_address = session.get('address', None)
    return render_template('cart.html', user_logged_in=user_logged_in, user_address=user_address)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # FIX: form field is "full_name" (was mismatched with register.html's old "name" field)
        full_name = request.form.get('full_name')
        email = (request.form.get('email') or '').strip().lower()
        phone_raw = request.form.get('phone')
        pincode = request.form.get('pincode')
        address = request.form.get('address')
        phone_digits = normalize_phone(phone_raw)

        if not full_name or not phone_raw or not email or not pincode or not address:
            return render_template('register.html', error="Please fill in all fields.",
                                    otp_enabled=SMS_OTP_CONFIGURED)

        if not is_valid_email_format(email):
            return render_template(
                'register.html',
                error="Please enter a valid email address (e.g. name@gmail.com).",
                otp_enabled=SMS_OTP_CONFIGURED
            )

        if not is_valid_gmail_address(email):
            return render_template(
                'register.html',
                error="That Gmail address isn't valid. Gmail usernames must be 6-30 characters "
                      "long and can only contain letters, numbers, and dots (no leading, "
                      "trailing, or repeated dots).",
                otp_enabled=SMS_OTP_CONFIGURED
            )

        if not is_valid_phone(phone_digits):
            return render_template(
                'register.html',
                error="Please enter a valid 10-digit phone number.",
                otp_enabled=SMS_OTP_CONFIGURED
            )

        if SMS_OTP_CONFIGURED and session.get('otp_verified_phone') != phone_digits:
            return render_template(
                'register.html',
                error="Please verify your phone number with the OTP sent to it before continuing.",
                otp_enabled=SMS_OTP_CONFIGURED
            )

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
            return render_template('register.html', error="Email already exists. Please login or use another email.",
                                    otp_enabled=SMS_OTP_CONFIGURED)

    return render_template('register.html', otp_enabled=SMS_OTP_CONFIGURED)


# --- PHONE OTP ROUTES ---

@app.route('/send-otp', methods=['POST'])
def send_otp():
    if not SMS_OTP_CONFIGURED:
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


# --- LOGIN (email + one-time code sent to the phone number on the account) ---

LOGIN_SENT_MESSAGE = ('If an account exists for that email, a verification code has been '
                      'sent to the phone number on file.')
LOGIN_FAILED_MESSAGE = 'Incorrect or expired code. Please request a new one.'


@app.route('/login')
def login():
    if 'user_id' in session:
        return redirect(safe_next(request.args.get('next')))
    return render_template('login.html',
                           next_url=request.args.get('next', ''),
                           otp_ready=SMS_OTP_CONFIGURED or DEBUG_MODE)


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

    # Same reply whether or not the email exists, so this can't be used to
    # find out who has an account.
    if user:
        phone_digits = normalize_phone(user['phone'])
        if is_valid_phone(phone_digits):
            ok, error, status = issue_otp(phone_digits)
            if not ok and status == 502:  # the SMS provider failed - tell the user
                return jsonify({'success': False, 'error': error}), 502

    return jsonify({'success': True, 'message': LOGIN_SENT_MESSAGE})


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

    failed = (jsonify({'success': False, 'error': LOGIN_FAILED_MESSAGE}), 400)
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


# --- ORDER ROUTES (new) ---

@app.route('/place-order', methods=['POST'])
def place_order():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'not_logged_in'}), 401

    data = request.get_json(silent=True)
    items = data.get('items') if data else None

    if not items or not isinstance(items, list) or len(items) > MAX_CART_LINES:
        return jsonify({'success': False, 'error': 'empty_cart',
                        'message': 'Your bag is empty or has too many items.'}), 400

    user_id = session['user_id']
    customer_name = session.get('user_name', '')
    customer_phone = session.get('phone', '')
    address = session.get('address', '')
    pincode = session.get('pincode', '')
    order_group = uuid.uuid4().hex[:12]

    conn = get_db_connection()
    try:
        lines = []
        for item in items:
            if not isinstance(item, dict):
                continue
            # Only the product id, size and quantity are taken from the browser.
            try:
                product_id = int(item.get('id'))
                quantity = int(item.get('quantity', 1))
            except (TypeError, ValueError):
                continue
            if quantity <= 0:
                continue
            quantity = min(quantity, MAX_QTY_PER_LINE)

            # Title and price always come from the products table, never from the cart.
            product = conn.execute(
                'SELECT id, title, price, sizes, delivery_days FROM products WHERE id = ?',
                (product_id,)
            ).fetchone()
            if product is None:
                return jsonify({'success': False, 'error': 'unavailable',
                                'message': 'An item in your bag is no longer available. '
                                           'Please remove it and try again.'}), 400

            allowed_sizes = [s.strip() for s in (product['sizes'] or '').split(',') if s.strip()] or ['Free Size']
            requested_size = str(item.get('size') or '').strip()
            if len(allowed_sizes) == 1:
                size = allowed_sizes[0]
            elif requested_size in allowed_sizes:
                size = requested_size
            else:
                return jsonify({'success': False, 'error': 'invalid_size',
                                'message': f'Please choose a size for "{product["title"]}" on its '
                                           f'product page, then add it to your bag again.'}), 400

            delivery_days = product['delivery_days'] or 5
            estimated_delivery = (datetime.now() + timedelta(days=delivery_days)).strftime('%A, %d %b %Y')
            lines.append((product['id'], product['title'], product['price'], size, quantity, estimated_delivery))

        if not lines:
            return jsonify({'success': False, 'error': 'empty_cart',
                            'message': 'Your bag is empty.'}), 400

        for product_id, title, price, size, quantity, estimated_delivery in lines:
            conn.execute('''
                INSERT INTO orders (order_group, user_id, product_id, title, price, size, quantity,
                                     customer_name, customer_phone, delivery_address, pincode,
                                     estimated_delivery, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Placed')
            ''', (order_group, user_id, product_id, title, price, size, quantity,
                  customer_name, customer_phone, address, pincode, estimated_delivery))

        conn.commit()
    finally:
        conn.close()

    return jsonify({'success': True, 'order_group': order_group})


@app.route('/orders')
def orders():
    if 'user_id' not in session:
        return redirect(url_for('login', next=request.path))

    conn = get_db_connection()
    rows = conn.execute(
        'SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()
    conn.close()

    # Group line items back into the order they were placed together in
    order_groups = []
    groups_by_id = {}
    for row in rows:
        gid = row['order_group']
        if gid not in groups_by_id:
            group = {
                'order_group': gid,
                'created_at': row['created_at'],
                'delivery_address': row['delivery_address'],
                'pincode': row['pincode'],
                'status': row['status'],
                'lines': [],
                'total': 0
            }
            groups_by_id[gid] = group
            order_groups.append(group)
        groups_by_id[gid]['lines'].append(row)
        groups_by_id[gid]['total'] += row['price'] * row['quantity']

    return render_template('orders.html', order_groups=order_groups)


@app.route('/orders/<order_group>/update-address', methods=['POST'])
def update_order_address(order_group):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    new_address = request.form.get('address')
    new_pincode = request.form.get('pincode')

    if new_address and new_pincode:
        conn = get_db_connection()
        # Only the order's own owner can edit it, and only before it has shipped.
        owned_order = conn.execute(
            'SELECT status FROM orders WHERE order_group = ? AND user_id = ? LIMIT 1',
            (order_group, session['user_id'])
        ).fetchone()

        if owned_order and owned_order['status'] == 'Placed':
            conn.execute(
                'UPDATE orders SET delivery_address = ?, pincode = ? WHERE order_group = ? AND user_id = ?',
                (new_address, new_pincode, order_group, session['user_id'])
            )
            conn.commit()
        conn.close()

    return redirect(url_for('orders'))


# --- PROFILE ROUTES (new) ---

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login', next=request.path))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()

    if user is None:
        # Session pointed at a user that no longer exists in the DB
        session.clear()
        return redirect(url_for('register'))

    return render_template('profile.html', user=user)


@app.route('/profile/update', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    full_name = request.form.get('full_name')
    phone = normalize_phone(request.form.get('phone'))
    pincode = request.form.get('pincode')
    address = request.form.get('address')

    if not full_name or not is_valid_phone(phone) or not pincode or not address:
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        return render_template('profile.html', user=user,
                               error="Please fill in all fields (phone must be 10 digits).")

    conn = get_db_connection()
    conn.execute(
        'UPDATE users SET full_name = ?, phone = ?, pincode = ?, address = ? WHERE id = ?',
        (full_name, phone, pincode, address, session['user_id'])
    )
    conn.commit()
    conn.close()

    # Keep session in sync with the DB
    session['user_name'] = full_name
    session['phone'] = phone
    session['pincode'] = pincode
    session['address'] = address

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()

    return render_template('profile.html', user=user, success="Profile updated successfully.")


# --- ADMIN PANEL ROUTES ---

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password or ''):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_panel'))
        else:
            return render_template('admin_login.html', error="Invalid admin username or password.")

    return render_template('admin_login.html')


@app.route('/admin')
def admin_panel():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products').fetchall()
    pending_orders = conn.execute(
        "SELECT COUNT(DISTINCT order_group) FROM orders WHERE status = 'Placed'"
    ).fetchone()[0]
    conn.close()
    return render_template('admin.html', products=products, pending_orders=pending_orders)


@app.route('/admin/orders')
def admin_orders():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    rows = conn.execute('''
        SELECT o.*, u.email AS customer_email
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.id
        ORDER BY o.created_at DESC
    ''').fetchall()
    conn.close()

    # Group line items back into the order they were placed together in
    order_groups = []
    groups_by_id = {}
    for row in rows:
        gid = row['order_group']
        if gid not in groups_by_id:
            group = {
                'order_group': gid,
                'created_at': row['created_at'],
                'customer_name': row['customer_name'],
                'customer_phone': row['customer_phone'],
                'customer_email': row['customer_email'],
                'delivery_address': row['delivery_address'],
                'pincode': row['pincode'],
                'status': row['status'],
                'lines': [],
                'total': 0
            }
            groups_by_id[gid] = group
            order_groups.append(group)
        groups_by_id[gid]['lines'].append(row)
        groups_by_id[gid]['total'] += row['price'] * row['quantity']

    return render_template('admin_orders.html', order_groups=order_groups, statuses=ORDER_STATUSES)


@app.route('/admin/orders/<order_group>/update-status', methods=['POST'])
def admin_update_order_status(order_group):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    new_status = request.form.get('status')
    if new_status in ORDER_STATUSES:
        conn = get_db_connection()
        conn.execute('UPDATE orders SET status = ? WHERE order_group = ?', (new_status, order_group))
        conn.commit()
        conn.close()

    return redirect(url_for('admin_orders'))


# FIX: renamed route to match the form action in admin.html ("/admin/add")
@app.route('/admin/add', methods=['POST'])
def add_product():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    title = request.form.get('title')
    category = request.form.get('category')
    price = float(request.form.get('price', 0))
    original_price = float(request.form.get('original_price', 0))
    image_url = request.form.get('image_url')
    description = request.form.get('description', '')

    discount_percent = 0
    if original_price > price and original_price > 0:
        discount_percent = int(((original_price - price) / original_price) * 100)

    conn = get_db_connection()
    conn.execute('''
        INSERT INTO products (title, category, price, original_price, discount_percent, image_url, description)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (title, category, price, original_price, discount_percent, image_url, description))
    conn.commit()
    conn.close()

    return redirect(url_for('admin_panel'))


# POST-only (and CSRF-protected): a plain link must never be able to delete data
@app.route('/admin/delete/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    conn.execute('DELETE FROM products WHERE id = ?', (product_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('admin_panel'))


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))


if __name__ == '__main__':
    # Debug mode is now opt-in via an env var instead of hardcoded True,
    # so it can't accidentally ship to production.
    app.run(debug=DEBUG_MODE)
