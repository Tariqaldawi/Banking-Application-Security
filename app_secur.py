from flask import Flask, request, render_template, session, redirect, flash, abort
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import logging
from functools import wraps
import os
import re
from html import escape

app = Flask(__name__)
app.secret_key = os.urandom(32)  # مفتاح عشوائي قوي
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600

# حماية CSRF
csrf = CSRFProtect()
csrf.init_app(app)

# معدل الطلبات
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# إعدادات التسجيل
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_db():
    """تهيئة قاعدة البيانات بشكل آمن"""
    conn = sqlite3.connect('bank.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, 
                  username TEXT UNIQUE, 
                  password_hash TEXT, 
                  balance REAL,
                  role TEXT DEFAULT 'user',
                  failed_login_attempts INTEGER DEFAULT 0,
                  account_locked INTEGER DEFAULT 0)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS transactions
                 (id INTEGER PRIMARY KEY, 
                  from_user TEXT, 
                  to_user TEXT, 
                  amount REAL,
                  description TEXT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(from_user) REFERENCES users(username),
                  FOREIGN KEY(to_user) REFERENCES users(username))''')
    
    # كلمات مرور مشفرة
    users = [
        ('admin', 'SecureAdminPass123!', 10000, 'admin'),
        ('user1', 'StrongUser1Pass456!', 5000, 'user'),
        ('user2', 'StrongUser2Pass789!', 3000, 'user')
    ]
    
    for username, password, balance, role in users:
        password_hash = generate_password_hash(password)
        c.execute('''INSERT OR IGNORE INTO users 
                     (username, password_hash, balance, role) 
                     VALUES (?, ?, ?, ?)''', 
                     (username, password_hash, balance, role))
    
    conn.commit()
    conn.close()

def get_db_connection():
    """الحصول على اتصال بقاعدة البيانات"""
    conn = sqlite3.connect('bank.db')
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    """ديكوراتور للتحقق من تسجيل الدخول"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or 'username' not in session:
            flash('يجب تسجيل الدخول أولاً')
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """ديكوراتور للتحقق من صلاحيات المدير"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def validate_input(text, max_length=100):
    """التحقق من صحة المدخلات"""
    if not text or len(text) > max_length:
        return False
    # منع الأحرف الخطرة
    if re.search(r'[<>\"\']', text):
        return False
    return True

def validate_amount(amount):
    """التحقق من صحة المبلغ"""
    try:
        amount = float(amount)
        if amount <= 0 or amount > 100000:
            return False, "المبلغ غير صالح"
        return True, amount
    except (ValueError, TypeError):
        return False, "مبلغ غير صالح"

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/dashboard')
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not validate_input(username) or not password:
            flash('بيانات الدخول غير صالحة')
            return render_template('login.html')
        
        conn = get_db_connection()
        
        # استعلام معد مسبقاً لمنع SQL Injection
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? AND account_locked = 0',
            (username,)
        ).fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            # إعادة تعيين محاولات تسجيل الدخول الفاشلة
            conn.execute(
                'UPDATE users SET failed_login_attempts = 0 WHERE id = ?',
                (user['id'],)
            )
            conn.commit()
            
            # إعداد الجلسة بشكل آمن
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session.permanent = False
            
            logger.info(f"تم تسجيل دخول المستخدم: {username}")
            conn.close()
            return redirect('/dashboard')
        else:
            # زيادة محاولات تسجيل الدخول الفاشلة
            if user:
                conn.execute(
                    'UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?',
                    (user['id'],)
                )
                # قفل الحساب بعد 5 محاولات فاشلة
                if user['failed_login_attempts'] + 1 >= 5:
                    conn.execute(
                        'UPDATE users SET account_locked = 1 WHERE id = ?',
                        (user['id'],)
                    )
                    flash('تم قفل حسابك بسبب محاولات تسجيل دخول فاشلة متعددة')
                conn.commit()
            
            conn.close()
            flash('اسم المستخدم أو كلمة المرور غير صحيحة')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    
    # استعلامات آمنة
    user = conn.execute(
        'SELECT balance FROM users WHERE id = ?',
        (session['user_id'],)
    ).fetchone()
    
    transactions = conn.execute(
        '''SELECT from_user, to_user, amount, description, timestamp 
           FROM transactions 
           WHERE from_user = ? OR to_user = ? 
           ORDER BY timestamp DESC LIMIT 10''',
        (session['username'], session['username'])
    ).fetchall()
    
    conn.close()
    
    return render_template('dashboard.html',
                         username=escape(session['username']),
                         balance=user['balance'],
                         transactions=transactions)

@app.route('/transfer', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def transfer():
    from_user = session['username']
    to_account = request.form.get('to_account', '').strip()
    amount_str = request.form.get('amount', '')
    
    # التحقق من صحة المدخلات
    if not validate_input(to_account) or not amount_str:
        flash('بيانات غير صالحة')
        return redirect('/dashboard')
    
    is_valid, amount_or_error = validate_amount(amount_str)
    if not is_valid:
        flash(amount_or_error)
        return redirect('/dashboard')
    
    amount = amount_or_error
    
    conn = get_db_connection()
    
    try:
        # التحقق من وجود الحساب المستلم
        to_user = conn.execute(
            'SELECT username FROM users WHERE username = ?',
            (to_account,)
        ).fetchone()
        
        if not to_user:
            flash('الحساب المستلم غير موجود')
            return redirect('/dashboard')
        
        # التحقق من الرصيد الكافي
        from_balance = conn.execute(
            'SELECT balance FROM users WHERE username = ?',
            (from_user,)
        ).fetchone()['balance']
        
        if from_balance < amount:
            flash('رصيد غير كافي')
            return redirect('/dashboard')
        
        # تنفيذ التحويل باستخدام معاملة آمنة
        conn.execute('BEGIN TRANSACTION')
        
        conn.execute(
            'UPDATE users SET balance = balance - ? WHERE username = ?',
            (amount, from_user)
        )
        conn.execute(
            'UPDATE users SET balance = balance + ? WHERE username = ?',
            (amount, to_account)
        )
        
        desc = f"تحويل آمن من {from_user} إلى {to_account}"
        conn.execute(
            'INSERT INTO transactions (from_user, to_user, amount, description) VALUES (?, ?, ?, ?)',
            (from_user, to_account, amount, desc)
        )
        
        conn.commit()
        logger.info(f"تم التحويل: {from_user} إلى {to_account} - ${amount}")
        flash('تم التحويل بنجاح')
        
    except Exception as e:
        conn.rollback()
        logger.error(f"خطأ في التحويل: {str(e)}")
        flash('حدث خطأ أثناء التحويل')
    finally:
        conn.close()
    
    return redirect('/dashboard')

@app.route('/admin')
@login_required
@admin_required
def admin():
    conn = get_db_connection()
    
    users = conn.execute(
        'SELECT username, balance, role FROM users'
    ).fetchall()
    
    transactions = conn.execute(
        'SELECT from_user, to_user, amount, timestamp FROM transactions ORDER BY timestamp DESC LIMIT 50'
    ).fetchall()
    
    conn.close()
    
    return render_template('admin.html',
                         users=users,
                         transactions=transactions)

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '').strip()
    
    if not validate_input(query):
        flash('طلب بحث غير صالح')
        return redirect('/dashboard')
    
    conn = get_db_connection()
    
    # استعلام آمن
    results = conn.execute(
        '''SELECT from_user, to_user, amount, description, timestamp 
           FROM transactions 
           WHERE (from_user = ? OR to_user = ?) 
           AND description LIKE ?''',
        (session['username'], session['username'], f'%{query}%')
    ).fetchall()
    
    conn.close()
    
    return render_template('search_results.html',
                         query=escape(query),
                         results=results)

@app.route('/logout')
def logout():
    # تسجيل الخروج الآمن
    session.clear()
    flash('تم تسجيل الخروج بنجاح')
    return redirect('/login')

if __name__ == '__main__':
    init_db()
    # تعطيل وضع التصحيح في الإنتاج
    app.run(debug=False, port=5000)