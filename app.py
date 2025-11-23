from flask import Flask, request, render_template_string, session, redirect, make_response
import sqlite3
import pickle
import os
import hashlib

app = Flask(__name__)
app.secret_key = '12345'  # مفتاح ضعيف

# قوالب غير آمنة مع ثغرات XSS
LOGIN_TEMPLATE = '''
<h2>تسجيل الدخول</h2>
<form method="post">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" value="Login">
</form>
{% if error %}<div style="color: red;">{{ error }}</div>{% endif %}
'''

DASHBOARD_TEMPLATE = '''
<h2>مرحبا {{ username | safe }}!</h2>  <!-- ثغرة XSS -->
<p>رصيدك: ${{ balance }}</p>

<h3>تحويل الأموال</h3>
<form method="post" action="/transfer">
    <!-- لا يوجد توكن CSRF -->
    الحساب المستلم: <input type="text" name="to_account"><br>
    المبلغ: <input type="text" name="amount"><br>
    <input type="submit" value="تحويل">
</form>

<h3>معاملاتك</h3>
{{ transactions | safe }}  <!-- ثغرة XSS -->
'''

def init_db():
    conn = sqlite3.connect('bank.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, balance REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS transactions
                 (id INTEGER PRIMARY KEY, from_user TEXT, to_user TEXT, amount REAL, description TEXT)''')
    
    # كلمات المرور غير مشفرة
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 10000)")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'user1', 'password1', 5000)")
    c.execute("INSERT OR IGNORE INTO users VALUES (3, 'user2', 'password2', 3000)")
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    if 'username' in session:
        return redirect('/dashboard')
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # ثغرة SQL Injection
    conn = sqlite3.connect('bank.db')
    c = conn.cursor()
    query = f"SELECT * FROM users WHERE username = ? AND password = ? "
    c.execute(query,(username,password))  # SQL Injection هنا
    
    user = c.fetchone()
    conn.close()
    
    if user:
        session['username'] = username
        session['user_id'] = user[0]
        # مصادقة ضعيفة - لا تحقق من الصلاحيات
        return redirect('/dashboard')
    
    return render_template_string(LOGIN_TEMPLATE, error="فشل تسجيل الدخول")

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/')
    
    # ثغرة في الصلاحيات - يمكن لأي مستخدم الوصول
    username = session['username']
    
    conn = sqlite3.connect('bank.db')
    c = conn.cursor()
    
    # جلب الرصيد
    c.execute(f"SELECT balance FROM users WHERE username = '{username}'")  # SQL Injection
    balance = c.fetchone()[0]
    
    # جلب المعاملات مع ثغرة XSS
    c.execute(f"SELECT * FROM transactions WHERE from_user = '{username}' OR to_user = '{username}'")
    transactions = c.fetchall()
    
    conn.close()
    
    # عرض المعاملات بشكل غير آمن
    transactions_html = "<ul>"
    for trans in transactions:
        transactions_html += f"<li>من {trans[1]} إلى {trans[2]}: ${trans[3]} - {trans[4]}</li>"
    transactions_html += "</ul>"
    
    return render_template_string(DASHBOARD_TEMPLATE, 
                                username=username, 
                                balance=balance, 
                                transactions=transactions_html)

@app.route('/transfer', methods=['POST'])
def transfer():
    if 'username' not in session:
        return redirect('/')
    
    # لا يوجد تحقق من CSRF
    from_user = session['username']
    to_account = request.form['to_account']
    amount = request.form['amount']
    
    # لا يوجد تحقق من صحة المدخلات
    conn = sqlite3.connect('bank.db')
    c = conn.cursor()
    
    # SQL Injection في الاستعلامات
    c.execute(f"SELECT balance FROM users WHERE username = '{from_user}'")
    from_balance = c.fetchone()[0]
    
    if float(from_balance) >= float(amount):
        # عدم استخدام المعاملات الآمنة
        c.execute(f"UPDATE users SET balance = balance - {amount} WHERE username = '{from_user}'")
        c.execute(f"UPDATE users SET balance = balance + {amount} WHERE username = '{to_account}'")
        
        # تخزين بيانات غير موثوقة
        desc = f"تحويل من {from_user} إلى {to_account}"
        c.execute(f"INSERT INTO transactions (from_user, to_user, amount, description) VALUES ('{from_user}', '{to_account}', {amount}, '{desc}')")
        
        conn.commit()
    
    conn.close()
    return redirect('/dashboard')

@app.route('/admin')
def admin():
    # ثغرة في التحكم بالوصول - لا تحقق من الصلاحيات
    conn = sqlite3.connect('bank.db')
    c = conn.cursor()
    
    # كشف معلومات حساسة
    c.execute("SELECT username, password, balance FROM users")
    users = c.fetchall()
    
    c.execute("SELECT * FROM transactions")
    transactions = c.fetchall()
    
    conn.close()
    
    html = "<h1>لوحة الإدارة</h1><h2>المستخدمين:</h2><ul>"
    for user in users:
        html += f"<li>{user[0]} - {user[1]} - ${user[2]}</li>"  # كشف كلمات المرور
    html += "</ul><h2>المعاملات:</h2><ul>"
    for trans in transactions:
        html += f"<li>{trans}</li>"
    html += "</ul>"
    
    return html

@app.route('/search')
def search():
    # ثغرة SQL Injection واضحة
    query = request.args.get('q', '')
    
    conn = sqlite3.connect('bank.db')
    c = conn.cursor()
    
    c.execute(f"SELECT * FROM transactions WHERE description LIKE '%{query}%'")  # SQL Injection خطيرة
    results = c.fetchall()
    conn.close()
    
    html = "<h2>نتائج البحث:</h2><ul>"
    for result in results:
        html += f"<li>{result}</li>"
    html += "</ul>"
    
    return html

@app.route('/set_cookie')
def set_cookie():
    # ثغرة في إعدادات الكوكيز
    resp = make_response("Cookie set")
    resp.set_cookie('user_id', str(session.get('user_id')), httponly=False, secure=False)  # غير آمن
    return resp

@app.route('/profile', methods=['POST'])
def update_profile():
    # ثغرة في تحميل الملفات
    if 'file' in request.files:
        file = request.files['file']
        if file:
            # حفظ الملف بدون تحقق
            file.save(f"uploads/{file.filename}")
    
    return "تم تحديث الملف الشخصي"

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)  # وضع التصحيح مفعل