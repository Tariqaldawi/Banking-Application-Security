Banking Application Security Demonstration
This project demonstrates two versions of a banking application: one with intentional security vulnerabilities and a secure version with all vulnerabilities patched.

⚠️ Important Security Notice
The vulnerable version is for educational purposes only and should NEVER be used in production environments. It contains deliberate security flaws that could be exploited by attackers.

Project Structure
text
banking-app/
├── vulnerable_app.py          # Application with security vulnerabilities
├── secure_app.py             # Secure version with all fixes
├── templates/                # HTML templates (for secure version)
│   ├── login.html
│   ├── dashboard.html
│   ├── admin.html
│   └── search_results.html
├── requirements.txt          # Python dependencies
└── README.md                # This file
Applications Overview
1. Vulnerable Application (vulnerable_app.py)
Purpose: Educational demonstration of common web application security vulnerabilities.

🚨 Deliberate Security Vulnerabilities:
A. SQL Injection

Unsafe string concatenation in SQL queries

No parameterized queries

Example: f"SELECT * FROM users WHERE username = '{username}'"

B. Cross-Site Scripting (XSS)

Unsafe use of | safe filter in templates

Direct rendering of user input without escaping

Stored and reflected XSS vulnerabilities

C. Cross-Site Request Forgery (CSRF)

No CSRF tokens in forms

No referer checking

State-changing operations without validation

D. Authentication & Session Issues

Weak secret key ('12345')

Plain text password storage

No password complexity requirements

Weak session management

E. Authorization Bypasses

No role-based access control

Admin panel accessible without admin privileges

Missing authentication checks

F. Information Disclosure

Exposure of sensitive data (passwords, balances)

Detailed error messages in production

Debug mode enabled

G. Input Validation Issues

No input sanitization

Missing data type validation

Unlimited file uploads

2. Secure Application (secure_app.py)
Purpose: Production-ready secure banking application with all vulnerabilities fixed.

✅ Security Implementations:
A. SQL Injection Protection

Parameterized queries exclusively

Prepared statements for all database operations

Input validation before database operations

B. XSS Protection

Automatic HTML escaping in templates

Content Security Policy ready

Safe handling of all user input

C. CSRF Protection

CSRF tokens on all forms

Flask-WTF CSRF integration

Token validation for state-changing operations

D. Secure Authentication

Strong password hashing (Werkzeug)

Brute force protection with account locking

Secure session management

Strong random secret key

E. Proper Authorization

Role-based access control

Authentication decorators

Admin-only endpoints properly protected

F. Input Validation & Sanitization

Comprehensive input validation

Data type and range checking

SQL/LDAP injection prevention

File upload restrictions

G. Additional Security Measures

Rate limiting (Flask-Limiter)

Security headers

Comprehensive logging

Secure cookie settings

Error handling without information leakage

Installation & Setup
Prerequisites
Python 3.8+

pip (Python package manager)

Dependencies
Create a requirements.txt file:

txt
Flask==2.3.3
Flask-WTF==1.1.1
Flask-Limiter==3.3.0
Werkzeug==2.3.7
Install dependencies:

bash
pip install -r requirements.txt
Running the Applications
Vulnerable Application (Educational Only):

bash
python vulnerable_app.py
Access at: http://localhost:5000

Secure Application:

bash
python secure_app.py
Access at: http://localhost:5000

Security Testing
Testing the Vulnerable Application
SQL Injection Tests:

sql
-- Login bypass
' OR '1'='1' --

-- Data extraction
' UNION SELECT username, password, balance FROM users --
XSS Tests:

html
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
CSRF Tests:

Create HTML forms that submit to the transfer endpoint

Test without CSRF tokens

Testing the Secure Application
All above attacks should be blocked

Rate limiting should trigger after 5 failed logins

CSRF tokens required for all forms

Input validation should reject malicious payloads

API Endpoints
Vulnerable Application Endpoints:
GET / - Login page

POST / - Login (vulnerable)

GET /dashboard - User dashboard (XSS vulnerable)

POST /transfer - Money transfer (CSRF vulnerable)

GET /admin - Admin panel (access control vulnerable)

GET /search - Search (SQL injection vulnerable)

Secure Application Endpoints:
GET /login - Secure login form

POST /login - Secure login (rate limited)

GET /dashboard - Secure dashboard

POST /transfer - Secure transfer (CSRF protected)

GET /admin - Admin panel (admin role required)

GET /search - Secure search

POST /logout - Secure logout

Security Headers Implemented
The secure application includes:

CSRF Protection

XSS Protection

Secure Session Cookies

Rate Limiting

Input Validation

Output Encoding

Logging & Monitoring
The secure application includes comprehensive logging for:

Login attempts (success/failure)

Financial transactions

Administrative actions

Security events

Error conditions

Best Practices Demonstrated
Never trust user input

Use parameterized queries

Implement proper authentication and authorization

Validate all inputs

Escape all outputs

Use security libraries and frameworks

Implement proper error handling

Use secure configuration

Log security events

Implement rate limiting

Educational Use
This project is ideal for:

Security awareness training

Secure coding workshops

Penetration testing practice

Code review exercises

Security team training

Disclaimer
This software is provided for educational purposes only. The vulnerable version should never be deployed in any environment accessible to untrusted users. The developers are not responsible for any misuse of this code.

Reporting Issues
If you find additional vulnerabilities in the "secure" version, please report them through appropriate security channels.

License
This project is intended for educational use. Please ensure you have proper authorization before using these applications for security testing.
