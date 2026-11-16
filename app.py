"""
SQL Injection Evaluation Lab (Flask + SQLAlchemy)

EDUCATIONAL USE ONLY. This app contains intentionally vulnerable routes
(/vulnerable and /search_vulnerable) to demonstrate SQL injection next to
secure equivalents. Run it only on localhost. Never deploy it.
"""
from flask import Flask, request, render_template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_lab.db'
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'echo': True}  # logs every SQL statement
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # long enough for hashes


@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')


# SECURE ROUTE (ORM + hash verification)
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # 1. Fetch the user safely via the ORM by username only
    query = db.select(User).filter_by(username=username)
    user = db.session.execute(query).scalar()

    # 2. Verify the password hash in Python, not in SQL
    if user and check_password_hash(user.password, password):
        return render_template('index.html', message=f"ACCESS GRANTED: {user.username}", status="success")

    return render_template('index.html', message="ACCESS DENIED", status="error")


# VULNERABLE ROUTE (raw SQL string concatenation)
@app.route('/vulnerable', methods=['POST'])
def vulnerable():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    raw_sql = f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'"
    query = text(raw_sql)
    user = db.session.execute(query).fetchone()

    if user:
        return render_template('index.html', message=f"SYSTEM COMPROMISED: {user[1]}", status="success")

    return render_template('index.html', message="ACCESS DENIED", status="error")


# VULNERABLE SEARCH (user input injected between the LIKE wildcards)
@app.route('/search_vulnerable', methods=['POST'])
def search_vulnerable():
    search_term = request.form.get('search', '')

    raw_sql = f"SELECT username FROM user WHERE username LIKE '%{search_term}%'"
    query = text(raw_sql)
    results = db.session.execute(query).fetchall()

    if results:
        users = [row[0] for row in results]
        return render_template('index.html', search_message=f"Discovered: {', '.join(users)}", status="success")

    return render_template('index.html', search_message="No users found.", status="error")


# SECURE SEARCH (escaped wildcards + ORM parameterization)
@app.route('/search_secure', methods=['POST'])
def search_secure():
    search_term = request.form.get('search', '')

    # 1. Neutralize LIKE wildcards before the ORM sees them
    safe_term = search_term.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')

    # 2. Parameterized query; tell SQLite which character is the escape character
    query = db.select(User.username).where(User.username.like(f"%{safe_term}%", escape='\\'))
    results = db.session.execute(query).scalars().all()

    if results:
        return render_template('index.html', search_message=f"Found: {', '.join(results)}", status="success")

    return render_template('index.html', search_message="No users found.", status="error")


# This block must stay at the bottom so every route above is registered first.
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
