# SQL Injection Evaluation Lab (Flask + SQLAlchemy)

A small Flask app that places **intentionally vulnerable** SQL code next to **secure equivalents**, so the difference between raw string-built queries and ORM parameterization is easy to see, test and log.

> ⚠️ **Educational use only.** `/vulnerable` and `/search_vulnerable` are insecure on purpose. Run this locally (`127.0.0.1`) and never deploy it.

## What it demonstrates

| Feature | Vulnerable route | Secure route |
|---|---|---|
| Login | `POST /vulnerable` builds SQL with an f-string | `POST /login` uses the ORM, then verifies the password hash in Python |
| User search | `POST /search_vulnerable` injects input between `LIKE` wildcards | `POST /search_secure` escapes `%`, `_`, `\` and parameterizes via the ORM |

## Security concepts covered

- **Injection root cause:** user input concatenated into SQL changes the query's logic
- **Parameterized queries / ORM:** input is treated as data, never as SQL
- **Password storage:** salted hashes (`generate_password_hash` / `check_password_hash`), not plaintext
- **Wildcard handling:** escaping `%` and `_` in `LIKE` searches with a defined escape character
- **Query logging:** `echo=True` prints each SQL statement, so you can see exactly what reaches the database

## Setup

```bash
git clone https://github.com/Dhruv4152/sqli-flask-evaluation.git
cd sqli-flask-evaluation

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

python init_db.py               # creates the SQLite DB with hashed demo users
python app.py                   # http://127.0.0.1:5000
```

Demo accounts created by `init_db.py`: `admin` and `guest` (passwords are stored as hashes).

## Try it

1. **Login bypass:** submit this as the username to `/vulnerable`, with any password: `' OR '1'='1' --`. The query logic changes and the check passes.
2. Submit the same input to `/login`. It is treated as a plain string, so access is denied.
3. **Search:** compare `/search_vulnerable` and `/search_secure` with input such as `%` or `_`. The secure route treats them as literal characters.
4. Watch the terminal: the SQL echoed for each request shows how the two approaches differ.

> Note: because passwords are hashed, a correct password does not work on `/vulnerable`. Only the injection succeeds, which shows how injection can bypass a hash check entirely.

## Project structure

```
sqli-flask-evaluation/
├── app.py            # routes (vulnerable and secure)
├── init_db.py        # builds the DB with hashed passwords
├── templates/
│   └── index.html
├── requirements.txt
└── README.md
```

## Tech stack

Python · Flask · Flask-SQLAlchemy · SQLite · Werkzeug (password hashing)

## Key takeaways

- Never build SQL with string formatting. Use parameterized queries or an ORM.
- Hash passwords and verify them in application code.
- Validate and escape special characters, including `LIKE` wildcards.
- Log queries during development to audit what the database actually receives.

## Disclaimer

Built for learning and portfolio purposes. Do not use the vulnerable routes against any system you do not own.
