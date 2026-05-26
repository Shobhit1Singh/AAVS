"""
Vulnerable Test API
DO NOT use this in production - intentionally insecure
"""

from flask import Flask, request, jsonify
from asgiref.wsgi import WsgiToAsgi
import sqlite3
import subprocess

flask_app = Flask(__name__)

def get_db():
    conn = sqlite3.connect(':memory:')
    conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT)')
    conn.execute("INSERT INTO users VALUES (1, 'admin', 'admin@example.com', 'admin123')")
    conn.execute("INSERT INTO users VALUES (2, 'user', 'user@example.com', 'user123')")
    conn.commit()
    return conn


@flask_app.route("/")
def home():
s    return "Vulnerable API Running"


@flask_app.route('/api/v1/users', methods=['GET'])
def get_users():
    limit = request.args.get('limit', '10')
    query = f"SELECT id, username, email FROM users LIMIT {limit}"

    try:
        conn = get_db()
        cursor = conn.execute(query)
        users = [{'id': r[0], 'username': r[1], 'email': r[2]} for r in cursor.fetchall()]
        conn.close()
        return jsonify(users)
    except Exception as e:
        return jsonify({'error': str(e), 'query': query}), 500


@flask_app.route('/api/v1/users', methods=['POST'])
def create_user():
    data = request.get_json()

    username = data.get('username', '')
    email = data.get('email', '')
    password = data.get('password', '')

    query = f"INSERT INTO users (username, email, password) VALUES ('{username}', '{email}', '{password}')"

    try:
        conn = get_db()
        conn.execute(query)
        conn.commit()
        conn.close()
        return jsonify({'message': 'User created'}), 201
    except Exception as e:
        import traceback
        return jsonify({
            'error': str(e),
            'query': query,
            'traceback': traceback.format_exc()
        }), 500


@flask_app.route('/api/v1/users/<user_id>', methods=['GET'])
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"

    try:
        conn = get_db()
        cursor = conn.execute(query)
        row = cursor.fetchone()
        conn.close()

        if row:
            return jsonify({'id': row[0], 'username': row[1], 'email': row[2], 'password': row[3]})
        return jsonify({'error': 'User not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e), 'query': query}), 500


@flask_app.route('/api/v1/search', methods=['GET'])
def search():
    q = request.args.get('q', '')

    try:
        result = subprocess.check_output(f"echo {q}", shell=True, text=True)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


app = WsgiToAsgi(flask_app)
