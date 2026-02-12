"""
Vulnerable Test API
DO NOT use this in production - it's intentionally insecure for testing
"""

from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)

# In-memory database
def get_db():
    conn = sqlite3.connect(':memory:')
    conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT)')
    conn.execute("INSERT INTO users VALUES (1, 'admin', 'admin@example.com', 'admin123')")
    conn.execute("INSERT INTO users VALUES (2, 'user', 'user@example.com', 'user123')")
    conn.commit()
    return conn


@app.route('/api/v1/users', methods=['GET'])
def get_users():
    """
    Vulnerable to SQL injection via 'limit' parameter
    """
    limit = request.args.get('limit', '10')
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT id, username, email FROM users LIMIT {limit}"
    
    try:
        conn = get_db()
        cursor = conn.execute(query)
        users = [{'id': row[0], 'username': row[1], 'email': row[2]} for row in cursor.fetchall()]
        conn.close()
        return jsonify(users)
    except Exception as e:
        # VULNERABLE: Exposing error details
        return jsonify({'error': str(e), 'query': query}), 500


@app.route('/api/v1/users', methods=['POST'])
def create_user():
    """
    Vulnerable to various injection attacks
    """
    data = request.get_json()
    
    username = data.get('username', '')
    email = data.get('email', '')
    password = data.get('password', '')
    
    # VULNERABLE: No input validation
    # VULNERABLE: SQL injection via string concat
    query = f"INSERT INTO users (username, email, password) VALUES ('{username}', '{email}', '{password}')"
    
    try:
        conn = get_db()
        conn.execute(query)
        conn.commit()
        conn.close()
        return jsonify({'message': 'User created', 'username': username}), 201
    except Exception as e:
        # VULNERABLE: Stack trace exposure
        import traceback
        return jsonify({
            'error': str(e), 
            'query': query,
            'traceback': traceback.format_exc()
        }), 500


@app.route('/api/v1/users/<user_id>', methods=['GET'])
def get_user(user_id):
    """
    Vulnerable to SQL injection in path parameter
    """
    # VULNERABLE: No input sanitization
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    try:
        conn = get_db()
        cursor = conn.execute(query)
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return jsonify({'id': row[0], 'username': row[1], 'email': row[2], 'password': row[3]})
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e), 'debug': {'query': query}}), 500


@app.route('/api/v1/search', methods=['GET'])
def search():
    """
    Vulnerable to command injection
    """
    query = request.args.get('q', '')
    
    # VULNERABLE: Command injection
    import subprocess
    try:
        result = subprocess.check_output(f"echo {query}", shell=True, text=True)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("\n" + "="*70)
    print("⚠️  VULNERABLE TEST API STARTING")
    print("="*70)
    print("This API is INTENTIONALLY INSECURE for testing purposes")
    print("Running on: http://127.0.0.1:5000")
    print("="*70 + "\n")
    
    app.run(debug=True, port=5000)