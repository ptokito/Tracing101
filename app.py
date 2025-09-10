from flask import Flask, render_template, request, jsonify, redirect, url_for
import sqlite3
import secrets
import string
from datetime import datetime
import os

app = Flask(__name__)

# Database setup
DATABASE = 'passwords.db'

def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website TEXT NOT NULL,
            username TEXT,
            password TEXT NOT NULL,
            length INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def generate_password(length=12, include_symbols=True):
    """Generate a secure password"""
    characters = string.ascii_letters + string.digits
    if include_symbols:
        characters += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    # Ensure at least one character from each category
    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits)
    ]
    
    if include_symbols:
        password.append(secrets.choice("!@#$%^&*"))
    
    # Fill the rest randomly
    for _ in range(length - len(password)):
        password.append(secrets.choice(characters))
    
    # Shuffle the password
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)

@app.route('/')
def index():
    """Main page with password generator form"""
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate():
    """Generate and store a new password"""
    website = request.form.get('website', '').strip()
    username = request.form.get('username', '').strip()
    length = int(request.form.get('length', 12))
    include_symbols = 'symbols' in request.form
    
    if not website:
        return jsonify({'error': 'Website is required'}), 400
    
    if length < 4 or length > 128:
        return jsonify({'error': 'Password length must be between 4 and 128'}), 400
    
    # Generate password
    password = generate_password(length, include_symbols)
    
    # Store in database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO passwords (website, username, password, length)
        VALUES (?, ?, ?, ?)
    ''', (website, username, password, length))
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'password': password,
        'website': website,
        'username': username
    })

@app.route('/passwords')
def view_passwords():
    """View all stored passwords"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, website, username, password, length, created_at 
        FROM passwords 
        ORDER BY created_at DESC
    ''')
    passwords = cursor.fetchall()
    conn.close()
    
    return render_template('passwords.html', passwords=passwords)

@app.route('/api/passwords')
def api_passwords():
    """API endpoint for monitoring purposes - simple data retrieval"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM passwords')
    count = cursor.fetchone()[0]
    conn.close()
    
    return jsonify({
        'total_passwords': count,
        'status': 'healthy'
    })

@app.route('/delete/<int:password_id>', methods=['POST'])
def delete_password(password_id):
    """Delete a password entry"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM passwords WHERE id = ?', (password_id,))
    conn.commit()
    conn.close()
    
    return redirect(url_for('view_passwords'))

@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT 1')
        conn.close()
        return jsonify({'status': 'healthy', 'database': 'connected'})
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Run the application
    app.run(host='0.0.0.0', port=5000, debug=True)
