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

@app.route('/generate', methods=['GET', 'POST'])
def generate():
    """Generate and store a new password"""
    if request.method == 'GET':
        return redirect(url_for('index'))
    
    website = request.form.get('website', '').strip()
    username = request.form.get('username', '').strip()
    length_str = request.form.get('length', '12')
    include_symbols = 'symbols' in request.form

    # Validate inputs
    if not website:
        return render_template('index.html', error='Website/Service is required')

    try:
        length = int(length_str)
    except ValueError:
        return render_template('index.html', error='Password length must be a number')

    if length < 4 or length > 128:
        return render_template('index.html', error='Password length must be between 4 and 128')

    try:
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

        # Return success page with the generated password
        return render_template('result.html', 
                             password=password,
                             website=website,
                             username=username,
                             length=length,
                             include_symbols=include_symbols)
    
    except Exception as e:
        app.logger.error(f"Error generating password: {str(e)}")
        return render_template('index.html', error=f'An error occurred: {str(e)}')

@app.route('/passwords')
def view_passwords():
    """View all stored passwords"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, website, username, password, length, created_at
            FROM passwords
            ORDER BY created_at DESC
        ''')
        passwords = cursor.fetchall()
        conn.close()
        
        # Debug output
        print(f"Found {len(passwords)} passwords in database")
        
        return render_template('passwords.html', passwords=passwords)
    
    except Exception as e:
        app.logger.error(f"Error retrieving passwords: {str(e)}")
        return render_template('passwords.html', passwords=[], error=str(e))

@app.route('/api/passwords')
def api_passwords():
    """API endpoint for monitoring purposes"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM passwords')
        count = cursor.fetchone()[0]
        conn.close()

        return jsonify({
            'total_passwords': count,
            'status': 'healthy',
            'storage_type': 'sqlite',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        app.logger.error(f"API error: {str(e)}")
        return jsonify({'error': str(e), 'status': 'unhealthy'}), 500

@app.route('/delete/<int:password_id>', methods=['POST'])
def delete_password(password_id):
    """Delete a password entry"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM passwords WHERE id = ?', (password_id,))
        conn.commit()
        conn.close()
        return redirect(url_for('view_passwords'))
    except Exception as e:
        app.logger.error(f"Error deleting password: {str(e)}")
        return redirect(url_for('view_passwords'))

@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT 1')
        conn.close()
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        app.logger.error(f"Health check failed: {str(e)}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@app.route('/favicon.ico')
def favicon():
    """Handle favicon requests"""
    return '', 204

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('index.html', error='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Internal error: {str(error)}")
    return render_template('index.html', error='Internal server error'), 500

@app.errorhandler(405)
def method_not_allowed(error):
    return render_template('index.html', error='Method not allowed'), 405

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Run the application
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
