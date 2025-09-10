from flask import Flask, render_template, request, jsonify, redirect, url_for
import secrets
import string
from datetime import datetime
import os

app = Flask(__name__)

# In-memory storage for demo purposes (will reset on each deployment)
passwords_storage = []

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

        # Store in memory (temporary storage)
        password_entry = {
            'id': len(passwords_storage) + 1,
            'website': website,
            'username': username,
            'password': password,
            'length': length,
            'include_symbols': include_symbols,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        passwords_storage.append(password_entry)

        # Return success page with the generated password
        return render_template('result.html', 
                             password=password,
                             website=website,
                             username=username,
                             length=length,
                             include_symbols=include_symbols)
    
    except Exception as e:
        return render_template('index.html', error=f'An error occurred: {str(e)}')

@app.route('/api/generate', methods=['POST'])
def api_generate():
    """API endpoint for generating passwords (returns JSON)"""
    data = request.get_json() if request.is_json else request.form
    
    website = data.get('website', '').strip()
    username = data.get('username', '').strip()
    
    try:
        length = int(data.get('length', 12))
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid length parameter'}), 400
        
    include_symbols = bool(data.get('symbols', False))

    if not website:
        return jsonify({'error': 'Website is required'}), 400

    if length < 4 or length > 128:
        return jsonify({'error': 'Password length must be between 4 and 128'}), 400

    try:
        # Generate password
        password = generate_password(length, include_symbols)

        # Store in memory
        password_entry = {
            'id': len(passwords_storage) + 1,
            'website': website,
            'username': username,
            'password': password,
            'length': length,
            'include_symbols': include_symbols,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        passwords_storage.append(password_entry)

        return jsonify({
            'success': True,
            'password': password,
            'website': website,
            'username': username,
            'length': length
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/passwords')
def view_passwords():
    """View all stored passwords (from current session)"""
    try:
        # Sort by most recent first
        sorted_passwords = sorted(passwords_storage, key=lambda x: x['created_at'], reverse=True)
        return render_template('passwords.html', passwords=sorted_passwords)
    
    except Exception as e:
        return render_template('passwords.html', passwords=[], error=str(e))

@app.route('/api/passwords')
def api_passwords():
    """API endpoint for monitoring purposes - simple data retrieval"""
    try:
        return jsonify({
            'total_passwords': len(passwords_storage),
            'status': 'healthy',
            'storage_type': 'in-memory'
        })
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'unhealthy'}), 500

@app.route('/delete/<int:password_id>', methods=['POST'])
def delete_password(password_id):
    """Delete a password entry"""
    try:
        global passwords_storage
        passwords_storage = [p for p in passwords_storage if p['id'] != password_id]
        return redirect(url_for('view_passwords'))
    except Exception as e:
        return redirect(url_for('view_passwords'))

@app.route('/clear', methods=['POST'])
def clear_passwords():
    """Clear all stored passwords"""
    global passwords_storage
    passwords_storage = []
    return redirect(url_for('view_passwords'))

@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    try:
        return jsonify({
            'status': 'healthy',
            'storage': 'in-memory',
            'passwords_count': len(passwords_storage),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
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
    return render_template('index.html', error='Internal server error'), 500

@app.errorhandler(405)
def method_not_allowed(error):
    return render_template('index.html', error='Method not allowed'), 405

if __name__ == '__main__':
    # Run the application
    app.run(host='0.0.0.0', port=5000, debug=True)
