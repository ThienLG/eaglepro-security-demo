from flask import Flask, request, render_template, redirect, session, url_for, flash, jsonify
import time
import os
from collections import defaultdict
from database import (
    init_db, get_db_connection, get_hidden_file, update_hidden_file,
    safe_login, safe_search_documents, safe_get_user_by_id,
    safe_get_documents_by_user, safe_admin_query
)
from datetime import datetime
import re

app = Flask(__name__)
app.secret_key = 'eaglepro-demo-secret-key-2024'
app.debug = True

# ==================== SECURITY HEADERS ====================
@app.after_request
def set_security_headers(response):
    """
    🛡️ Thêm Security Headers cho mọi response
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    return response

# ==================== RATE LIMITING ====================
rate_limit_storage = {}

def check_rate_limit(identifier, limit=5, window=60):
    """
    🛡️ Kiểm tra rate limiting cho một identifier (IP hoặc user_id)
    """
    now = time.time()
    window_start = now - window
    
    if identifier in rate_limit_storage:
        rate_limit_storage[identifier] = [
            req_time for req_time in rate_limit_storage[identifier] 
            if req_time > window_start
        ]
    else:
        rate_limit_storage[identifier] = []
    
    current_requests = len(rate_limit_storage[identifier])
    
    if current_requests >= limit:
        oldest_request = min(rate_limit_storage[identifier])
        reset_time = oldest_request + window
        return True, 0, reset_time
    else:
        rate_limit_storage[identifier].append(now)
        return False, limit - current_requests - 1, now + window

def get_client_identifier():
    return request.remote_addr

@app.before_request
def apply_rate_limiting():
    """
    🛡️ Áp dụng rate limiting cho các endpoint quan trọng
    """
    print(f"🔍 Rate Limiting Check: {request.endpoint} - {request.method} - {request.path}")
    
    if request.endpoint == 'login' and request.method == 'POST':
        identifier = get_client_identifier()
        print(f"🔄 LOGIN Rate Limiting for: {identifier}")
        
        is_blocked, remaining, reset_time = check_rate_limit(
            f"login_{identifier}", 
            limit=3,
            window=15
        )
        
        print(f"   Login Blocked: {is_blocked}, Remaining: {remaining}")
        
        if is_blocked:
            wait_seconds = int(reset_time - time.time())
            flash(f'Too many login attempts. Please try again in {wait_seconds} seconds.', 'error')
            return render_template('login.html'), 429

    elif request.endpoint == 'search_documents' and request.method == 'GET':
        identifier = get_client_identifier()
        print(f"🔍 SEARCH Rate Limiting for: {identifier}")
        
        is_blocked, remaining, reset_time = check_rate_limit(
            f"search_{identifier}",
            limit=10,
            window=15
        )
        
        print(f"   Search Blocked: {is_blocked}, Remaining: {remaining}")
        
        if is_blocked:
            wait_seconds = int(reset_time - time.time())
            return jsonify({
                'error': 'Rate limited',
                'message': f'Too many search requests. Please wait {wait_seconds} seconds.',
                'retry_after': wait_seconds
            }), 429

# Danh sách user đặc biệt có hidden files
SPECIAL_USERS = ['HusThien_IA', 'Collie_Min', 'LazyBeo']

def enhanced_sql_injection_detection(input_string):
    """
    Phát hiện SQL Injection nâng cao với nhiều pattern hơn
    """
    if not input_string or not isinstance(input_string, str):
        return False

    sql_patterns = [
        r'(\bUNION\b.*\bSELECT\b)',
        r'(\bSELECT\b.*\bFROM\b)',
        r'(\bINSERT\b.*\bINTO\b)',
        r'(\bDROP\b.*\bTABLE\b)',
        r'(\bDELETE\b.*\bFROM\b)',
        r'(\bUPDATE\b.*\bSET\b)',
        r'(\bOR\b.*[1-9=])',
        r'(\bAND\b.*[1-9=])',
        r'(\-\-.*)',
        r'(\;.*)',
        r'(\/\*.*\*\/)',
        r'(\bSLEEP\b.*\()',
        r'(\bBENCHMARK\b.*\()',
        r'(\bWAITFOR\b.*\bDELAY\b)',
        r'(\bEXEC\b.*\()',
        r'(\bXP_CMDSHELL\b)',
        r'(\bCREATE\b.*\bTABLE\b)',
        r'(\bALTER\b.*\bTABLE\b)',
        r'(\bTRUNCATE\b.*\bTABLE\b)',
        r'(1\s*=\s*1)',
        r'(\'\s*OR\s*\')',
        r'(\"\s*OR\s*\")',
        r'(\bSELECT\b.*\bFROM\b.*\bWHERE\b.*\b1\b.*\=\b.*\1\b)',
        r'(\bUNION\b.*\bALL\b.*\bSELECT\b)',
        r'(\bCONCAT\b.*\()',
        r'(\bGROUP_CONCAT\b.*\()',
        r'(\bINFORMATION_SCHEMA\b)',
        r'(\bLOAD_FILE\b.*\()',
        r'(\bOUTFILE\b)',
        r'(\bDUMPFILE\b)'
    ]

    input_upper = input_string.upper()
    
    for pattern in sql_patterns:
        try:
            if re.search(pattern, input_upper, re.IGNORECASE | re.DOTALL):
                return True
        except Exception:
            continue

    suspicious_sequences = [
        '/*', '*/', '--', ';', '\'', '"', '`',
        '||', '&&', '@@', '@'
    ]
    
    if any(seq in input_string for seq in suspicious_sequences):
        suspicious_chars = sum(1 for char in input_string if char in ['\'', '"', ';', '-', '#'])
        if suspicious_chars > 3:
            return True

    return False

def detect_sql_injection(input_string):
    return enhanced_sql_injection_detection(input_string)

def log_sql_attempt(input_string, endpoint, user_id="unknown", ip="unknown"):
    """
    Ghi log cảnh báo SQL Injection với format rõ ràng
    """
    warning_msg = f"""
🚨 SQL INJECTION ATTEMPT DETECTED 🚨
Endpoint: {endpoint}
User ID: {user_id}
IP Address: {ip}
Input: {input_string}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
========================================="""
    print(warning_msg)

print("✅ SQL Injection detection system INITIALIZED")

test_payload = "admin' --"
test_result = detect_sql_injection(test_payload)
print(f"✅ Startup test - Payload: '{test_payload}' -> Detected: {test_result}")

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    try:
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        print(f"🔐 Login attempt from {request.remote_addr}")
        print(f"   Username: '{username}'")
        
        # 🛡️ SQL INJECTION DETECTION
        sql_detected = detect_sql_injection(username) or detect_sql_injection(password)
        
        if sql_detected:
            user_id = session.get('user_id', 'pre-auth')
            ip = request.remote_addr
            log_sql_attempt(f"Username: {username}, Password: {password}", '/login', user_id, ip)
            
            identifier = get_client_identifier()
            check_rate_limit(f"login_{identifier}", limit=3, window=60)
            
            flash('Security violation detected. Please use valid credentials.', 'error')
            return render_template('login.html'), 200
        
        # ✅ SAFE LOGIN
        user = safe_login(username, password)
        
        if user:
            identifier = get_client_identifier()
            if f"login_{identifier}" in rate_limit_storage:
                del rate_limit_storage[f"login_{identifier}"]
            
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['avatar'] = user['avatar']
            session['is_admin'] = bool(user['is_admin'])
            session['full_name'] = user['full_name']
            
            print(f"🔓 LOGIN SUCCESS - User: {user['username']} from {request.remote_addr}")
            return redirect('/dashboard')
        else:
            print(f"❌ LOGIN FAILED - Invalid credentials from {request.remote_addr}")
            flash('Invalid username or password!', 'error')
            return render_template('login.html'), 200
            
    except Exception as e:
        print(f"💥 LOGIN ERROR: {str(e)}")
        flash('System error occurred. Please try again.', 'error')
        return render_template('login.html'), 200

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')

    try:
        user_docs = safe_get_documents_by_user(session['user_id'])

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, full_name, avatar, department, position FROM users')
        all_users = cursor.fetchall()

        cursor.execute('SELECT * FROM documents')
        all_docs_result = cursor.fetchall()
        conn.close()

        has_hidden_file = session['username'] in SPECIAL_USERS

        return render_template(
            'dashboard.html',
            username=session['username'],
            user_id=session['user_id'],
            current_user_avatar=session.get('avatar', 'husthi_avatar.png'),
            user_docs=user_docs,
            all_users=all_users,
            all_docs=all_docs_result,
            total_docs=len(all_docs_result),
            is_admin=session.get('is_admin', False),
            has_hidden_file=has_hidden_file,
            special_users=SPECIAL_USERS
        )
    except Exception as e:
        print(f"🚨 Dashboard error: {e}")
        return f"Dashboard error: {e}", 500

@app.route('/admin/documents')
def admin_documents():
    if 'user_id' not in session:
        return redirect('/')

    if not session.get('is_admin'):
        flash('Access denied. Administrator privileges required.', 'error')
        return redirect('/dashboard')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        query = f"""
            SELECT d.*, u.username, u.full_name, u.avatar
            FROM documents d
            JOIN users u ON d.user_id = u.id
            ORDER BY d.created_date DESC
        """
        cursor.execute(query)
        all_documents = cursor.fetchall()
        conn.close()

        return render_template(
            'admin_documents.html',
            username=session['username'],
            user_id=session['user_id'],
            current_user_avatar=session.get('avatar', 'admin_avatar.png'),
            all_documents=all_documents,
            total_documents=len(all_documents)
        )
    except Exception as e:
        print(f"🚨 Admin documents error: {e}")
        return f"Admin documents error: {e}", 500

@app.route('/document/<int:doc_id>')
def view_document(doc_id):
    if 'user_id' not in session:
        return redirect('/')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        query = f"""
            SELECT d.*, u.username, u.full_name
            FROM documents d
            JOIN users u ON d.user_id = u.id
            WHERE d.id = {doc_id}
        """
        cursor.execute(query)
        doc = cursor.fetchone()

        if not doc:
            return "Document not found", 404

        is_vulnerable = doc['user_id'] != session['user_id']

        user_docs = safe_get_documents_by_user(session['user_id'])

        conn.close()

        user_doc_ids = [doc['id'] for doc in user_docs]

        prev_doc_id = None
        next_doc_id = None

        if user_doc_ids:
            try:
                current_index = user_doc_ids.index(doc_id)
                if current_index > 0:
                    prev_doc_id = user_doc_ids[current_index - 1]
                if current_index < len(user_doc_ids) - 1:
                    next_doc_id = user_doc_ids[current_index + 1]
            except ValueError:
                pass

        return render_template(
            'document.html',
            doc=dict(doc),
            current_user_avatar=session.get('avatar', 'husthi_avatar.png'),
            username=session['username'],
            user_id=session['user_id'],
            is_admin=session.get('is_admin', False),
            is_vulnerable=is_vulnerable,
            prev_doc_id=prev_doc_id,
            next_doc_id=next_doc_id
        )
    except Exception as e:
        print(f"ERROR: {e}")
        return f"Error: {e}", 500

@app.route('/search')
def search_documents():
    if 'user_id' not in session:
        return redirect('/')

    search_term = request.args.get('q', '') or request.args.get('query', '')
    
    sql_injection_detected = False
    if search_term and detect_sql_injection(search_term):
        user_id = session.get('user_id', 'unknown')
        ip = request.remote_addr
        log_sql_attempt(search_term, '/search', user_id, ip)
        sql_injection_detected = True
        
        return render_template(
            'search_results.html',
            search_term=search_term,
            results=[],
            sql_injection_detected=True,
            blocked=True,
            username=session['username'],
            user_id=session['user_id'],
            current_user_avatar=session.get('avatar', 'husthi_avatar.png')
        )

    if search_term:
        try:
            results = safe_search_documents(search_term)
            return render_template(
                'search_results.html',
                search_term=search_term,
                results=results,
                sql_injection_detected=sql_injection_detected,
                blocked=False,
                username=session['username'],
                user_id=session['user_id'],
                current_user_avatar=session.get('avatar', 'husthi_avatar.png')
            )
        except Exception as e:
            print(f"Search error: {e}")
            flash('An error occurred during search.', 'error')
            return redirect('/dashboard')

    return render_template('search.html',
                         username=session['username'],
                         user_id=session['user_id'],
                         current_user_avatar=session.get('avatar', 'husthi_avatar.png'))

@app.route('/profile/<user_id>')
def user_profile(user_id):
    if not user_id.isdigit():
        flash('Invalid user ID format', 'error')
        return redirect('/dashboard')
    
    user = safe_get_user_by_id(user_id)
    
    if user:
        return render_template(
            'user_profile.html',
            profile_user=dict(user),
            username=session['username'],
            current_user_avatar=session.get('avatar', 'husthi_avatar.png')
        )
    else:
        flash('User not found!', 'error')
        return redirect('/dashboard')

@app.route('/admin/query')
def admin_query():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Admin access required!', 'error')
        return redirect('/dashboard')

    sql_query = request.args.get('sql', '')
    results = None
    error = None

    if sql_query:
        if detect_sql_injection(sql_query):
            log_sql_attempt(sql_query, '/admin/query', session['user_id'], request.remote_addr)
        
        results = safe_admin_query(sql_query)

    return render_template(
        'admin_query.html',
        sql_query=sql_query,
        results=results,
        error=error,
        username=session['username'],
        current_user_avatar=session.get('avatar', 'admin_avatar.png')
    )

@app.route('/hidden-file')
def hidden_file():
    if 'user_id' not in session:
        return redirect('/')

    if session['username'] not in SPECIAL_USERS:
        flash('Access denied. Hidden files are only available for special users.', 'error')
        return redirect('/dashboard')

    try:
        hidden_file = get_hidden_file(session['user_id'])

        if not hidden_file:
            return redirect('/create-hidden-file')

        return render_template(
            'hidden_file.html',
            hidden_file=dict(hidden_file),
            username=session['username'],
            user_id=session['user_id'],
            current_user_avatar=session.get('avatar', 'husthi_avatar.png'),
            is_admin=session.get('is_admin', False)
        )
    except Exception as e:
        print(f"🚨 Hidden file error: {e}")
        return f"Hidden file error: {e}", 500

@app.route('/update-hidden-file', methods=['POST'])
def update_hidden_file_route():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'})

    if session['username'] not in SPECIAL_USERS:
        return jsonify({'success': False, 'error': 'Access denied'})

    try:
        content = request.form.get('content', '')
        title = request.form.get('title', '🔒 My Secret File')

        update_hidden_file(session['user_id'], title, content)

        return jsonify({
            'success': True,
            'message': 'File updated successfully!',
            'last_modified': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })

    except Exception as e:
        print(f"🚨 Update hidden file error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/create-hidden-file')
def create_hidden_file():
    if 'user_id' not in session:
        return redirect('/')

    if session['username'] not in SPECIAL_USERS:
        return redirect('/dashboard')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        default_content = f"""# 🎉 Welcome to Your Hidden File, {session['username']}!

This is your personal secret space. You can write anything here!

## Ideas for your hidden file:
- Secret notes 📝
- Personal diary 📓
- Important links 🔗
- Code snippets 💻
- Project ideas 💡
- Password hints (be careful!) 🔐
- Private thoughts 🤫

Your content is automatically saved and only visible to you!"""

        cursor.execute('''
            INSERT INTO hidden_files (user_id, title, content, created_date, last_modified)
            VALUES (?, ?, ?, ?, ?)
        ''', (session['user_id'], '🔒 My Secret File', default_content,
              datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
              datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

        conn.commit()
        conn.close()

        flash('Hidden file created successfully!', 'success')
        return redirect('/hidden-file')

    except Exception as e:
        print(f"🚨 Create hidden file error: {e}")
        return f"Create hidden file error: {e}", 500

@app.route('/debug')
def debug():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM users')
        users = cursor.fetchall()

        cursor.execute('SELECT * FROM documents')
        docs = cursor.fetchall()

        cursor.execute('SELECT * FROM hidden_files')
        hidden_files = cursor.fetchall()

        conn.close()

        result = {
            'users': [dict(user) for user in users],
            'documents': [dict(doc) for doc in docs],
            'hidden_files': [dict(hf) for hf in hidden_files],
            'total_users': len(users),
            'total_documents': len(docs),
            'total_hidden_files': len(hidden_files),
            'database_type': 'SQLite',
            'special_users': SPECIAL_USERS
        }
        return result
    except Exception as e:
        return {'error': str(e)}

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    print("🚀 Initializing SQLite database...")
    init_db()
    print("🚀 First American EaglePro IDOR & SQL Injection Vulnerability Demo Starting...")
    print("📧 Available Accounts:")
    print("   - Admin: admin / admin123")
    print("   - HusThi IA: HusThien_IA / Thi2104en (⭐ SPECIAL USER)")
    print("   - Collie Minh: Collie_Min / Mi1304nh (⭐ SPECIAL USER)")
    print("   - LazyBeo: LazyBeo / HuhWhatIsPass (⭐ SPECIAL USER)")
    print("   - User1: user1 / pass123")
    print("   - User2: user2 / pass123")
    print("💉 SQL Injection Vulnerabilities:")
    print("   - Login bypass: admin' --")
    print("   - Search injection: ' UNION SELECT * FROM users--")
    print("   - Admin query: Direct SQL execution at /admin/query")
    print("💥 Access at: http://localhost:5000")
    print("🔓 IDOR VULNERABILITY: Users can access any document by changing the ID in URL")
    print("🔒 HIDDEN FILES: Available for 3 special users with secret file access")

    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)