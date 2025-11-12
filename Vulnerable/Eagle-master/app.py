from flask import Flask, request, render_template, redirect, session, url_for, flash, jsonify
import os
from collections import defaultdict
from database import (
    init_db, get_db_connection, get_hidden_file, update_hidden_file,
    vulnerable_login, vulnerable_search_documents, vulnerable_get_user_by_id,
    vulnerable_get_documents_by_user, vulnerable_admin_query
)
from datetime import datetime
import re

app = Flask(__name__)
app.secret_key = 'eaglepro-demo-secret-key-2024'
app.debug = True

login_attempts = defaultdict(int)

# Danh sách user đặc biệt có hidden files
SPECIAL_USERS = ['HusThien_IA', 'Collie_Min', 'LazyBeo']

# 🛡️ SQL Injection Detection Functions - ĐẶT TRƯỚC CÁC ROUTE
def detect_sql_injection(input_string):
    """
    Phát hiện các pattern SQL Injection
    """
    if not input_string or not isinstance(input_string, str):
        return False

    # Pattern cải tiến - bắt nhiều dạng SQL injection hơn
    sql_patterns = [
        r'(\bUNION\b.*\bSELECT\b)',
        r'(\bSELECT\b.*\bFROM\b)',
        r'(\bINSERT\b.*\bINTO\b)',
        r'(\bDROP\b.*\bTABLE\b)',
        r'(\bDELETE\b.*\bFROM\b)',
        r'(\bUPDATE\b.*\bSET\b)',
        r'(\bOR\b.*[1-9]\b.*[=]\b.*[1-9]\b)',
        r'(\bAND\b.*[1-9]\b.*[=]\b.*[1-9]\b)',
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
        r'(\'\s*OR\s*\'.*\'\s*=\s*\')',
        r'(\"\s*OR\s*\".*\"\s*=\s*\")'
    ]

    input_upper = input_string.upper()

    for pattern in sql_patterns:
        try:
            if re.search(pattern, input_upper, re.IGNORECASE):
                print(f"🎯 Pattern matched: {pattern} in input: {input_string}")  # Debug
                return True
        except Exception as e:
            print(f"⚠️ Regex error for pattern {pattern}: {e}")
            continue

    return False

def log_sql_attempt(input_string, endpoint, user_id="unknown", ip="unknown"):
    """
    Ghi log cảnh báo SQL Injection
    """
    warning_msg = f"""
🚨 SQL INJECTION ATTEMPT DETECTED 🚨
Endpoint: {endpoint}
User ID: {user_id}
IP Address: {ip}
Input: {input_string}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
========================================="""
    print(warning_msg)  # Log ra server console (Docker terminal)

# 🎯 GLOBAL DEBUG - KIỂM TRA CODE MỚI CÓ CHẠY KHÔNG
print("✅ SQL Injection detection system INITIALIZED")

# Test detection function ngay khi khởi động
test_payload = "admin' --"
test_result = detect_sql_injection(test_payload)
print(f"✅ Startup test - Payload: '{test_payload}' -> Detected: {test_result}")

@app.route('/', methods=['GET', 'POST'])
def login():
    # 🎯 DEBUG: Log tất cả request đến /
    print(f"🎯 / endpoint called - Method: {request.method}")
    
    # Xử lý GET request - hiển thị form login
    if request.method == 'GET':
        print("🔍 GET request - Displaying login page")
        return render_template('login.html')
    
    # Xử lý POST request - xử lý đăng nhập
    print("🎯 POST request - Processing login form")
    
    try:
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        print(f"🔐 Login attempt received:")
        print(f"   Username: '{username}'")
        print(f"   Password: '{password}'")
        print(f"   Form data: {dict(request.form)}")
        
        # 🛡️ PHÁT HIỆN SQL INJECTION ATTEMPT TRONG LOGIN
        sql_detected_in_username = detect_sql_injection(username)
        sql_detected_in_password = detect_sql_injection(password)
        
        print(f"🔐 SQL Detection Results:")
        print(f"   Username detection: {sql_detected_in_username}")
        print(f"   Password detection: {sql_detected_in_password}")
        
        if sql_detected_in_username or sql_detected_in_password:
            user_id = session.get('user_id', 'pre-auth')
            ip = request.remote_addr
            log_sql_attempt(f"Username: {username}, Password: {password}", '/login', user_id, ip)
            print("🚨 SQL Injection detected and logged in login!")
        
        # ❌ VULNERABLE: Using vulnerable login function
        print("🔑 Calling vulnerable_login function...")
        user = vulnerable_login(username, password)
        print(f"🔑 Login result: {user}")
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['avatar'] = user['avatar']
            session['is_admin'] = bool(user['is_admin'])
            session['full_name'] = user['full_name']
            
            print(f"🔓 LOGIN SUCCESS - User: {user['username']} (ID: {user['id']})")
            print("🔄 Redirecting to dashboard...")
            return redirect('/dashboard')
        else:
            print("❌ LOGIN FAILED - Invalid credentials")
            flash('Invalid username or password!', 'error')
            return render_template('login.html'), 200
            
    except Exception as e:
        print(f"💥 LOGIN ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f'System error: {e}', 'error')
        return render_template('login.html'), 200

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')

    try:
        # ❌ VULNERABLE: Using vulnerable document retrieval
        user_docs = vulnerable_get_documents_by_user(session['user_id'])

        # Lấy tất cả users (vẫn dùng parameterized cho phần này để app chạy ổn)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, full_name, avatar, department, position FROM users')
        all_users = cursor.fetchall()

        cursor.execute('SELECT * FROM documents')
        all_docs_result = cursor.fetchall()
        conn.close()

        # Kiểm tra nếu user có hidden file
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
    """Admin view to see all documents in the system"""
    if 'user_id' not in session:
        return redirect('/')

    if not session.get('is_admin'):
        flash('Access denied. Administrator privileges required.', 'error')
        return redirect('/dashboard')

    try:
        # ❌ VULNERABLE: Direct SQL string concatenation
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
        # ❌ VULNERABLE: String formatting in query
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

        # ❌ VULNERABILITY: No access control check - IDOR
        is_vulnerable = doc['user_id'] != session['user_id']

        # Lấy danh sách documents của user HIỆN TẠI (để navigation)
        user_docs = vulnerable_get_documents_by_user(session['user_id'])

        conn.close()

        # Tìm previous và next document trong danh sách của user
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
                # Document hiện tại không thuộc về user - không có navigation
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

# Search route with SQL Injection vulnerability
@app.route('/search')
def search_documents():
    """Vulnerable search endpoint for SQL Injection demo"""
    if 'user_id' not in session:
        return redirect('/')

    # NHẬN CẢ 'q' VÀ 'query' ĐỂ XỬ LÝ CẢ 2 TRƯỜNG HỢP
    search_term = request.args.get('q', '') or request.args.get('query', '')

    # 🛡️ PHÁT HIỆN SQL INJECTION ATTEMPT
    sql_injection_detected = False
    if search_term and detect_sql_injection(search_term):
        user_id = session.get('user_id', 'unknown')
        ip = request.remote_addr
        log_sql_attempt(search_term, '/search', user_id, ip)
        sql_injection_detected = True

    if search_term:
        try:
            # ❌ VULNERABLE: Direct string concatenation in SQL query
            conn = get_db_connection()
            cursor = conn.cursor()

            query = f"""
                SELECT d.*, u.username
                FROM documents d
                JOIN users u ON d.user_id = u.id
                WHERE d.title LIKE '%{search_term}%'
                OR d.content LIKE '%{search_term}%'
                OR d.doc_type LIKE '%{search_term}%'
            """
            cursor.execute(query)
            results = cursor.fetchall()
            conn.close()

            return render_template(
                'search_results.html',
                search_term=search_term,
                results=results,
                username=session['username'],
                user_id=session['user_id'],
                current_user_avatar=session.get('avatar', 'husthi_avatar.png'),
                sql_injection_detected=sql_injection_detected
            )
        except Exception as e:
            print(f"Search error: {e}")
            flash('An error occurred during search.', 'error')
            return redirect('/dashboard')

    # Nếu không có search term, render trang search
    return render_template('search.html',
                         username=session['username'],
                         user_id=session['user_id'],
                         current_user_avatar=session.get('avatar', 'husthi_avatar.png'))

@app.route('/profile/<user_id>')
def user_profile(user_id):
    """Vulnerable user profile endpoint - SQL Injection demo"""
    if 'user_id' not in session:
        return redirect('/')

    # ❌ VULNERABLE: Direct user_id usage in query
    user = vulnerable_get_user_by_id(user_id)

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
    """Dangerously vulnerable admin query interface - EXTREME SQL Injection risk"""
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Admin access required!', 'error')
        return redirect('/dashboard')

    sql_query = request.args.get('sql', '')
    results = None
    error = None

    if sql_query:
        try:
            # ❌❌❌ EXTREMELY VULNERABLE: Direct SQL execution
            results = vulnerable_admin_query(sql_query)
        except Exception as e:
            error = str(e)

    return render_template(
        'admin_query.html',
        sql_query=sql_query,
        results=results,
        error=error,
        username=session['username'],
        current_user_avatar=session.get('avatar', 'admin_avatar.png')
    )

# Hidden Files Routes (keep these secure for functionality)
@app.route('/hidden-file')
def hidden_file():
    """Trang xem và chỉnh sửa file ẩn"""
    if 'user_id' not in session:
        return redirect('/')

    # Chỉ cho phép user đặc biệt
    if session['username'] not in SPECIAL_USERS:
        flash('Access denied. Hidden files are only available for special users.', 'error')
        return redirect('/dashboard')

    try:
        hidden_file = get_hidden_file(session['user_id'])

        if not hidden_file:
            # Tạo hidden file mới nếu chưa có
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
    """Cập nhật nội dung file ẩn"""
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
    """Tạo hidden file mới (nếu chưa có)"""
    if 'user_id' not in session:
        return redirect('/')

    if session['username'] not in SPECIAL_USERS:
        return redirect('/dashboard')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Tạo hidden file mới
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
    """Debug endpoint to check database status"""
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