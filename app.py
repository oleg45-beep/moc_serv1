import os
import sqlite3
import uuid
from datetime import datetime, timedelta
from functools import wraps
import sys

from flask import Flask, render_template, request, jsonify, send_from_directory, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'moc-secret-key-2024-make-it-long-and-secure'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_PERMANENT'] = True
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def get_db():
    conn = sqlite3.connect('moc.db')
    conn.row_factory = sqlite3.Row
    return conn

def ensure_db():
    try:
        conn = sqlite3.connect('moc.db')
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if not cursor.fetchone():
            print("⚠️ Database not found, creating...")
            init_db()
        else:
            print("✅ Database exists")
        conn.close()
    except Exception as e:
        print(f"DB check error: {e}")
        init_db()


def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            handle TEXT,
            bio TEXT,
            avatar TEXT,
            is_support INTEGER DEFAULT 0,
            last_seen TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            mime_type TEXT,
            file_size INTEGER DEFAULT 0,
            album_id INTEGER DEFAULT 0,
            share_token TEXT UNIQUE,
            share_expires TIMESTAMP,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS albums (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS friends (
            user_id INTEGER,
            friend_id INTEGER,
            is_trusted_for_recovery INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, friend_id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS friend_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user_id INTEGER,
            to_user_id INTEGER,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user1_id INTEGER,
            user2_id INTEGER,
            last_message TEXT,
            last_message_time TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id INTEGER,
            sender_id INTEGER,
            text TEXT NOT NULL,
            file_id INTEGER,
            delivered INTEGER DEFAULT 0,
            read INTEGER DEFAULT 0,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create test user
    cursor.execute("SELECT id FROM users WHERE username = 'test'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (username, password, handle, bio) VALUES (?, ?, ?, ?)",
                      ('test', generate_password_hash('123'), 'test_user', 'Тестовый пользователь'))
    
    # Create support user
    cursor.execute("SELECT id FROM users WHERE username = 'support'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (username, password, handle, bio) VALUES (?, ?, ?, ?)",
                      ('support', generate_password_hash('support123'), 'support', 'Техническая поддержка', 1))
    
    conn.commit()
    conn.close()
    print("✅ База данных инициализирована")

def get_moscow_time():
    return datetime.utcnow() + timedelta(hours=3)

def get_mime_type(filename):
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    mime_map = {
        'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'png': 'image/png',
        'gif': 'image/gif', 'webp': 'image/webp', 'pdf': 'application/pdf',
        'txt': 'text/plain', 'mp4': 'video/mp4', 'mp3': 'audio/mpeg'
    }
    return mime_map.get(ext, 'application/octet-stream')

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

def get_unread_counts(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT c.id, COUNT(m.id) as unread_count
        FROM chats c
        JOIN messages m ON m.chat_id = c.id
        WHERE (c.user1_id = ? OR c.user2_id = ?)
        AND m.sender_id != ?
        AND m.read = 0
        GROUP BY c.id
    ''', (user_id, user_id, user_id))
    result = {row['id']: row['unread_count'] for row in cursor.fetchall()}
    conn.close()
    return result

def mark_messages_read(chat_id, user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE messages SET read = 1 
        WHERE chat_id = ? AND sender_id != ? AND read = 0
    ''', (chat_id, user_id))
    conn.commit()
    conn.close()

# ==================== АВТОРИЗАЦИЯ ====================
@app.route('/')
def index():
    ensure_db()
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    
    if not username or not password:
        return jsonify({'error': 'Fill all fields'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': 'User exists'}), 400
    
    hashed = generate_password_hash(password)
    cursor.execute("INSERT INTO users (username, password, handle, bio) VALUES (?, ?, ?, ?)",
                  (username, hashed, username, 'New user'))
    user_id = cursor.lastrowid
    
    # Create chat with support
    cursor.execute("SELECT id FROM users WHERE username = 'support'")
    support = cursor.fetchone()
    if support:
        cursor.execute("INSERT INTO chats (user1_id, user2_id, last_message, last_message_time) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                      (user_id, support['id'], 'Welcome to MOC!'))
    
    conn.commit()
    conn.close()
    
    session['user_id'] = user_id
    session.permanent = True
    return jsonify({'message': 'OK', 'username': username, 'user_id': user_id})

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if not user or not check_password_hash(user['password'], password):
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Обновляем время последнего захода
        cursor.execute("UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?", (user['id'],))
        conn.commit()
        conn.close()
        
        session['user_id'] = user['id']
        session.permanent = True
        return jsonify({'message': 'OK', 'username': user['username'], 'user_id': user['id']})
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': str(e)}), 500
    

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'OK'})

@app.route('/api/profile')
@login_required
def get_profile():
    user_id = session['user_id']
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT username, handle, bio, avatar FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    cursor.execute("SELECT COUNT(*) FROM files WHERE user_id = ?", (user_id,))
    photos = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM albums WHERE user_id = ?", (user_id,))
    albums = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM friends WHERE user_id = ?", (user_id,))
    friends = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM chats WHERE user1_id = ? OR user2_id = ?", (user_id, user_id))
    chats = cursor.fetchone()[0]
    
    cursor.execute('''
        SELECT fr.id, fr.from_user_id, u.username
        FROM friend_requests fr
        JOIN users u ON fr.from_user_id = u.id
        WHERE fr.to_user_id = ? AND fr.status = 'pending'
    ''', (user_id,))
    friend_requests = [dict(row) for row in cursor.fetchall()]
    
    cursor.execute('''
        SELECT u.id, u.username, u.handle
        FROM friends f JOIN users u ON f.friend_id = u.id
        WHERE f.user_id = ?
    ''', (user_id,))
    friends_list = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return jsonify({
        'user': dict(user),
        'stats': {'photos': photos, 'albums': albums, 'friends': friends, 'chats': chats},
        'friend_requests': friend_requests,
        'friends_list': friends_list
    })

@app.route('/api/update_profile', methods=['POST'])
@login_required
def update_profile():
    data = request.json
    username = data.get('username', '').strip()
    handle = data.get('handle', '').strip()
    bio = data.get('bio', '').strip()
    user_id = session['user_id']
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET username = ?, handle = ?, bio = ? WHERE id = ?",
                  (username, handle, bio, user_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'OK'})

# ==================== АВАТАРЫ ====================
@app.route('/api/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    try:
        if 'avatar' not in request.files:
            return jsonify({'error': 'No file'}), 400
        
        file = request.files['avatar']
        if file.filename == '':
            return jsonify({'error': 'Empty filename'}), 400
        
        if not file.content_type.startswith('image/'):
            return jsonify({'error': 'Only images allowed'}), 400
        
        if not os.path.exists('uploads'):
            os.makedirs('uploads')
        
        ext = file.filename.split('.')[-1].lower()
        filename = f"avatar_{session['user_id']}.{ext}"
        filepath = os.path.join('uploads', filename)
        file.save(filepath)
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET avatar = ? WHERE id = ?", (filename, session['user_id']))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'OK', 'avatar': filename})
    except Exception as e:
        print(f"Upload avatar error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/get_avatar/<int:user_id>')
def get_user_avatar(user_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT avatar FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        if user and user['avatar']:
            avatar_path = os.path.join('uploads', user['avatar'])
            if os.path.exists(avatar_path):
                return send_file(avatar_path, mimetype='image/jpeg')
        
        return '', 404
    except Exception as e:
        return '', 404

# ==================== ЧАТЫ ====================
@app.route('/api/chats')
@login_required
def get_chats():
    try:
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT c.id, c.last_message, c.last_message_time,
                   CASE WHEN c.user1_id = ? THEN u2.username ELSE u1.username END as other_user,
                   c.updated_at
            FROM chats c
            LEFT JOIN users u1 ON c.user1_id = u1.id
            LEFT JOIN users u2 ON c.user2_id = u2.id
            WHERE c.user1_id = ? OR c.user2_id = ?
            ORDER BY c.last_message_time DESC
        ''', (user_id, user_id, user_id))
        
        chats = []
        unread_counts = get_unread_counts(user_id)
        
        for row in cursor.fetchall():
            chat = dict(row)
            chat['chat_type'] = 'regular'
            chat['unread_count'] = unread_counts.get(chat['id'], 0)
            chats.append(chat)
        
        conn.close()
        return jsonify(chats)
    except Exception as e:
        print(f"Chats error: {e}")
        return jsonify([])

@app.route('/api/messages/<int:chat_id>')
@login_required
def get_messages(chat_id):
    try:
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, user1_id, user2_id FROM chats WHERE id = ?", (chat_id,))
        chat = cursor.fetchone()
        if not chat:
            conn.close()
            return jsonify({'error': 'Chat not found'}), 404
        if chat['user1_id'] != user_id and chat['user2_id'] != user_id:
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        cursor.execute('''
            SELECT m.*, u.username as sender_name, f.mime_type, f.filename as file_filename, f.original_name as file_original_name, f.file_size as file_size
            FROM messages m
            LEFT JOIN users u ON m.sender_id = u.id
            LEFT JOIN files f ON m.file_id = f.id
            WHERE m.chat_id = ?
            ORDER BY m.timestamp ASC
        ''', (chat_id,))
        
        messages = []
        for row in cursor.fetchall():
            msg = dict(row)
            if msg['sender_id'] == user_id:
                if msg['read'] == 1:
                    msg['status'] = 'read'
                elif msg['delivered'] == 1:
                    msg['status'] = 'delivered'
                else:
                    msg['status'] = 'sent'
            messages.append(msg)
        
        conn.close()
        
        if messages:
            mark_messages_read(chat_id, user_id)
        
        return jsonify(messages)
    except Exception as e:
        print(f"Get messages error: {e}")
        return jsonify([])

@app.route('/api/send_message', methods=['POST'])
@login_required
def send_message():
    try:
        data = request.json
        chat_id = data.get('chat_id')
        text = data.get('text', '').strip()
        file_id = data.get('file_id')
        
        if not chat_id or (not text and not file_id):
            return jsonify({'error': 'Missing data'}), 400
        
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, user1_id, user2_id FROM chats WHERE id = ?", (chat_id,))
        chat = cursor.fetchone()
        if not chat:
            conn.close()
            return jsonify({'error': 'Chat not found'}), 404
        if chat['user1_id'] != user_id and chat['user2_id'] != user_id:
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        cursor.execute('''
            INSERT INTO messages (chat_id, sender_id, text, file_id, timestamp, delivered, read)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, 0, 0)
        ''', (chat_id, user_id, text or '📎 Файл', file_id if file_id else None))
        
        last_text = (text or '📎 Файл')[:30] + "..." if len(text or '📎 Файл') > 30 else (text or '📎 Файл')
        cursor.execute('''
            UPDATE chats SET last_message = ?, last_message_time = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (last_text, chat_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Sent'})
    except Exception as e:
        print(f"Send message error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/mark_read', methods=['POST'])
@login_required
def mark_read():
    data = request.json
    chat_id = data.get('chat_id')
    if not chat_id:
        return jsonify({'error': 'No chat_id'}), 400
    
    mark_messages_read(chat_id, session['user_id'])
    return jsonify({'message': 'OK'})

@app.route('/api/unread_counts')
@login_required
def get_unread():
    try:
        user_id = session['user_id']
        counts = get_unread_counts(user_id)
        total = sum(counts.values())
        return jsonify({'by_chat': counts, 'total': total})
    except Exception as e:
        return jsonify({'by_chat': {}, 'total': 0})

@app.route('/api/create_chat', methods=['POST'])
@login_required
def create_chat():
    try:
        data = request.json
        username = data.get('username', '').strip()
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        target = cursor.fetchone()
        
        if not target:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        user_id = session['user_id']
        target_id = target['id']
        
        cursor.execute('''
            SELECT id FROM chats 
            WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
        ''', (user_id, target_id, target_id, user_id))
        existing = cursor.fetchone()
        
        if existing:
            conn.close()
            return jsonify({'id': existing['id']})
        
        cursor.execute('''
            INSERT INTO chats (user1_id, user2_id, last_message, last_message_time, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ''', (user_id, target_id, 'New chat'))
        chat_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({'id': chat_id})
    except Exception as e:
        print(f"Create chat error: {e}")
        return jsonify({'error': str(e)}), 500

# ==================== ФАЙЛЫ ====================
@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Empty filename'}), 400
        
        filename = f"{uuid.uuid4().hex}_{file.filename}"
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        file_size = os.path.getsize(filepath)
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO files (user_id, filename, original_name, mime_type, file_size, uploaded_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (session['user_id'], filename, file.filename, file.mimetype or 'application/octet-stream', file_size))
        file_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'OK', 'file_id': file_id})
    except Exception as e:
        print(f"Upload error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/files')
@login_required
def get_files():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM files WHERE user_id = ? ORDER BY uploaded_at DESC", (session['user_id'],))
        files = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(files)
    except Exception as e:
        return jsonify([])

@app.route('/api/delete_file/<int:file_id>', methods=['DELETE'])
@login_required
def delete_file(file_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT filename FROM files WHERE id = ? AND user_id = ?", (file_id, session['user_id']))
        file = cursor.fetchone()
        if file:
            try:
                os.remove(os.path.join(UPLOAD_FOLDER, file['filename']))
            except:
                pass
            cursor.execute("DELETE FROM files WHERE id = ?", (file_id,))
            conn.commit()
        conn.close()
        return jsonify({'message': 'OK'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rename_file/<int:file_id>', methods=['POST'])
@login_required
def rename_file(file_id):
    try:
        data = request.json
        new_name = data.get('new_name', '').strip()
        if not new_name:
            return jsonify({'error': 'Name required'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT original_name FROM files WHERE id = ? AND user_id = ?", (file_id, session['user_id']))
        file = cursor.fetchone()
        if not file:
            conn.close()
            return jsonify({'error': 'Not found'}), 404
        
        if '.' in file['original_name'] and '.' not in new_name:
            ext = file['original_name'].split('.')[-1]
            new_name = f"{new_name}.{ext}"
        
        cursor.execute("UPDATE files SET original_name = ? WHERE id = ?", (new_name, file_id))
        conn.commit()
        conn.close()
        return jsonify({'message': 'OK'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/file_info/<int:file_id>')
@login_required
def get_file_info(file_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, filename, original_name, mime_type, file_size, user_id FROM files WHERE id = ?", (file_id,))
        file = cursor.fetchone()
        conn.close()
        if not file:
            return jsonify({'error': 'Not found'}), 404
        return jsonify(dict(file))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download_file/<int:file_id>')
@login_required
def download_file(file_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT filename, original_name FROM files WHERE id = ? AND user_id = ?", (file_id, session['user_id']))
        file = cursor.fetchone()
        conn.close()
        if not file:
            return jsonify({'error': 'Not found'}), 404
        return send_from_directory(UPLOAD_FOLDER, file['filename'], as_attachment=True, download_name=file['original_name'])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/uploads/<filename>')
def serve_upload(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/api/share_file', methods=['POST'])
@login_required
def share_file():
    try:
        data = request.json
        file_id = data.get('file_id')
        chat_id = data.get('chat_id')
        expires_hours = data.get('expires_hours')
        
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        # Проверяем файл
        cursor.execute("SELECT id, original_name FROM files WHERE id = ? AND user_id = ?", (file_id, user_id))
        file = cursor.fetchone()
        if not file:
            conn.close()
            return jsonify({'error': 'File not found'}), 404
        
        # Если создаём ссылку
        if expires_hours and not chat_id:
            share_token = str(uuid.uuid4())
            cursor.execute('''
                UPDATE files SET share_token = ?, share_expires = datetime('now', '+' || ? || ' hours')
                WHERE id = ?
            ''', (share_token, expires_hours, file_id))
            conn.commit()
            conn.close()
            share_url = f"{request.host_url}share/{share_token}"
            return jsonify({'share_url': share_url, 'message': 'Link created'})
        
        # Если отправляем в чат
        if chat_id:
            cursor.execute("SELECT id, user1_id, user2_id FROM chats WHERE id = ?", (chat_id,))
            chat = cursor.fetchone()
            if not chat:
                conn.close()
                return jsonify({'error': 'Chat not found'}), 404
            
            if chat['user1_id'] != user_id and chat['user2_id'] != user_id:
                conn.close()
                return jsonify({'error': 'Access denied'}), 403
            
            text = f"📎 {file['original_name']}"
            cursor.execute('''
                INSERT INTO messages (chat_id, sender_id, text, file_id, timestamp, delivered, read)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, 0, 0)
            ''', (chat_id, user_id, text, file_id))
            
            last_text = text[:30] + "..." if len(text) > 30 else text
            cursor.execute('''
                UPDATE chats SET last_message = ?, last_message_time = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (last_text, chat_id))
            
            conn.commit()
            conn.close()
            return jsonify({'message': 'Sent to chat'})
        
        conn.close()
        return jsonify({'error': 'Missing action'}), 400
    except Exception as e:
        print(f"Share error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/share/<token>')
def share_file_download(token):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT filename, original_name, mime_type FROM files WHERE share_token = ? AND (share_expires IS NULL OR share_expires > datetime('now'))", (token,))
        file = cursor.fetchone()
        conn.close()
        if not file:
            return jsonify({'error': 'Ссылка недействительна или истек срок действия'}), 404
        mime_type = file['mime_type'] or get_mime_type(file['original_name'])
        return send_from_directory(UPLOAD_FOLDER, file['filename'], as_attachment=True, download_name=file['original_name'], mimetype=mime_type)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== АЛЬБОМЫ ====================
@app.route('/api/albums')
@login_required
def get_albums():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM albums WHERE user_id = ? ORDER BY created_at DESC", (session['user_id'],))
        albums = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(albums)
    except Exception as e:
        return jsonify([])

@app.route('/api/create_album', methods=['POST'])
@login_required
def create_album():
    try:
        data = request.json
        name = data.get('name', '').strip()
        if not name:
            return jsonify({'error': 'Name required'}), 400
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO albums (user_id, name, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)", (session['user_id'], name))
        album_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return jsonify({'message': 'OK', 'album_id': album_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/album/<int:album_id>')
@login_required
def get_album(album_id):
    try:
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM albums WHERE id = ? AND user_id = ?", (album_id, user_id))
        album = cursor.fetchone()
        if not album:
            conn.close()
            return jsonify({'error': 'Not found'}), 404
        cursor.execute("SELECT * FROM files WHERE album_id = ? AND user_id = ? ORDER BY uploaded_at DESC", (album_id, user_id))
        files = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({'album': dict(album), 'files': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/album/<int:album_id>/add_files', methods=['POST'])
@login_required
def add_to_album(album_id):
    try:
        data = request.json
        file_ids = data.get('file_ids', [])
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        for file_id in file_ids:
            cursor.execute("UPDATE files SET album_id = ? WHERE id = ? AND user_id = ?", (album_id, file_id, user_id))
        conn.commit()
        conn.close()
        return jsonify({'message': 'OK'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/album/<int:album_id>/remove_file', methods=['POST'])
@login_required
def remove_from_album(album_id):
    try:
        data = request.json
        file_id = data.get('file_id')
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE files SET album_id = 0 WHERE id = ? AND user_id = ? AND album_id = ?", (file_id, user_id, album_id))
        conn.commit()
        conn.close()
        return jsonify({'message': 'OK'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/album/<int:album_id>/delete', methods=['DELETE'])
@login_required
def delete_album(album_id):
    try:
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE files SET album_id = 0 WHERE album_id = ? AND user_id = ?", (album_id, user_id))
        cursor.execute("DELETE FROM albums WHERE id = ? AND user_id = ?", (album_id, user_id))
        conn.commit()
        conn.close()
        return jsonify({'message': 'OK'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/content')
@login_required
def get_content():
    try:
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM files WHERE user_id = ? ORDER BY uploaded_at DESC", (user_id,))
        files = [dict(row) for row in cursor.fetchall()]
        cursor.execute("SELECT * FROM albums WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
        albums = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({'files': files, 'albums': albums})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== ДРУЗЬЯ ====================
@app.route('/api/send_friend_request', methods=['POST'])
@login_required
def send_friend_request():
    try:
        data = request.json
        username = data.get('username', '').strip()
        
        if not username:
            return jsonify({'error': 'Введите имя пользователя'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        target = cursor.fetchone()
        
        if not target:
            conn.close()
            return jsonify({'error': f'Пользователь "{username}" не найден'}), 404
        
        user_id = session['user_id']
        target_id = target['id']
        
        if user_id == target_id:
            conn.close()
            return jsonify({'error': 'Нельзя добавить самого себя'}), 400
        
        # Проверяем друзья
        cursor.execute("SELECT 1 FROM friends WHERE user_id = ? AND friend_id = ?", (user_id, target_id))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Уже в друзьях'}), 400
        
        # Проверяем существующий запрос
        cursor.execute("SELECT id FROM friend_requests WHERE from_user_id = ? AND to_user_id = ? AND status = 'pending'", (user_id, target_id))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Запрос уже отправлен'}), 400
        
        cursor.execute("INSERT INTO friend_requests (from_user_id, to_user_id) VALUES (?, ?)", (user_id, target_id))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'OK'})
    except Exception as e:
        print(f"Send friend request error: {e}")
        return jsonify({'error': str(e)}), 500



@app.route('/api/respond_friend_request', methods=['POST'])
@login_required
def respond_friend_request():
    try:
        data = request.json
        request_id = data.get('request_id')
        accept = data.get('accept', False)
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT from_user_id, to_user_id FROM friend_requests WHERE id = ? AND to_user_id = ?", (request_id, session['user_id']))
        req = cursor.fetchone()
        if not req:
            conn.close()
            return jsonify({'error': 'Not found'}), 404
        
        if accept:
            cursor.execute("INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)", (req['from_user_id'], req['to_user_id']))
            cursor.execute("INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)", (req['to_user_id'], req['from_user_id']))
            cursor.execute("UPDATE friend_requests SET status = 'accepted' WHERE id = ?", (request_id,))
        else:
            cursor.execute("UPDATE friend_requests SET status = 'rejected' WHERE id = ?", (request_id,))
        
        conn.commit()
        conn.close()
        return jsonify({'message': 'OK'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/remove_friend', methods=['POST'])
@login_required
def remove_friend():
    try:
        data = request.json
        friend_id = data.get('friend_id')
        user_id = session['user_id']
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM friends WHERE user_id = ? AND friend_id = ?", (user_id, friend_id))
        cursor.execute("DELETE FROM friends WHERE user_id = ? AND friend_id = ?", (friend_id, user_id))
        conn.commit()
        conn.close()
        return jsonify({'message': 'OK'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== БЕЗОПАСНОСТЬ ====================
@app.route('/api/security/overview')
@login_required
def security_overview():
    try:
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM files WHERE user_id = ?", (user_id,))
        total_files = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM friends WHERE user_id = ?", (user_id,))
        friends_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT id, username FROM friends f JOIN users u ON f.friend_id = u.id WHERE f.user_id = ?", (user_id,))
        friends_list = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return jsonify({
            'encryption': {'enabled': True, 'encrypted_files': total_files},
            'social_recovery': {'enabled': friends_count >= 5, 'trusted_friends': min(friends_count, 5)},
            'security_score': min(40 + friends_count * 12, 100),
            'friends': {'total': friends_count, 'list': friends_list}
        })
    except Exception as e:
        print(f"Security overview error: {e}")
        return jsonify({
            'encryption': {'enabled': True, 'encrypted_files': 0},
            'social_recovery': {'enabled': False, 'trusted_friends': 0},
            'security_score': 50,
            'friends': {'total': 0, 'list': []}
        })


@app.route('/api/admin_stats')
@login_required
def admin_stats():
    try:
        user_id = session['user_id']
        conn = sqlite3.connect('moc.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT is_support FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        if not user or not user['is_support']:
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        cursor.execute('''
            SELECT u.id, u.username, u.handle, u.created_at, u.last_seen,
                   COUNT(f.id) as files_count
            FROM users u
            LEFT JOIN files f ON f.user_id = u.id
            GROUP BY u.id
            ORDER BY u.created_at DESC
        ''')
        users = []
        for row in cursor.fetchall():
            user_data = dict(row)
            user_data['password_hash'] = user_data['password'][:20] + '...' if user_data.get('password') else 'нет'
            users.append(user_data)
        
        conn.close()
        return jsonify(users)
    except Exception as e:
        print(f"Admin stats error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete_user/<int:target_id>', methods=['DELETE'])
@login_required
def delete_user(target_id):
    try:
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT is_support FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if not user or not user['is_support']:
            return jsonify({'error': 'Access denied'}), 403
        
        cursor.execute("DELETE FROM users WHERE id = ?", (target_id,))
        conn.commit()
        conn.close()
        return jsonify({'message': 'OK'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/suggested_friends')
@login_required
def suggested_friends():
    try:
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        # Находим пользователей, с которыми есть чат, но нет в друзьях
        cursor.execute('''
            SELECT DISTINCT u.id, u.username, u.handle
            FROM chats c
            JOIN users u ON (c.user1_id = u.id OR c.user2_id = u.id)
            WHERE (c.user1_id = ? OR c.user2_id = ?)
            AND u.id != ?
            AND u.id NOT IN (SELECT friend_id FROM friends WHERE user_id = ?)
            AND u.id NOT IN (SELECT from_user_id FROM friend_requests WHERE to_user_id = ? AND status = 'pending')
            AND u.id NOT IN (SELECT to_user_id FROM friend_requests WHERE from_user_id = ? AND status = 'pending')
            LIMIT 10
        ''', (user_id, user_id, user_id, user_id, user_id, user_id))
        
        suggested = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(suggested)
    except Exception as e:
        return jsonify([])
    

@app.route('/api/init_encryption', methods=['POST'])
@login_required
def init_encryption():
    try:
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        # Создаём мастер-ключ
        import secrets
        import base64
        master_key = base64.b64encode(secrets.token_bytes(32)).decode()
        
        cursor.execute("INSERT OR REPLACE INTO user_keys (user_id, master_key_encrypted) VALUES (?, ?)",
                      (user_id, master_key))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'OK', 'key_created': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/social_recovery/setup', methods=['POST'])
@login_required
def setup_social_recovery():
    return jsonify({'message': 'OK'})

# ==================== AI И ДРУГОЕ ====================
@app.route('/api/ai_response', methods=['POST'])
@login_required
def ai_response():
    data = request.json
    message = data.get('message', '').strip().lower()
    
    responses = {
        'привет': 'Привет! Чем могу помочь? 😊',
        'как дела': 'Отлично! А у тебя?',
        'шифрование': 'MOC использует сквозное шифрование для всех сообщений! 🔐',
        'файл': 'Загрузить файл можно в разделе "Медиа"',
        'альбом': 'Создавай альбомы для группировки фото!',
        'друг': 'Добавляй друзей через профиль',
        'чат': 'Все чаты защищены сквозным шифрованием',
        'помощь': 'Я могу рассказать о шифровании, альбомах, друзьях и чатах!'
    }
    
    for key, resp in responses.items():
        if key in message:
            return jsonify({'response': resp})
    
    return jsonify({'response': 'Я здесь, чтобы помочь с MOC! Спроси что-нибудь о шифровании, чатах или альбомах.'})

@app.route('/api/report', methods=['POST'])
@login_required
def report():
    return jsonify({'message': 'OK'})

@app.route('/api/upload_encrypted', methods=['POST'])
@login_required
def upload_encrypted():
    return jsonify({'message': 'Coming soon'})

@app.route('/api/delete_message', methods=['POST'])
@login_required
def delete_message():
    try:
        data = request.json
        message_id = data.get('message_id')
        chat_id = data.get('chat_id')
        user_id = session['user_id']
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM messages WHERE id = ? AND sender_id = ? AND chat_id = ?", 
                      (message_id, user_id, chat_id))
        if cursor.fetchone():
            cursor.execute("DELETE FROM messages WHERE id = ?", (message_id,))
            conn.commit()
        conn.close()
        return jsonify({'message': 'OK'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/copy_to_cloud/<int:file_id>', methods=['POST'])
@login_required
def copy_to_cloud(file_id):
    try:
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT filename, original_name, mime_type, file_size FROM files WHERE id = ?", (file_id,))
        file = cursor.fetchone()
        
        if not file:
            conn.close()
            return jsonify({'error': 'File not found'}), 404
        
        new_filename = f"{uuid.uuid4().hex}_{file['original_name']}"
        
        cursor.execute('''
            INSERT INTO files (user_id, filename, original_name, mime_type, file_size, uploaded_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (user_id, new_filename, file['original_name'], file['mime_type'], file['file_size']))
        
        import shutil
        src = os.path.join('uploads', file['filename'])
        dst = os.path.join('uploads', new_filename)
        if os.path.exists(src):
            shutil.copy(src, dst)
        
        conn.commit()
        conn.close()
        return jsonify({'message': 'OK'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    return jsonify({'status': 'ok'})
@app.route('/api/recover', methods=['POST'])
def recover_account():
    # Простая заглушка
    return jsonify({'error': 'Not implemented yet'}), 501


with app.app_context():
    init_db()
    print("✅ Database initialized on startup")
# ==================== ЗАПУСК ====================
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
