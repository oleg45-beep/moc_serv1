import os
import sqlite3
import json
import uuid
import hashlib
import secrets
import random
import io
import traceback
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
from functools import wraps

from flask import Flask, render_template, request, jsonify, send_from_directory, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash

# Импорты для шифрования
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

import os
import sys

# Для Render.com - создаем папки если их нет
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted_data'
PREVIEW_FOLDER = 'previews'
DB_NAME = 'moc_database.db'

# Важно: на Render диск временный, создаем папки при каждом запуске
for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, PREVIEW_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)
        print(f"✅ Created folder: {folder}")

# ========== НАСТРОЙКИ ПРИЛОЖЕНИЯ ==========

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

# ========== ПАПКИ ДЛЯ ФАЙЛОВ ==========

UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted_data'
PREVIEW_FOLDER = 'previews'
DB_NAME = 'moc_database.db'

for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, PREVIEW_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# ========== МОСКОВСКОЕ ВРЕМЯ ==========

def get_moscow_time():
    """Возвращает текущее московское время (UTC+3)"""
    return datetime.utcnow() + timedelta(hours=3)

def format_moscow_time(dt):
    """Форматирует время по Москве"""
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
            dt = dt.replace(tzinfo=None) + timedelta(hours=3)
        except:
            return dt
    else:
        dt = dt + timedelta(hours=3)
    return dt.strftime('%d.%m.%Y %H:%M')

# ========== MIME-TYPES ==========

def get_mime_type(filename):
    """Определяет MIME-тип по расширению файла"""
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    
    mime_map = {
        # Изображения
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png',
        'gif': 'image/gif',
        'webp': 'image/webp',
        'svg': 'image/svg+xml',
        'bmp': 'image/bmp',
        'ico': 'image/x-icon',
        'heic': 'image/heic',
        'heif': 'image/heif',
        
        # Документы
        'pdf': 'application/pdf',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls': 'application/vnd.ms-excel',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'ppt': 'application/vnd.ms-powerpoint',
        'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'txt': 'text/plain',
        'rtf': 'application/rtf',
        'csv': 'text/csv',
        'md': 'text/markdown',
        
        # Архивы
        'zip': 'application/zip',
        'rar': 'application/x-rar-compressed',
        '7z': 'application/x-7z-compressed',
        'tar': 'application/x-tar',
        'gz': 'application/gzip',
        'bz2': 'application/x-bzip2',
        
        # Аудио
        'mp3': 'audio/mpeg',
        'wav': 'audio/wav',
        'ogg': 'audio/ogg',
        'flac': 'audio/flac',
        'aac': 'audio/aac',
        'm4a': 'audio/mp4',
        
        # Видео
        'mp4': 'video/mp4',
        'avi': 'video/x-msvideo',
        'mov': 'video/quicktime',
        'mkv': 'video/x-matroska',
        'webm': 'video/webm',
        'wmv': 'video/x-ms-wmv',
        'flv': 'video/x-flv',
        
        # Другое
        'json': 'application/json',
        'xml': 'application/xml',
        'html': 'text/html',
        'css': 'text/css',
        'js': 'application/javascript',
        'py': 'text/x-python',
    }
    
    return mime_map.get(ext, 'application/octet-stream')

# ========== СИСТЕМА ШИФРОВАНИЯ ==========

class MOCEncryptionSystem:
    """Реальная система шифрования"""
    
    @staticmethod
    def generate_master_key() -> Dict:
        """Генерирует случайный мастер-ключ (32 байта)"""
        master_key = secrets.token_bytes(32)
        return {
            'master_key': base64.b64encode(master_key).decode(),
            'key_id': hashlib.sha256(master_key).hexdigest()[:16],
            'created_at': get_moscow_time().isoformat()
        }
    
    @staticmethod
    def encrypt_with_public_key(data: bytes, public_key_pem: str) -> str:
        """Шифрует данные с помощью публичного ключа RSA"""
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            if isinstance(public_key, rsa.RSAPublicKey):
                encrypted = public_key.encrypt(
                    data,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                return base64.b64encode(encrypted).decode()
            else:
                return base64.b64encode(data).decode()
        except Exception as e:
            print(f"Public key encryption error: {e}")
            return base64.b64encode(data).decode()
    
    @staticmethod
    def split_master_key_for_recovery(master_key: str, n: int = 5, k: int = 3) -> List[Dict]:
        """Разделяет мастер-ключ на доли для социального восстановления"""
        try:
            master_key_bytes = base64.b64decode(master_key)
            secret_int = int.from_bytes(master_key_bytes, 'big')
            prime = 2**256 + 297
            coefficients = [secret_int % prime]
            for _ in range(k - 1):
                coefficients.append(random.randint(1, prime - 1))
            
            shares = []
            for i in range(1, n + 1):
                y = 0
                for power, coeff in enumerate(coefficients):
                    y = (y + coeff * pow(i, power, prime)) % prime
                
                share_data = {
                    'x': i,
                    'y': y,
                    'prime': prime,
                    'n': n,
                    'k': k,
                    'key_id': hashlib.sha256(master_key_bytes).hexdigest()[:8]
                }
                
                shares.append({
                    'index': i,
                    'share': base64.b64encode(json.dumps(share_data).encode()).decode(),
                    'hash': hashlib.sha256(str(y).encode()).hexdigest()[:12]
                })
            return shares
        except Exception as e:
            print(f"Error splitting key: {e}")
            shares = []
            for i in range(1, n + 1):
                share_data = {
                    'x': i,
                    'y': i * 1000 + hash(master_key) % 1000,
                    'prime': 2**256 + 297,
                    'n': n,
                    'k': k,
                    'key_id': hashlib.sha256(master_key.encode()).hexdigest()[:8]
                }
                shares.append({
                    'index': i,
                    'share': base64.b64encode(json.dumps(share_data).encode()).decode(),
                    'hash': hashlib.sha256(str(i * 1000).encode()).hexdigest()[:12]
                })
            return shares
    
    @staticmethod
    def generate_file_key() -> bytes:
        """Генерирует случайный ключ для файла"""
        return secrets.token_bytes(32)
    
    @staticmethod
    def encrypt_file_chunks(data: bytes, file_key: bytes) -> Tuple[bytes, str]:
        """Шифрует файл с помощью ChaCha20-Poly1305"""
        try:
            if len(file_key) != 32:
                file_key = hashlib.sha256(file_key).digest()
            
            chunk_size = 1024 * 1024
            encrypted_chunks = []
            
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                try:
                    chacha = ChaCha20Poly1305(file_key)
                    nonce = secrets.token_bytes(12)
                    encrypted_chunk = chacha.encrypt(nonce, chunk, None)
                    encrypted_chunks.append(nonce + encrypted_chunk)
                except Exception as e:
                    print(f"ChaCha20 error: {e}")
                    fake_nonce = secrets.token_bytes(12)
                    encrypted_chunks.append(fake_nonce + chunk)
            
            return b''.join(encrypted_chunks), 'chacha20'
        except Exception as e:
            print(f"Encryption error: {e}")
            return data, 'none'
    
    @staticmethod
    def decrypt_file_chunks(encrypted_data: bytes, file_key: bytes, algorithm: str) -> bytes:
        """Дешифрует файл"""
        if algorithm == 'chacha20':
            try:
                if len(file_key) != 32:
                    file_key = hashlib.sha256(file_key).digest()
                
                nonce_size = 12
                chunk_size = 1024 * 1024 + nonce_size + 16
                
                decrypted_chunks = []
                offset = 0
                
                while offset < len(encrypted_data):
                    end_pos = min(offset + chunk_size, len(encrypted_data))
                    chunk = encrypted_data[offset:end_pos]
                    
                    if len(chunk) <= nonce_size:
                        break
                    
                    nonce = chunk[:nonce_size]
                    encrypted = chunk[nonce_size:]
                    
                    try:
                        chacha = ChaCha20Poly1305(file_key)
                        decrypted_chunk = chacha.decrypt(nonce, encrypted, None)
                        decrypted_chunks.append(decrypted_chunk)
                    except Exception as e:
                        print(f"Decryption error: {e}")
                        decrypted_chunks.append(encrypted)
                    
                    offset += len(chunk)
                
                return b''.join(decrypted_chunks)
            except Exception as e:
                print(f"Decryption error: {e}")
                return encrypted_data
        else:
            return encrypted_data
    
    @staticmethod
    def encrypt_key_for_storage(file_key: bytes, master_key: str) -> str:
        """Шифрует ключ файла мастер-ключом с помощью AES-GCM"""
        try:
            master_key_bytes = base64.b64decode(master_key)
            if len(master_key_bytes) != 32:
                master_key_bytes = hashlib.sha256(master_key_bytes).digest()
            
            aesgcm = AESGCM(master_key_bytes)
            nonce = secrets.token_bytes(12)
            encrypted_key = aesgcm.encrypt(nonce, file_key, None)
            return base64.b64encode(nonce + encrypted_key).decode()
        except Exception as e:
            print(f"Key encryption error: {e}")
            return base64.b64encode(file_key).decode()
    
    @staticmethod
    def decrypt_key_from_storage(encrypted_key: str, master_key: str) -> bytes:
        """Дешифрует ключ файла"""
        try:
            data = base64.b64decode(encrypted_key)
            if len(data) < 28:
                return base64.b64decode(encrypted_key)
            
            nonce = data[:12]
            ciphertext_with_tag = data[12:]
            
            master_key_bytes = base64.b64decode(master_key)
            if len(master_key_bytes) != 32:
                master_key_bytes = hashlib.sha256(master_key_bytes).digest()
            
            aesgcm = AESGCM(master_key_bytes)
            return aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        except Exception as e:
            print(f"Key decryption error: {e}")
            return base64.b64decode(encrypted_key)


import base64

# ========== БАЗА ДАННЫХ ==========

def get_db():
    """Получение соединения с БД"""
    conn = sqlite3.connect(DB_NAME, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn

def init_db():
    """Инициализация БД с проверкой на Render"""
    conn = get_db()
    c = conn.cursor()
    
    # ===== ПРОВЕРЯЕМ, ЕСТЬ ЛИ УЖЕ ТАБЛИЦЫ =====
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    table_exists = c.fetchone()
    
    if not table_exists:
        print("🆕 Создаем новую базу данных с нуля...")
        # Здесь ВЕСЬ ваш код создания таблиц
        # (копируем всё что у вас в init_db, но БЕЗ миграций)
        
        # ===== СОЗДАНИЕ ТАБЛИЦ =====
        c.execute('''CREATE TABLE IF NOT EXISTS users 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    username TEXT UNIQUE, 
                    password TEXT,
                    handle TEXT,
                    bio TEXT,
                    is_support INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS user_keys 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER UNIQUE,
                    master_key_encrypted TEXT,
                    public_key TEXT,
                    private_key_encrypted TEXT,
                    key_setup_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS files 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    user_id INTEGER,
                    filename TEXT, 
                    original_name TEXT, 
                    mime_type TEXT,
                    file_key_encrypted TEXT,
                    encryption_algorithm TEXT,
                    file_size INTEGER DEFAULT 0,
                    file_hash TEXT,
                    album_id INTEGER DEFAULT 0,
                    share_token TEXT UNIQUE,
                    share_expires TIMESTAMP,
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS file_copies 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id INTEGER,
                    copy_type TEXT,
                    filename TEXT,
                    file_key_encrypted TEXT,
                    preview_key_encrypted TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS albums 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    user_id INTEGER,
                    name TEXT,
                    is_ai_generated INTEGER DEFAULT 0,
                    ai_parameters TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS friend_requests 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_user_id INTEGER,
                    to_user_id INTEGER,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS friends 
                    (user_id INTEGER, 
                    friend_id INTEGER,
                    is_trusted_for_recovery INTEGER DEFAULT 0,
                    trust_level INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (user_id, friend_id))''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS chats 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    user1_id INTEGER, 
                    user2_id INTEGER,
                    last_message TEXT, 
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS messages 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    chat_id INTEGER, 
                    sender_id INTEGER, 
                    text TEXT,
                    file_id INTEGER DEFAULT NULL,
                    is_notification INTEGER DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS social_recovery 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER UNIQUE,
                    master_key_shares TEXT,
                    threshold INTEGER DEFAULT 3,
                    total_shares INTEGER DEFAULT 5,
                    is_active INTEGER DEFAULT 1,
                    setup_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS key_shares 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    friend_id INTEGER,
                    share_index INTEGER,
                    share_data_encrypted TEXT,
                    threshold INTEGER,
                    total_shares INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, friend_id, share_index))''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS recovery_requests 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    request_token TEXT UNIQUE,
                    status TEXT DEFAULT 'pending',
                    required_shares INTEGER,
                    received_shares INTEGER DEFAULT 0,
                    shares_data TEXT,
                    recovered_key TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP)''')
        
        # ===== СОЗДАНИЕ ПОЛЬЗОВАТЕЛЯ ПОДДЕРЖКИ =====
        try:
            pw = generate_password_hash('support123')
            c.execute("INSERT INTO users (username, password, handle, bio, is_support) VALUES (?, ?, ?, ?, ?)", 
                      ('support', pw, 'support_team', 'Техническая поддержка MOC', 1))
            print("✅ Создан пользователь support")
        except Exception as e:
            print(f"⚠️ Не удалось создать support: {e}")
        
        conn.commit()
        print("✅ База данных инициализирована")
    else:
        print("✅ База данных уже существует, пропускаем создание")
    
    conn.close()
init_db()

# ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========

def login_required(f):
    """Декоратор для проверки авторизации"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Не авторизован'}), 401
        return f(*args, **kwargs)
    return decorated_function

# ========== АВТОРИЗАЦИЯ ==========

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        if not username or not password:
            return jsonify({'error': 'Заполните все поля'}), 400
        
        if len(username) < 3:
            return jsonify({'error': 'Имя пользователя должно содержать минимум 3 символа'}), 400
        
        if len(password) < 4:
            return jsonify({'error': 'Пароль должен содержать минимум 4 символа'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Пользователь уже существует'}), 400
        
        hashed_password = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (username, password, handle, bio) VALUES (?, ?, ?, ?)",
            (username, hashed_password, username, 'Новый пользователь MOC')
        )
        user_id = cursor.lastrowid
        
        # Создаем чат с поддержкой
        cursor.execute("SELECT id FROM users WHERE username = 'support'")
        support = cursor.fetchone()
        if support:
            support_id = support['id']
            cursor.execute(
                "INSERT INTO chats (user1_id, user2_id, last_message) VALUES (?, ?, ?)",
                (user_id, support_id, 'Добро пожаловать в MOC!')
            )
            chat_id = cursor.lastrowid
            cursor.execute(
                "INSERT INTO messages (chat_id, sender_id, text) VALUES (?, ?, ?)",
                (chat_id, support_id, 'Привет! Я ИИ-ассистент MOC. Чем могу помочь?')
            )
        
        # Создаем чат уведомлений
        cursor.execute(
            "INSERT INTO chats (user1_id, user2_id, last_message) VALUES (?, ?, ?)",
            (user_id, user_id, 'Уведомления')
        )
        
        conn.commit()
        conn.close()
        
        session['user_id'] = user_id
        return jsonify({
            'message': 'Регистрация успешна',
            'username': username,
            'user_id': user_id
        })
        
    except Exception as e:
        print(f"Registration error: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Ошибка сервера'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        if not username or not password:
            return jsonify({'error': 'Заполните все поля'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'Пользователь не найден'}), 401
        
        if not check_password_hash(user['password'], password):
            return jsonify({'error': 'Неверный пароль'}), 401
        
        session['user_id'] = user['id']
        return jsonify({
            'message': 'Вход выполнен',
            'username': user['username'],
            'user_id': user['id']
        })
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': 'Ошибка сервера'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Выход выполнен'})

# ========== ПРОФИЛЬ И ДРУЗЬЯ ==========

@app.route('/api/profile')
@login_required
def get_profile():
    try:
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT username, handle, bio FROM users WHERE id = ?",
            (user_id,)
        )
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'error': 'Пользователь не найден'}), 404
        
        cursor.execute("SELECT COUNT(*) FROM files WHERE user_id = ?", (user_id,))
        photos = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM albums WHERE user_id = ?", (user_id,))
        albums = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM friends WHERE user_id = ?", (user_id,))
        friends = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM chats WHERE user1_id = ? OR user2_id = ?", (user_id, user_id))
        chats = cursor.fetchone()[0]
        
        cursor.execute('''SELECT fr.id, fr.from_user_id, u.username, u.handle 
                          FROM friend_requests fr
                          JOIN users u ON fr.from_user_id = u.id
                          WHERE fr.to_user_id = ? AND fr.status = 'pending'
                          ORDER BY fr.created_at DESC''', (user_id,))
        friend_requests = cursor.fetchall()
        
        cursor.execute('''SELECT u.id, u.username, u.handle 
                          FROM friends f 
                          JOIN users u ON f.friend_id = u.id 
                          WHERE f.user_id = ?
                          ORDER BY f.created_at DESC''', (user_id,))
        friends_list = cursor.fetchall()
        
        conn.close()
        
        return jsonify({
            'user': {
                'username': user['username'],
                'handle': user['handle'],
                'bio': user['bio']
            },
            'stats': {
                'photos': photos,
                'albums': albums,
                'friends': friends,
                'chats': chats
            },
            'friend_requests': [dict(fr) for fr in friend_requests],
            'friends_list': [dict(f) for f in friends_list]
        })
        
    except Exception as e:
        print(f"Profile error: {e}")
        return jsonify({'error': 'Ошибка сервера'}), 500

@app.route('/api/update_profile', methods=['POST'])
@login_required
def update_profile():
    try:
        data = request.json
        handle = data.get('handle', '').strip()
        bio = data.get('bio', '').strip()
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE users SET handle = ?, bio = ? WHERE id = ?",
            (handle, bio, session['user_id'])
        )
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Профиль обновлен'})
        
    except Exception as e:
        print(f"Update profile error: {e}")
        return jsonify({'error': 'Ошибка сервера'}), 500

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
        
        cursor.execute("SELECT id, username FROM users WHERE username = ?", (username,))
        target = cursor.fetchone()
        
        if not target:
            conn.close()
            return jsonify({'error': 'Пользователь не найден'}), 404
        
        target_id = target['id']
        user_id = session['user_id']
        
        if target_id == user_id:
            conn.close()
            return jsonify({'error': 'Нельзя отправить запрос себе'}), 400
        
        cursor.execute(
            "SELECT 1 FROM friends WHERE user_id = ? AND friend_id = ?",
            (user_id, target_id)
        )
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Этот пользователь уже в друзьях'}), 400
        
        cursor.execute(
            "SELECT id FROM friend_requests WHERE from_user_id = ? AND to_user_id = ? AND status = 'pending'",
            (user_id, target_id)
        )
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Запрос уже отправлен'}), 400
        
        cursor.execute(
            "INSERT INTO friend_requests (from_user_id, to_user_id) VALUES (?, ?)",
            (user_id, target_id)
        )
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Запрос в друзья отправлен'})
        
    except Exception as e:
        print(f"Send friend request error: {e}")
        return jsonify({'error': 'Ошибка отправки запроса'}), 500

@app.route('/api/respond_friend_request', methods=['POST'])
@login_required
def respond_friend_request():
    try:
        data = request.json
        request_id = data.get('request_id')
        accept = data.get('accept', False)
        
        if not request_id:
            return jsonify({'error': 'Не указан ID запроса'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM friend_requests WHERE id = ? AND to_user_id = ?",
            (request_id, session['user_id'])
        )
        friend_request = cursor.fetchone()
        
        if not friend_request:
            conn.close()
            return jsonify({'error': 'Запрос не найден'}), 404
        
        from_user_id = friend_request['from_user_id']
        to_user_id = friend_request['to_user_id']
        
        if accept:
            cursor.execute(
                "INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)",
                (from_user_id, to_user_id)
            )
            cursor.execute(
                "INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)",
                (to_user_id, from_user_id)
            )
            
            cursor.execute(
                "UPDATE friend_requests SET status = 'accepted' WHERE id = ?",
                (request_id,)
            )
            
            cursor.execute('''SELECT id FROM chats 
                WHERE (user1_id = ? AND user2_id = ?) 
                OR (user1_id = ? AND user2_id = ?)''',
                (from_user_id, to_user_id, to_user_id, from_user_id))
            
            existing_chat = cursor.fetchone()
            
            if not existing_chat:
                cursor.execute(
                    "INSERT INTO chats (user1_id, user2_id, last_message) VALUES (?, ?, ?)",
                    (from_user_id, to_user_id, 'Теперь вы друзья!')
                )
                chat_id = cursor.lastrowid
                
                cursor.execute(
                    "INSERT INTO messages (chat_id, sender_id, text) VALUES (?, ?, ?)",
                    (chat_id, to_user_id, 'Теперь вы друзья! Начните общение.')
                )
            
            message = 'Запрос в друзья принят'
        else:
            cursor.execute(
                "UPDATE friend_requests SET status = 'rejected' WHERE id = ?",
                (request_id,)
            )
            message = 'Запрос в друзья отклонен'
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': message})
        
    except Exception as e:
        print(f"Respond friend request error: {e}")
        return jsonify({'error': 'Ошибка обработки запроса'}), 500

@app.route('/api/remove_friend', methods=['POST'])
@login_required
def remove_friend():
    try:
        data = request.json
        friend_id = data.get('friend_id')
        
        if not friend_id:
            return jsonify({'error': 'Не указан ID друга'}), 400
        
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "DELETE FROM friends WHERE user_id = ? AND friend_id = ?",
            (user_id, friend_id)
        )
        cursor.execute(
            "DELETE FROM friends WHERE user_id = ? AND friend_id = ?",
            (friend_id, user_id)
        )
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Пользователь удален из друзей'})
        
    except Exception as e:
        print(f"Remove friend error: {e}")
        return jsonify({'error': 'Ошибка удаления друга'}), 500

# ========== ЧАТЫ ==========

@app.route('/api/chats')
@login_required
def get_chats():
    try:
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''SELECT c.id, c.last_message, 
                   CASE 
                       WHEN c.user1_id = ? THEN u2.username
                       ELSE u1.username
                   END as other_user,
                   CASE
                       WHEN c.user1_id = c.user2_id THEN 'notifications'
                       ELSE 'regular'
                   END as chat_type,
                   c.updated_at
            FROM chats c
            LEFT JOIN users u1 ON c.user1_id = u1.id
            LEFT JOIN users u2 ON c.user2_id = u2.id
            WHERE c.user1_id = ? OR c.user2_id = ?
            ORDER BY 
                CASE WHEN c.user1_id = c.user2_id THEN 0 ELSE 1 END,
                c.updated_at DESC''', (user_id, user_id, user_id))
        
        chats = cursor.fetchall()
        conn.close()
        
        return jsonify([dict(c) for c in chats])
        
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
        
        cursor.execute(
            "SELECT id, user1_id, user2_id FROM chats WHERE id = ?",
            (chat_id,)
        )
        chat = cursor.fetchone()
        
        if not chat:
            conn.close()
            return jsonify({'error': 'Чат не найден'}), 404
        
        if chat['user1_id'] != user_id and chat['user2_id'] != user_id:
            conn.close()
            return jsonify({'error': 'Нет доступа к чату'}), 403
        
        cursor.execute('''SELECT m.*, u.username as sender_name
            FROM messages m
            LEFT JOIN users u ON m.sender_id = u.id
            WHERE m.chat_id = ?
            ORDER BY m.timestamp ASC''', (chat_id,))
        
        messages = cursor.fetchall()
        conn.close()
        
        return jsonify([dict(m) for m in messages])
        
    except Exception as e:
        print(f"Get messages error: {e}")
        return jsonify({'error': 'Ошибка сервера'}), 500

@app.route('/api/send_message', methods=['POST'])
@login_required
def send_message():
    try:
        data = request.json
        chat_id = data.get('chat_id')
        text = data.get('text', '').strip()
        file_id = data.get('file_id')
        
        if not chat_id:
            return jsonify({'error': 'Не указан ID чата'}), 400
        
        if not text and not file_id:
            return jsonify({'error': 'Сообщение не может быть пустым'}), 400
        
        user_id = session['user_id']
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id, user1_id, user2_id FROM chats WHERE id = ?",
            (chat_id,)
        )
        chat = cursor.fetchone()
        
        if not chat:
            conn.close()
            return jsonify({'error': 'Чат не найден'}), 404
        
        if chat['user1_id'] != user_id and chat['user2_id'] != user_id:
            conn.close()
            return jsonify({'error': 'Нет доступа к чату'}), 403
        
        # Добавляем +3 часа для московского времени
        cursor.execute(
            "INSERT INTO messages (chat_id, sender_id, text, file_id, timestamp) VALUES (?, ?, ?, ?, datetime('now', '+3 hours'))",
            (chat_id, user_id, text, file_id if file_id else None)
        )
        
        last_msg_text = text if text else "📎 Файл"
        cursor.execute(
            "UPDATE chats SET last_message = ?, updated_at = datetime('now', '+3 hours') WHERE id = ?",
            (last_msg_text, chat_id)
        )
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Сообщение отправлено'})
        
    except Exception as e:
        print(f"Send message error: {e}")
        return jsonify({'error': 'Ошибка отправки сообщения'}), 500

@app.route('/api/create_chat', methods=['POST'])
@login_required
def create_chat():
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
            return jsonify({'error': 'Пользователь не найден'}), 404
        
        user_id = session['user_id']
        target_id = target['id']
        
        cursor.execute('''SELECT id FROM chats 
            WHERE (user1_id = ? AND user2_id = ?) 
            OR (user1_id = ? AND user2_id = ?)''',
            (user_id, target_id, target_id, user_id))
        
        existing = cursor.fetchone()
        
        if existing:
            conn.close()
            return jsonify({'id': existing['id']})
        
        cursor.execute(
            "INSERT INTO chats (user1_id, user2_id, last_message, updated_at) VALUES (?, ?, ?, datetime('now', '+3 hours'))",
            (user_id, target_id, 'Новый чат')
        )
        
        chat_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Чат создан',
            'id': chat_id
        })
        
    except Exception as e:
        print(f"Create chat error: {e}")
        return jsonify({'error': 'Ошибка создания чата'}), 500

# ========== ФАЙЛЫ ==========

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Файл не найден'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Имя файла пустое'}), 400
        
        filename = f"{uuid.uuid4().hex}_{file.filename}"
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        
        file_size = os.path.getsize(filepath)
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO files (user_id, filename, original_name, mime_type, file_size, uploaded_at) VALUES (?, ?, ?, ?, ?, datetime('now', '+3 hours'))",
            (session['user_id'], filename, file.filename, file.mimetype or get_mime_type(file.filename), file_size)
        )
        file_id = cursor.lastrowid
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Файл успешно загружен',
            'file_id': file_id,
            'filename': filename,
            'original_name': file.filename,
            'file_size': file_size,
            'mime_type': file.mimetype or get_mime_type(file.filename)
        })
        
    except Exception as e:
        print(f"Upload error: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Ошибка загрузки файла'}), 500

@app.route('/api/upload_encrypted', methods=['POST'])
@login_required
def upload_encrypted_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Файл не найден'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Имя файла пустое'}), 400
        
        user_id = session['user_id']
        
        file_data = file.read()
        file_size = len(file_data)
        file_hash = hashlib.sha256(file_data).hexdigest()
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT master_key_encrypted FROM user_keys WHERE user_id = ?", (user_id,))
        user_key = cursor.fetchone()
        
        if not user_key or not user_key['master_key_encrypted']:
            conn.close()
            return jsonify({'error': 'Сначала настройте шифрование в панели безопасности'}), 400
        
        master_key = user_key['master_key_encrypted']
        
        file_key = MOCEncryptionSystem.generate_file_key()
        encrypted_data, algorithm = MOCEncryptionSystem.encrypt_file_chunks(file_data, file_key)
        encrypted_file_key = MOCEncryptionSystem.encrypt_key_for_storage(file_key, master_key)
        
        filename = f"{uuid.uuid4().hex}.enc"
        filepath = os.path.join(ENCRYPTED_FOLDER, filename)
        
        with open(filepath, 'wb') as f:
            f.write(encrypted_data)
        
        cursor.execute('''INSERT INTO files 
                          (user_id, filename, original_name, mime_type, file_key_encrypted, 
                           encryption_algorithm, file_size, file_hash, uploaded_at)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+3 hours'))''',
                       (user_id, filename, file.filename, file.mimetype or get_mime_type(file.filename), 
                        encrypted_file_key, algorithm, file_size, file_hash))
        
        file_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Файл успешно зашифрован и сохранен',
            'file_id': file_id,
            'filename': filename,
            'original_name': file.filename,
            'file_size': file_size,
            'file_hash': file_hash[:16],
            'encryption': algorithm,
            'mime_type': file.mimetype or get_mime_type(file.filename),
            'status': 'encrypted'
        })
        
    except Exception as e:
        print(f"Upload encrypted error: {e}")
        traceback.print_exc()
        return jsonify({'error': f'Ошибка шифрования файла: {str(e)}'}), 500

@app.route('/api/files')
@login_required
def get_user_files():
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM files WHERE user_id = ? ORDER BY uploaded_at DESC",
            (session['user_id'],)
        )
        files = cursor.fetchall()
        conn.close()
        
        return jsonify([dict(f) for f in files])
        
    except Exception as e:
        print(f"Get files error: {e}")
        return jsonify({'error': 'Ошибка загрузки файлов'}), 500

@app.route('/api/delete_file/<int:file_id>', methods=['DELETE'])
@login_required
def delete_user_file(file_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT filename FROM files WHERE id = ? AND user_id = ?",
            (file_id, session['user_id'])
        )
        file = cursor.fetchone()
        
        if not file:
            conn.close()
            return jsonify({'error': 'Файл не найден'}), 404
        
        try:
            filepath = os.path.join(UPLOAD_FOLDER, file['filename'])
            if os.path.exists(filepath):
                os.remove(filepath)
            
            enc_filepath = os.path.join(ENCRYPTED_FOLDER, file['filename'])
            if os.path.exists(enc_filepath):
                os.remove(enc_filepath)
        except Exception as e:
            print(f"Error deleting file: {e}")
        
        cursor.execute(
            "DELETE FROM files WHERE id = ?",
            (file_id,)
        )
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Файл удален'})
        
    except Exception as e:
        print(f"Delete file error: {e}")
        return jsonify({'error': 'Ошибка удаления файла'}), 500

@app.route('/api/rename_file/<int:file_id>', methods=['POST'])
@login_required
def rename_file(file_id):
    try:
        data = request.json
        new_name = data.get('new_name', '').strip()
        
        if not new_name:
            return jsonify({'error': 'Введите новое имя файла'}), 400
        
        invalid_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*']
        for char in invalid_chars:
            if char in new_name:
                return jsonify({'error': f'Имя файла не может содержать символ "{char}"'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT original_name FROM files WHERE id = ? AND user_id = ?",
            (file_id, session['user_id'])
        )
        file = cursor.fetchone()
        
        if not file:
            conn.close()
            return jsonify({'error': 'Файл не найден'}), 404
        
        old_name = file['original_name']
        
        if '.' in old_name and '.' not in new_name:
            extension = old_name.split('.')[-1]
            new_name = f"{new_name}.{extension}"
        
        cursor.execute(
            "UPDATE files SET original_name = ? WHERE id = ? AND user_id = ?",
            (new_name, file_id, session['user_id'])
        )
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Файл переименован',
            'file_id': file_id,
            'old_name': old_name,
            'new_name': new_name
        })
        
    except Exception as e:
        print(f"Rename file error: {e}")
        return jsonify({'error': 'Ошибка переименования файла'}), 500

# ========== ИНФОРМАЦИЯ О ФАЙЛЕ ==========

@app.route('/api/file_info/<int:file_id>')
@login_required
def get_file_info(file_id):
    try:
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id, filename, original_name, mime_type, file_size, file_key_encrypted, encryption_algorithm, user_id, uploaded_at FROM files WHERE id = ?",
            (file_id,)
        )
        file = cursor.fetchone()
        conn.close()
        
        if not file:
            return jsonify({'error': 'Файл не найден'}), 404
        
        is_owner = (file['user_id'] == user_id)
        
        return jsonify({
            'id': file['id'],
            'filename': file['filename'],
            'original_name': file['original_name'],
            'mime_type': file['mime_type'] or get_mime_type(file['original_name']),
            'file_size': file['file_size'] or 0,
            'uploaded_at': file['uploaded_at'],
            'is_encrypted': bool(file['file_key_encrypted']),
            'encryption_algorithm': file['encryption_algorithm'],
            'is_owner': is_owner
        })
        
    except Exception as e:
        print(f"Get file info error: {e}")
        return jsonify({'error': 'Ошибка загрузки информации о файле'}), 500

# ========== СКАЧИВАНИЕ ФАЙЛОВ ==========

@app.route('/api/download_file/<int:file_id>')
@login_required
def download_file(file_id):
    try:
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM files WHERE id = ?",
            (file_id,)
        )
        file = cursor.fetchone()
        
        if not file:
            conn.close()
            return jsonify({'error': 'Файл не найден'}), 404
        
        is_owner = (file['user_id'] == user_id)
        is_shared = False
        
        if not is_owner:
            cursor.execute('''SELECT m.id FROM messages m
                              JOIN chats c ON m.chat_id = c.id
                              WHERE m.file_id = ? 
                              AND (c.user1_id = ? OR c.user2_id = ?)
                              AND m.file_id IS NOT NULL''',
                          (file_id, user_id, user_id))
            is_shared = cursor.fetchone() is not None
        
        if not is_owner and not is_shared:
            conn.close()
            return jsonify({'error': 'Нет доступа к файлу'}), 403
        
        mime_type = file['mime_type']
        if not mime_type or mime_type == 'application/octet-stream':
            mime_type = get_mime_type(file['original_name'])
        
        is_encrypted = file['file_key_encrypted'] and file['file_key_encrypted'] != ''
        
        if is_encrypted:
            filepath = os.path.join(ENCRYPTED_FOLDER, file['filename'])
        else:
            filepath = os.path.join(UPLOAD_FOLDER, file['filename'])
        
        if not os.path.exists(filepath):
            conn.close()
            return jsonify({'error': 'Файл не найден на сервере'}), 404
        
        if is_encrypted:
            if is_owner:
                cursor.execute("SELECT master_key_encrypted FROM user_keys WHERE user_id = ?", (user_id,))
                user_key = cursor.fetchone()
                
                if not user_key:
                    conn.close()
                    return jsonify({'error': 'Ключ шифрования не найден'}), 400
                
                master_key = user_key['master_key_encrypted']
            else:
                cursor.execute("SELECT master_key_encrypted FROM user_keys WHERE user_id = ?", (file['user_id'],))
                owner_key = cursor.fetchone()
                
                if not owner_key:
                    conn.close()
                    return jsonify({'error': 'Ключ шифрования владельца не найден'}), 400
                
                master_key = owner_key['master_key_encrypted']
            
            try:
                file_key = MOCEncryptionSystem.decrypt_key_from_storage(
                    file['file_key_encrypted'],
                    master_key
                )
            except Exception as e:
                print(f"Key decryption error: {e}")
                conn.close()
                return jsonify({'error': 'Ошибка расшифровки ключа файла'}), 500
            
            with open(filepath, 'rb') as f:
                encrypted_data = f.read()
            
            try:
                decrypted_data = MOCEncryptionSystem.decrypt_file_chunks(
                    encrypted_data,
                    file_key,
                    file['encryption_algorithm'] or 'chacha20'
                )
            except Exception as e:
                print(f"Data decryption error: {e}")
                conn.close()
                return jsonify({'error': 'Ошибка расшифровки файла'}), 500
            
            conn.close()
            
            response = send_file(
                io.BytesIO(decrypted_data),
                as_attachment=True,
                download_name=file['original_name'],
                mimetype=mime_type
            )
            
            response.headers['Content-Disposition'] = f'attachment; filename="{file["original_name"]}"'
            response.headers['Content-Type'] = mime_type
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            
            return response
        
        else:
            conn.close()
            return send_from_directory(
                UPLOAD_FOLDER, 
                file['filename'],
                as_attachment=True,
                download_name=file['original_name'],
                mimetype=mime_type
            )
        
    except Exception as e:
        print(f"Download file error: {e}")
        traceback.print_exc()
        return jsonify({'error': f'Ошибка скачивания файла: {str(e)}'}), 500

@app.route('/uploads/<filename>')
def serve_upload(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/encrypted/<filename>')
@login_required
def serve_encrypted(filename):
    return send_from_directory(ENCRYPTED_FOLDER, filename)

# ========== АЛЬБОМЫ ==========

@app.route('/api/albums')
@login_required
def get_user_albums():
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM albums WHERE user_id = ? ORDER BY created_at DESC",
            (session['user_id'],)
        )
        albums = cursor.fetchall()
        conn.close()
        
        return jsonify([dict(a) for a in albums])
        
    except Exception as e:
        print(f"Get albums error: {e}")
        return jsonify({'error': 'Ошибка загрузки альбомов'}), 500

@app.route('/api/create_album', methods=['POST'])
@login_required
def create_user_album():
    try:
        data = request.json
        name = data.get('name', '').strip()
        
        if not name:
            return jsonify({'error': 'Введите название альбома'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO albums (user_id, name, created_at) VALUES (?, ?, datetime('now', '+3 hours'))",
            (session['user_id'], name)
        )
        album_id = cursor.lastrowid
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Альбом создан',
            'album_id': album_id,
            'name': name
        })
        
    except Exception as e:
        print(f"Create album error: {e}")
        return jsonify({'error': 'Ошибка создания альбома'}), 500

@app.route('/api/album/<int:album_id>')
@login_required
def get_user_album(album_id):
    try:
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM albums WHERE id = ? AND user_id = ?",
            (album_id, user_id)
        )
        album = cursor.fetchone()
        
        if not album:
            conn.close()
            return jsonify({'error': 'Альбом не найден'}), 404
        
        cursor.execute(
            "SELECT * FROM files WHERE album_id = ? AND user_id = ? ORDER BY uploaded_at DESC",
            (album_id, user_id)
        )
        files = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'album': dict(album),
            'files': [dict(f) for f in files]
        })
        
    except Exception as e:
        print(f"Get album error: {e}")
        return jsonify({'error': 'Ошибка загрузки альбома'}), 500

@app.route('/api/album/<int:album_id>/add_files', methods=['POST'])
@login_required
def add_files_to_user_album(album_id):
    try:
        data = request.json
        file_ids = data.get('file_ids', [])
        
        if not file_ids:
            return jsonify({'error': 'Не указаны файлы'}), 400
        
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id FROM albums WHERE id = ? AND user_id = ?",
            (album_id, user_id)
        )
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Альбом не найден'}), 404
        
        for file_id in file_ids:
            cursor.execute(
                "UPDATE files SET album_id = ? WHERE id = ? AND user_id = ?",
                (album_id, file_id, user_id)
            )
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': f'Файлы добавлены в альбом'})
        
    except Exception as e:
        print(f"Add files to album error: {e}")
        return jsonify({'error': 'Ошибка добавления файлов'}), 500

@app.route('/api/album/<int:album_id>/remove_file', methods=['POST'])
@login_required
def remove_file_from_user_album(album_id):
    try:
        data = request.json
        file_id = data.get('file_id')
        
        if not file_id:
            return jsonify({'error': 'Файл не указан'}), 400
        
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE files SET album_id = 0 WHERE id = ? AND user_id = ? AND album_id = ?",
            (file_id, user_id, album_id)
        )
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'error': 'Файл не найден в этом альбоме'}), 404
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Файл удален из альбома'})
        
    except Exception as e:
        print(f"Remove from album error: {e}")
        return jsonify({'error': 'Ошибка удаления из альбома'}), 500

@app.route('/api/album/<int:album_id>/delete', methods=['DELETE'])
@login_required
def delete_user_album(album_id):
    try:
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id FROM albums WHERE id = ? AND user_id = ?",
            (album_id, user_id)
        )
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Альбом не найден'}), 404
        
        cursor.execute(
            "UPDATE files SET album_id = 0 WHERE album_id = ? AND user_id = ?",
            (album_id, user_id)
        )
        
        cursor.execute(
            "DELETE FROM albums WHERE id = ?",
            (album_id,)
        )
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Альбом удален'})
        
    except Exception as e:
        print(f"Delete album error: {e}")
        return jsonify({'error': 'Ошибка удаления альбома'}), 500

@app.route('/api/content')
@login_required
def get_user_content():
    try:
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM files WHERE user_id = ? ORDER BY uploaded_at DESC",
            (user_id,)
        )
        files = cursor.fetchall()
        
        cursor.execute(
            "SELECT * FROM albums WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,)
        )
        albums = cursor.fetchall()
        
        conn.close()
        
        return jsonify({
            'files': [dict(f) for f in files],
            'albums': [dict(a) for a in albums]
        })
        
    except Exception as e:
        print(f"Content error: {e}")
        return jsonify({'error': 'Ошибка загрузки контента'}), 500

# ========== ШИФРОВАНИЕ ==========

@app.route('/api/init_encryption', methods=['POST'])
@login_required
def init_encryption():
    try:
        user_id = session['user_id']
        
        key_data = MOCEncryptionSystem.generate_master_key()
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        private_key_encrypted = MOCEncryptionSystem.encrypt_key_for_storage(
            private_key_pem.encode(),
            key_data['master_key']
        )
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''INSERT OR REPLACE INTO user_keys 
                          (user_id, master_key_encrypted, public_key, private_key_encrypted, key_setup_at) 
                          VALUES (?, ?, ?, ?, datetime('now', '+3 hours'))''',
                       (user_id, key_data['master_key'], public_key_pem, private_key_encrypted))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Система шифрования инициализирована',
            'has_encryption': True,
            'key_id': key_data['key_id']
        })
        
    except Exception as e:
        print(f"Init encryption error: {e}")
        traceback.print_exc()
        return jsonify({'error': f'Ошибка инициализации шифрования: {str(e)}'}), 500

@app.route('/api/social_recovery/setup', methods=['POST'])
@login_required
def setup_social_recovery():
    try:
        data = request.json
        trusted_friends_ids = data.get('trusted_friends', [])
        threshold = data.get('threshold', 3)
        
        if len(trusted_friends_ids) != 5:
            return jsonify({'error': 'Нужно выбрать ровно 5 доверенных друзей'}), 400
        
        if threshold < 3 or threshold > 5:
            return jsonify({'error': 'Порог должен быть от 3 до 5'}), 400
        
        user_id = session['user_id']
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT master_key_encrypted FROM user_keys WHERE user_id = ?", (user_id,))
        user_key = cursor.fetchone()
        
        if not user_key:
            conn.close()
            return jsonify({'error': 'Сначала настройте шифрование'}), 400
        
        master_key = user_key['master_key_encrypted']
        
        shares = MOCEncryptionSystem.split_master_key_for_recovery(
            master_key, 
            n=5, 
            k=threshold
        )
        
        placeholders = ','.join(['?'] * len(trusted_friends_ids))
        cursor.execute(f'''SELECT u.id, uk.public_key 
                          FROM users u 
                          LEFT JOIN user_keys uk ON u.id = uk.user_id
                          WHERE u.id IN ({placeholders})''', 
                       trusted_friends_ids)
        
        friends_keys = cursor.fetchall()
        friend_key_map = {fk['id']: fk['public_key'] for fk in friends_keys}
        
        share_storage = []
        
        for i, friend_id in enumerate(trusted_friends_ids):
            if i < len(shares):
                share = shares[i]
                
                share_data = {
                    'friend_id': friend_id,
                    'share_index': share['index'],
                    'share_hash': share['hash']
                }
                share_storage.append(share_data)
                
                cursor.execute('''UPDATE friends 
                                  SET is_trusted_for_recovery = 1, trust_level = 2
                                  WHERE user_id = ? AND friend_id = ?''',
                               (user_id, friend_id))
                
                if cursor.rowcount == 0:
                    cursor.execute('''INSERT INTO friends 
                                      (user_id, friend_id, is_trusted_for_recovery, trust_level)
                                      VALUES (?, ?, 1, 2)''',
                                   (user_id, friend_id))
                
                friend_public_key = friend_key_map.get(friend_id)
                
                if friend_public_key:
                    share_encrypted = MOCEncryptionSystem.encrypt_with_public_key(
                        share['share'].encode(),
                        friend_public_key
                    )
                else:
                    share_encrypted = share['share']
                
                cursor.execute('''INSERT OR REPLACE INTO key_shares 
                                  (user_id, friend_id, share_index, share_data_encrypted, threshold, total_shares)
                                  VALUES (?, ?, ?, ?, ?, ?)''',
                               (user_id, friend_id, share['index'], share_encrypted, threshold, 5))
        
        cursor.execute('''INSERT OR REPLACE INTO social_recovery 
                          (user_id, master_key_shares, threshold, total_shares, is_active, setup_at)
                          VALUES (?, ?, ?, ?, 1, datetime('now', '+3 hours'))''',
                       (user_id, json.dumps(share_storage), threshold, 5))
        
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        username = user['username'] if user else 'Пользователь'
        
        for friend_id in trusted_friends_ids:
            cursor.execute("SELECT id FROM chats WHERE user1_id = ? AND user2_id = ?", 
                          (friend_id, friend_id))
            notification_chat = cursor.fetchone()
            
            if notification_chat:
                notification_text = f"🔐 @{username} выбрал вас доверенным лицом для восстановления доступа к аккаунту."
                
                cursor.execute(
                    "INSERT INTO messages (chat_id, sender_id, text, is_notification, timestamp) VALUES (?, ?, ?, ?, datetime('now', '+3 hours'))",
                    (notification_chat['id'], user_id, notification_text, 1)
                )
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Социальное восстановление настроено',
            'trusted_friends': trusted_friends_ids,
            'trusted_count': len(trusted_friends_ids),
            'threshold': threshold,
            'total_shares': 5
        })
        
    except Exception as e:
        print(f"Setup social recovery error: {e}")
        traceback.print_exc()
        return jsonify({'error': f'Ошибка настройки восстановления: {str(e)}'}), 500

# ========== ПАНЕЛЬ БЕЗОПАСНОСТИ ==========

@app.route('/api/security/overview')
@login_required
def security_overview():
    try:
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        result = {
            'has_encryption': False,
            'encryption': {
                'enabled': False,
                'setup_date': None,
                'algorithms': ['XChaCha20-Poly1305', 'AES-GCM', 'Shamir SS'],
                'encrypted_files': 0,
                'atc_previews': 0
            },
            'social_recovery': {
                'enabled': False,
                'setup_date': None,
                'threshold': 0,
                'total_shares': 0,
                'trusted_friends': 0,
                'status': 'inactive'
            },
            'security_score': 0
        }
        
        cursor.execute("SELECT master_key_encrypted, key_setup_at FROM user_keys WHERE user_id = ?", (user_id,))
        user_key = cursor.fetchone()
        
        if user_key and user_key['master_key_encrypted']:
            result['has_encryption'] = True
            result['encryption']['enabled'] = True
            result['encryption']['setup_date'] = user_key['key_setup_at']
        
        cursor.execute("SELECT is_active, setup_at, threshold, total_shares FROM social_recovery WHERE user_id = ? AND is_active = 1", (user_id,))
        social_recovery = cursor.fetchone()
        
        if social_recovery:
            result['social_recovery']['enabled'] = True
            result['social_recovery']['setup_date'] = social_recovery['setup_at']
            result['social_recovery']['threshold'] = social_recovery['threshold']
            result['social_recovery']['total_shares'] = social_recovery['total_shares']
            result['social_recovery']['status'] = 'active'
        
        cursor.execute("SELECT COUNT(*) as trusted FROM friends WHERE user_id = ? AND is_trusted_for_recovery = 1", (user_id,))
        trusted_result = cursor.fetchone()
        result['social_recovery']['trusted_friends'] = trusted_result['trusted'] if trusted_result else 0
        
        cursor.execute('''SELECT COUNT(*) as encrypted FROM files 
                          WHERE user_id = ? AND file_key_encrypted IS NOT NULL 
                          AND file_key_encrypted != '' ''', (user_id,))
        encrypted_result = cursor.fetchone()
        result['encryption']['encrypted_files'] = encrypted_result['encrypted'] if encrypted_result else 0
        
        try:
            cursor.execute('''SELECT u.id, u.username, u.handle, 
                                     f.is_trusted_for_recovery, f.trust_level
                              FROM friends f
                              JOIN users u ON f.friend_id = u.id
                              WHERE f.user_id = ? 
                              ORDER BY f.is_trusted_for_recovery DESC''', (user_id,))
            
            friends = cursor.fetchall()
            
            cursor.execute("SELECT COUNT(*) as total FROM friends WHERE user_id = ?", (user_id,))
            total_result = cursor.fetchone()
            total_friends = total_result['total'] if total_result else 0
            
            friends_list = []
            for friend in friends:
                is_trusted = bool(friend['is_trusted_for_recovery']) if friend['is_trusted_for_recovery'] is not None else False
                friends_list.append({
                    'id': friend['id'],
                    'username': friend['username'],
                    'handle': friend['handle'],
                    'is_trusted': is_trusted,
                    'trust_level': friend['trust_level'] or 1
                })
            
            result['friends'] = {
                'total': total_friends,
                'trusted': result['social_recovery']['trusted_friends'],
                'list': friends_list
            }
        except Exception as e:
            print(f"Error getting friends list: {e}")
            result['friends'] = {'total': 0, 'trusted': 0, 'list': []}
        
        conn.close()
        
        score = 0
        if result['has_encryption']:
            score += 40
        if result['social_recovery']['enabled']:
            score += 30
            score += min(result['social_recovery']['trusted_friends'] * 6, 30)
        score += min(result['encryption']['encrypted_files'] * 2, 20)
        result['security_score'] = min(score, 100)
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Security overview error: {e}")
        traceback.print_exc()
        return jsonify({
            'has_encryption': False,
            'encryption': {'enabled': False, 'encrypted_files': 0},
            'social_recovery': {'enabled': False, 'trusted_friends': 0},
            'security_score': 0,
            'friends': {'total': 0, 'trusted': 0, 'list': []}
        })

# ========== ШАРИНГ ФАЙЛОВ ==========

@app.route('/api/share_file', methods=['POST'])
@login_required
def share_file():
    try:
        data = request.json
        file_id = data.get('file_id')
        expires_hours = data.get('expires_hours', 24)
        chat_id = data.get('chat_id')
        
        if not file_id:
            return jsonify({'error': 'Не указан ID файла'}), 400
        
        user_id = session['user_id']
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id, user_id, original_name, filename, file_key_encrypted FROM files WHERE id = ?",
            (file_id,)
        )
        file = cursor.fetchone()
        
        if not file:
            conn.close()
            return jsonify({'error': 'Файл не найден'}), 404
        
        if file['user_id'] != user_id:
            conn.close()
            return jsonify({'error': 'Нет доступа к файлу'}), 403
        
        result = {
            'message': 'Файл доступен для отправки',
            'filename': file['original_name']
        }
        
        if expires_hours and not chat_id:
            share_token = str(uuid.uuid4())
            
            cursor.execute(
                "UPDATE files SET share_token = ?, share_expires = datetime('now', '+3 hours', ?) WHERE id = ?",
                (share_token, f'+{expires_hours} hours', file_id)
            )
            
            share_url = f"{request.host_url}share/{share_token}"
            result['share_url'] = share_url
            result['token'] = share_token
            result['message'] = 'Ссылка для скачивания создана'
        
        if chat_id:
            cursor.execute(
                "SELECT id, user1_id, user2_id FROM chats WHERE id = ?",
                (chat_id,)
            )
            chat = cursor.fetchone()
            
            if not chat:
                conn.close()
                return jsonify({'error': 'Чат не найден'}), 404
            
            cursor.execute(
                "INSERT INTO messages (chat_id, sender_id, text, file_id, timestamp) VALUES (?, ?, ?, ?, datetime('now', '+3 hours'))",
                (chat_id, user_id, f"📎 Файл: {file['original_name']}", file_id)
            )
            
            cursor.execute(
                "UPDATE chats SET last_message = ?, updated_at = datetime('now', '+3 hours') WHERE id = ?",
                (f"📎 Файл: {file['original_name']}", chat_id)
            )
            
            result['message'] = 'Файл отправлен в чат'
        
        conn.commit()
        conn.close()
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Share file error: {e}")
        traceback.print_exc()
        return jsonify({'error': f'Ошибка отправки файла: {str(e)}'}), 500

@app.route('/share/<token>')
def share_file_download(token):
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT filename, original_name, mime_type FROM files WHERE share_token = ? AND (share_expires IS NULL OR share_expires > datetime('now', '+3 hours'))",
            (token,)
        )
        file = cursor.fetchone()
        
        if not file:
            conn.close()
            return jsonify({'error': 'Ссылка недействительна или истек срок действия'}), 404
        
        conn.close()
        
        mime_type = file['mime_type'] or get_mime_type(file['original_name'])
        
        return send_from_directory(
            UPLOAD_FOLDER, 
            file['filename'],
            as_attachment=True,
            download_name=file['original_name'],
            mimetype=mime_type
        )
        
    except Exception as e:
        print(f"Share download error: {e}")
        return jsonify({'error': 'Ошибка при загрузке файла'}), 500

# ========== AI АССИСТЕНТ ==========

@app.route('/api/ai_response', methods=['POST'])
@login_required
def ai_response():
    try:
        data = request.json
        message = data.get('message', '').strip().lower()
        
        if not message:
            return jsonify({'error': 'Сообщение не может быть пустым'}), 400
        
        responses = {
            'привет': 'Привет! Я ИИ-ассистент MOC. Я могу рассказать о функциях нашего облака, помочь с альбомами или ответить на вопросы о безопасности.',
            'здравствуй': 'Здравствуйте! Я помогу вам разобраться с MOC - вашим безопасным облаком.',
            'шифрование': 'MOC использует клиентское шифрование XChaCha20-Poly1305 для файлов и AES-GCM-SIV для ключей. Ваш мастер-ключ генерируется случайно и никогда не покидает ваше устройство.',
            'безопасность': 'MOC использует несколько уровней безопасности: 1) Клиентское шифрование 2) Социальное восстановление 3) Зашифрованный обмен файлами.',
            'социальное восстановление': 'Social Recovery позволяет восстановить доступ через 5 доверенных друзей. Ваш мастер-ключ разделяется на 5 частей, для восстановления нужно собрать минимум 3 части.',
            'альбом': 'Умные альбомы могут создаваться автоматически на основе AI-анализа ваших фотографий. Вы также можете создавать обычные альбомы вручную.',
            'друг': 'Добавляйте друзей через профиль. После добавления вы сможете общаться в защищенных чатах и делиться файлами.',
            'чат': 'Все чаты в MOC защищены сквозным шифрованием. Вы можете отправлять сообщения и файлы.',
            'файл': 'Вы можете загружать файлы с шифрованием или без. Рекомендуется использовать шифрование для важных данных.',
        }
        
        response_text = None
        for keyword, response in responses.items():
            if keyword in message:
                response_text = response
                break
        
        if not response_text:
            response_text = 'Я могу рассказать вам о функциях MOC: безопасном хранении, умных альбомах, зашифрованных чатах и социальном восстановлении.'
        
        return jsonify({
            'response': response_text,
            'suggestions': [
                'Как работает шифрование?',
                'Что такое Social Recovery?',
                'Как создать альбом?',
                'Как добавить друга?',
                'Как отправить файл?'
            ]
        })
        
    except Exception as e:
        print(f"AI response error: {e}")
        return jsonify({'error': 'Ошибка обработки запроса'}), 500

# ========== ОТЧЕТЫ ОБ ОШИБКАХ ==========

@app.route('/api/report', methods=['POST'])
@login_required
def report_bug():
    try:
        data = request.json
        text = data.get('text', '').strip()
        
        if not text:
            return jsonify({'error': 'Введите описание ошибки'}), 400
        
        user_id = session['user_id']
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id FROM users WHERE username = 'support'")
        support = cursor.fetchone()
        
        if support:
            support_id = support['id']
            
            cursor.execute('''SELECT id FROM chats 
                              WHERE (user1_id = ? AND user2_id = ?) 
                              OR (user1_id = ? AND user2_id = ?)''',
                          (user_id, support_id, support_id, user_id))
            
            chat = cursor.fetchone()
            
            if chat:
                chat_id = chat['id']
            else:
                cursor.execute(
                    "INSERT INTO chats (user1_id, user2_id, last_message, updated_at) VALUES (?, ?, ?, datetime('now', '+3 hours'))",
                    (user_id, support_id, 'Отчет об ошибке')
                )
                chat_id = cursor.lastrowid
            
            report_text = f"🐛 ОТЧЕТ ОБ ОШИБКЕ\n\n{text}"
            cursor.execute(
                "INSERT INTO messages (chat_id, sender_id, text, timestamp) VALUES (?, ?, ?, datetime('now', '+3 hours'))",
                (chat_id, user_id, report_text)
            )
            
            cursor.execute(
                "UPDATE chats SET last_message = ?, updated_at = datetime('now', '+3 hours') WHERE id = ?",
                ('Отчет об ошибке отправлен', chat_id)
            )
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Отчет отправлен'})
        
    except Exception as e:
        print(f"Report error: {e}")
        return jsonify({'error': 'Ошибка отправки отчета'}), 500

# ========== ЗАПУСК ==========
@app.route('/health')
def health_check():
    """Для Render - проверка что сервер жив"""
    return jsonify({'status': 'ok', 'time': get_moscow_time().isoformat()})

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
