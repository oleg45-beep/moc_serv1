// ========== ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ==========
let CURRENT_USER = null;
let ACTIVE_CHAT_ID = null;
let POLL_INTERVAL = null;
let IS_SENDING = false;
let CURRENT_ALBUM_ID = null;
let SELECTED_FILE_ID = null;
let SELECTED_FILES = [];
let selectedRecoveryFriends = [];

// ========== ФОРМАТИРОВАНИЕ ВРЕМЕНИ (МОСКВА) ==========

function formatMoscowTime(timestamp) {
    if (!timestamp) return 'Неизвестно';
    
    try {
        const date = new Date(timestamp);
        if (isNaN(date.getTime())) {
            return timestamp;
        }
        
        // Добавляем 3 часа для Москвы (UTC+3)
        const moscowTime = new Date(date.getTime() + (3 * 60 * 60 * 1000));
        
        const day = String(moscowTime.getDate()).padStart(2, '0');
        const month = String(moscowTime.getMonth() + 1).padStart(2, '0');
        const year = moscowTime.getFullYear();
        const hours = String(moscowTime.getHours()).padStart(2, '0');
        const minutes = String(moscowTime.getMinutes()).padStart(2, '0');
        
        return `${day}.${month}.${year} ${hours}:${minutes}`;
    } catch (e) {
        console.error('Ошибка форматирования времени:', e);
        return timestamp;
    }
}

function formatMoscowTimeShort(timestamp) {
    if (!timestamp) return '';
    
    try {
        const date = new Date(timestamp);
        if (isNaN(date.getTime())) {
            return timestamp;
        }
        
        const moscowTime = new Date(date.getTime() + (3 * 60 * 60 * 1000));
        const hours = String(moscowTime.getHours()).padStart(2, '0');
        const minutes = String(moscowTime.getMinutes()).padStart(2, '0');
        
        return `${hours}:${minutes}`;
    } catch (e) {
        return timestamp;
    }
}

// Для обратной совместимости
function formatTime(timestamp) {
    return formatMoscowTimeShort(timestamp);
}

// ========== ФОРМАТИРОВАНИЕ РАЗМЕРА ФАЙЛА ==========

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Б';
    const k = 1024;
    const sizes = ['Б', 'КБ', 'МБ', 'ГБ'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// ========== ЭСКЕЙПИНГ HTML ==========

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ========== ИНИЦИАЛИЗАЦИЯ ==========

document.addEventListener('DOMContentLoaded', () => {
    checkSession();
    initEventListeners();
    
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
    
    setTimeout(() => {
        checkSecurityStatus();
    }, 2000);
});

function initEventListeners() {
    const fileInput = document.getElementById('file-in');
    if (fileInput) {
        fileInput.addEventListener('change', handleFileUpload);
    }
    
    // Обработчик Enter для AI чата
    const aiInput = document.getElementById('ai-input');
    if (aiInput) {
        aiInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendAi();
            }
        });
    }
}

// ========== АВТОРИЗАЦИЯ ==========

async function checkSession() {
    try {
        const res = await fetch('/api/profile');
        if (res.ok) {
            const data = await res.json();
            if (data.user) {
                loginSuccess(data.user);
                updateProfileUI(data);
            } else {
                showAuthModal();
            }
        } else {
            showAuthModal();
        }
    } catch(e) {
        showAuthModal();
    }
}

function showAuthModal() {
    document.getElementById('auth-modal').classList.remove('hidden');
}

let isRegister = false;

function toggleAuth() {
    isRegister = !isRegister;
    document.getElementById('modal-title').innerText = isRegister ? 'Регистрация' : 'Вход';
    const link = document.querySelector('.link');
    if (link) {
        link.innerText = isRegister ? 'Есть аккаунт? Войти' : 'Нет аккаунта?';
    }
}

async function auth() {
    const username = document.getElementById('auth-user').value.trim();
    const password = document.getElementById('auth-pass').value.trim();
    
    if (!username || !password) {
        showError('auth-err', 'Заполните все поля');
        return;
    }
    
    const endpoint = isRegister ? '/api/register' : '/api/login';
    
    try {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await res.json();
        
        if (res.ok) {
            document.getElementById('auth-modal').classList.add('hidden');
            loginSuccess({ username, ...data });
        } else {
            showError('auth-err', data.error || 'Ошибка авторизации');
        }
    } catch (e) {
        showError('auth-err', 'Ошибка соединения');
    }
}

function loginSuccess(user) {
    CURRENT_USER = {
        username: user.username,
        user_id: parseInt(user.user_id || user.id)
    };
    
    document.getElementById('app').classList.remove('hidden');
    document.getElementById('mini-name').innerText = user.username;
    document.getElementById('mini-avatar').innerText = user.username.substring(0, 2).toUpperCase();
    
    loadContent();
    loadChats();
    loadProfile();
    
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
}

function showError(elementId, message) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerText = message;
        element.style.display = 'block';
        setTimeout(() => {
            element.style.display = 'none';
        }, 3000);
    }
}

// ========== НАВИГАЦИЯ ==========

function nav(view) {
    document.querySelectorAll('section[id^="v-"]').forEach(el => {
        el.classList.add('hidden');
    });
    
    document.querySelectorAll('nav a').forEach(el => {
        el.classList.remove('active');
    });
    
    const viewElement = document.getElementById(`v-${view}`);
    const linkElement = document.getElementById(`l-${view}`);
    
    if (viewElement) viewElement.classList.remove('hidden');
    if (linkElement) linkElement.classList.add('active');
    
    switch (view) {
        case 'media':
            loadContent();
            break;
        case 'chats':
            loadChats();
            break;
        case 'profile':
            loadProfile();
            break;
        case 'home':
            setTimeout(checkSecurityStatus, 100);
            break;
    }
}

// ========== УВЕДОМЛЕНИЯ ==========

function showUploadNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `upload-notification ${type}`;
    
    let icon = 'loader';
    if (type === 'success') icon = 'check-circle';
    if (type === 'error') icon = 'alert-circle';
    
    notification.innerHTML = `
        <i data-lucide="${icon}"></i>
        <span>${message}</span>
    `;
    
    document.body.appendChild(notification);
    
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
    
    if (type === 'info') {
        return notification;
    }
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
    
    return notification;
}

// ========== ФАЙЛЫ И АЛЬБОМЫ ==========

async function handleFileUpload(e) {
    const file = e.target.files[0];
    if (!file) return;
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const res = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });
        
        if (res.ok) {
            loadContent();
            showUploadNotification(`✅ Файл загружен: ${file.name}`, 'success');
        } else {
            showUploadNotification('❌ Ошибка загрузки', 'error');
        }
    } catch (e) {
        showUploadNotification('❌ Ошибка соединения', 'error');
    }
    
    e.target.value = '';
}

async function uploadEncryptedFile() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '*/*';
    input.style.display = 'none';
    
    input.onchange = async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        
        const notification = showUploadNotification(
            `🔄 Шифрование файла...<br><small>${file.name} (${formatFileSize(file.size)})</small>`,
            'info'
        );
        
        const formData = new FormData();
        formData.append('file', file);
        
        try {
            const res = await fetch('/api/upload_encrypted', {
                method: 'POST',
                body: formData
            });
            
            const data = await res.json();
            
            if (res.ok) {
                notification.className = 'upload-notification success';
                notification.innerHTML = `
                    <i data-lucide="check-circle"></i>
                    <span>
                        ✅ Файл зашифрован!<br>
                        <small>${file.name} (${formatFileSize(file.size)})</small>
                    </span>
                `;
                
                loadContent();
                checkSecurityStatus();
                
                setTimeout(() => {
                    notification.style.animation = 'slideOut 0.3s ease';
                    setTimeout(() => notification.remove(), 300);
                }, 5000);
            } else {
                notification.className = 'upload-notification error';
                notification.innerHTML = `
                    <i data-lucide="alert-circle"></i>
                    <span>❌ ${data.error || 'Ошибка шифрования'}</span>
                `;
                
                setTimeout(() => {
                    notification.style.animation = 'slideOut 0.3s ease';
                    setTimeout(() => notification.remove(), 300);
                }, 5000);
            }
        } catch (e) {
            console.error('Ошибка загрузки:', e);
            
            notification.className = 'upload-notification error';
            notification.innerHTML = `
                <i data-lucide="alert-circle"></i>
                <span>❌ Ошибка соединения с сервером</span>
            `;
            
            setTimeout(() => {
                notification.style.animation = 'slideOut 0.3s ease';
                setTimeout(() => notification.remove(), 300);
            }, 5000);
        }
        
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
    };
    
    document.body.appendChild(input);
    input.click();
    setTimeout(() => document.body.removeChild(input), 1000);
}

async function loadContent() {
    try {
        const res = await fetch('/api/content');
        if (!res.ok) throw new Error('Ошибка загрузки');
        
        const data = await res.json();
        
        // Альбомы
        const albumsGrid = document.getElementById('albums-grid');
        if (albumsGrid) {
            if (data.albums && data.albums.length > 0) {
                albumsGrid.innerHTML = data.albums.map(album => `
                    <div class="album-card">
                        <div class="album-cover" onclick="viewAlbum(${album.id})">
                            <i data-lucide="folder"></i>
                        </div>
                        <div class="album-info">
                            <h4 onclick="viewAlbum(${album.id})" style="cursor: pointer;">${escapeHtml(album.name)}</h4>
                            <p>Создан: ${formatMoscowTime(album.created_at)}</p>
                            <div class="album-buttons">
                                <button class="btn-xs" onclick="event.stopPropagation(); openAddToAlbumModal(${album.id})" title="Добавить фото">
                                    <i data-lucide="plus"></i>
                                </button>
                                <button class="btn-xs" onclick="event.stopPropagation(); deleteAlbum(${album.id})" title="Удалить альбом">
                                    <i data-lucide="trash-2"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                `).join('');
            } else {
                albumsGrid.innerHTML = '<p style="color: var(--text-tertiary); text-align: center; padding: 20px;">📁 Нет альбомов</p>';
            }
        }
        
        // Файлы
        const filesGrid = document.getElementById('files-grid');
        if (filesGrid) {
            if (data.files && data.files.length > 0) {
                filesGrid.innerHTML = data.files.map(file => {
                    const isImage = file.mime_type && file.mime_type.startsWith('image/');
                    const imageUrl = isImage ? `/uploads/${file.filename}` : '';
                    const isEncrypted = file.file_key_encrypted && file.file_key_encrypted.length > 0;
                    
                    return `
                        <div class="file-card">
                            <div class="file-thumb clickable" ${isImage ? `onclick="openImageModal('${imageUrl}', '${escapeHtml(file.original_name)}', ${file.id})"` : ''}>
                                ${isImage
                                    ? `<img src="${imageUrl}" alt="${escapeHtml(file.original_name)}" loading="lazy">`
                                    : `<i data-lucide="file"></i>`}
                                ${isEncrypted ? `<div class="encryption-badge-small"><i data-lucide="lock" width="12"></i></div>` : ''}
                            </div>
                            <div class="album-info">
                                <h4 title="${escapeHtml(file.original_name)}">${escapeHtml(file.original_name.length > 25 ? file.original_name.substring(0, 22) + '...' : file.original_name)} ${isEncrypted ? '🔐' : ''}</h4>
                                <p>Загружен: ${formatMoscowTime(file.uploaded_at)} • ${formatFileSize(file.file_size || 0)}</p>
                                ${file.encryption_algorithm ? `<p style="font-size:11px; color:#10B981;">🔒 ${file.encryption_algorithm}</p>` : ''}
                                <div class="file-buttons">
                                    <button class="btn-xs" onclick="renameFile(${file.id})" title="Переименовать">
                                        <i data-lucide="edit-2"></i>
                                    </button>
                                    <button class="btn-xs" onclick="downloadFile(${file.id})" title="Скачать">
                                        <i data-lucide="download"></i>
                                    </button>
                                    <button class="btn-xs" onclick="shareFile(${file.id})" title="Поделиться">
                                        <i data-lucide="share-2"></i>
                                    </button>
                                    <button class="btn-xs" onclick="openAddFileToAlbumModal(${file.id})" title="Добавить в альбом">
                                        <i data-lucide="folder-plus"></i>
                                    </button>
                                    <button class="btn-xs" onclick="deleteFile(${file.id})" title="Удалить">
                                        <i data-lucide="trash-2"></i>
                                    </button>
                                </div>
                            </div>
                        </div>
                    `;
                }).join('');
            } else {
                filesGrid.innerHTML = '<p style="color: var(--text-tertiary); text-align: center; padding: 20px;">📄 Нет файлов</p>';
            }
        }
        
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
    } catch (e) {
        console.error('Ошибка загрузки контента:', e);
    }
}

// ========== СКАЧИВАНИЕ ФАЙЛОВ ==========

async function downloadFile(fileId) {
    try {
        const notification = showUploadNotification('🔄 Подготовка файла к скачиванию...', 'info');
        
        const form = document.createElement('form');
        form.method = 'GET';
        form.action = `/api/download_file/${fileId}`;
        form.target = '_blank';
        form.style.display = 'none';
        
        document.body.appendChild(form);
        form.submit();
        
        setTimeout(() => {
            notification.className = 'upload-notification success';
            notification.innerHTML = `
                <i data-lucide="check-circle"></i>
                <span>✅ Скачивание началось</span>
            `;
            
            setTimeout(() => {
                notification.remove();
                document.body.removeChild(form);
            }, 2000);
        }, 1000);
        
    } catch (e) {
        console.error('Ошибка скачивания:', e);
        showUploadNotification('❌ Ошибка соединения с сервером', 'error');
    }
}

async function downloadChatFile(fileId) {
    await downloadFile(fileId);
}

// ========== ПЕРЕИМЕНОВАНИЕ ФАЙЛОВ ==========

async function renameFile(fileId) {
    try {
        const res = await fetch('/api/files');
        const files = await res.json();
        const file = files.find(f => f.id === fileId);
        
        if (!file) {
            alert('Файл не найден');
            return;
        }
        
        const currentName = file.original_name;
        const newName = prompt('Введите новое имя файла:', currentName);
        
        if (!newName || newName === currentName) return;
        
        const renameRes = await fetch(`/api/rename_file/${fileId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ new_name: newName })
        });
        
        const data = await renameRes.json();
        
        if (renameRes.ok) {
            showUploadNotification(`✅ Файл переименован в "${data.new_name}"`, 'success');
            loadContent();
        } else {
            alert('Ошибка: ' + (data.error || 'Не удалось переименовать файл'));
        }
    } catch (e) {
        console.error('Ошибка:', e);
        alert('Ошибка соединения с сервером');
    }
}

// ========== УДАЛЕНИЕ ФАЙЛОВ ==========

async function deleteFile(fileId) {
    if (!confirm('Удалить этот файл?')) return;
    
    try {
        const res = await fetch(`/api/delete_file/${fileId}`, {
            method: 'DELETE'
        });
        
        if (res.ok) {
            showUploadNotification('✅ Файл удален', 'success');
            loadContent();
        } else {
            const data = await res.json();
            alert(data.error || 'Ошибка удаления файла');
        }
    } catch (e) {
        alert('Ошибка соединения');
    }
}

// ========== АЛЬБОМЫ ==========

async function viewAlbum(albumId) {
    try {
        const res = await fetch(`/api/album/${albumId}`);
        if (!res.ok) throw new Error('Ошибка загрузки альбома');
        
        const data = await res.json();
        CURRENT_ALBUM_ID = albumId;
        
        const modal = document.getElementById('album-view-modal');
        if (modal) {
            modal.innerHTML = `
                <div class="modal-card">
                    <div class="modal-header-row">
                        <h3><i data-lucide="folder"></i> ${escapeHtml(data.album.name)}</h3>
                        <div style="display: flex; gap: 10px;">
                            <button class="btn-xs" onclick="openAddToAlbumModal(${albumId})" title="Добавить фото">
                                <i data-lucide="plus"></i> Добавить
                            </button>
                            <button class="btn-xs" onclick="deleteAlbum(${albumId})" title="Удалить альбом">
                                <i data-lucide="trash-2"></i>
                            </button>
                            <i data-lucide="x" class="close-icon" onclick="toggleModal('album-view-modal')"></i>
                        </div>
                    </div>
                    <div class="album-view-controls">
                        <p>📸 Фотографий: ${data.files.length}</p>
                    </div>
                    <div class="files-grid" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 15px; max-height: 400px; overflow-y: auto; padding: 10px;">
                        ${data.files.length > 0 ?
                data.files.map(file => {
                    const isImage = file.mime_type && file.mime_type.startsWith('image/');
                    const imageUrl = isImage ? `/uploads/${file.filename}` : '';
                    const isEncrypted = file.file_key_encrypted && file.file_key_encrypted.length > 0;
                    return `
                                    <div class="file-select-item">
                                        <div class="file-select-thumb">
                                            ${isImage
                            ? `<img src="${imageUrl}" alt="${escapeHtml(file.original_name)}">`
                            : `<div style="display: flex; align-items: center; justify-content: center; height: 100px; background: var(--bg-tertiary);">
                                                    <i data-lucide="file"></i>
                                                   </div>`}
                                            ${isEncrypted ? `<div class="encryption-badge-small"><i data-lucide="lock" width="10"></i></div>` : ''}
                                        </div>
                                        <div class="file-select-name">${escapeHtml(file.original_name)} ${isEncrypted ? '🔐' : ''}</div>
                                        <div style="display: flex; gap: 5px; justify-content: center; margin-top: 5px;">
                                            <button class="btn-xs" onclick="downloadFile(${file.id})" title="Скачать">
                                                <i data-lucide="download"></i>
                                            </button>
                                            <button class="btn-xs" onclick="removeFileFromAlbum(${albumId}, ${file.id})" title="Удалить из альбома">
                                                <i data-lucide="x"></i>
                                            </button>
                                        </div>
                                    </div>
                                `;
                }).join('')
                : '<p style="color: var(--text-tertiary); text-align: center; width: 100%;">📭 В альбоме нет файлов</p>'
            }
                    </div>
                    <div style="margin-top: 20px;">
                        <button class="btn-secondary" onclick="toggleModal('album-view-modal'); loadContent();">
                            <i data-lucide="arrow-left"></i> Назад
                        </button>
                    </div>
                </div>
            `;
            modal.classList.remove('hidden');
            
            if (typeof lucide !== 'undefined') {
                lucide.createIcons();
            }
        }
    } catch (e) {
        console.error('Ошибка загрузки альбома:', e);
        alert('Ошибка загрузки альбома');
    }
}

async function createAlbum() {
    const name = document.getElementById('album-name').value.trim();
    if (!name) {
        alert('Введите название альбома');
        return;
    }
    
    try {
        const res = await fetch('/api/create_album', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name })
        });
        
        if (res.ok) {
            toggleModal('album-modal');
            loadContent();
            document.getElementById('album-name').value = '';
            showUploadNotification(`✅ Альбом "${name}" создан`, 'success');
        } else {
            const data = await res.json();
            alert(data.error || 'Ошибка создания альбома');
        }
    } catch (e) {
        alert('Ошибка соединения');
    }
}

async function deleteAlbum(albumId) {
    if (!confirm('Удалить этот альбом? Файлы из него не будут удалены.')) return;
    
    try {
        const res = await fetch(`/api/album/${albumId}/delete`, {
            method: 'DELETE'
        });
        
        if (res.ok) {
            showUploadNotification('✅ Альбом удален', 'success');
            toggleModal('album-view-modal');
            loadContent();
        } else {
            const data = await res.json();
            alert(data.error || 'Ошибка удаления альбома');
        }
    } catch (e) {
        alert('Ошибка соединения');
    }
}

async function removeFileFromAlbum(albumId, fileId) {
    try {
        const res = await fetch(`/api/album/${albumId}/remove_file`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_id: fileId })
        });
        
        if (res.ok) {
            showUploadNotification('✅ Файл удален из альбома', 'success');
            viewAlbum(albumId);
            loadContent();
        } else {
            const data = await res.json();
            alert(data.error || 'Ошибка удаления файла из альбома');
        }
    } catch (e) {
        alert('Ошибка соединения');
    }
}

// ========== ДОБАВЛЕНИЕ ФАЙЛОВ В АЛЬБОМ ==========

function openAddFileToAlbumModal(fileId) {
    SELECTED_FILE_ID = fileId;
    loadAlbumsForSelection();
    toggleModal('add-to-album-modal');
}

async function loadAlbumsForSelection() {
    try {
        const res = await fetch('/api/albums');
        if (!res.ok) throw new Error('Ошибка загрузки альбомов');
        
        const albums = await res.json();
        const container = document.getElementById('albums-select');
        
        if (albums.length > 0) {
            container.innerHTML = albums.map(album => `
                <div class="album-select-item" onclick="selectAlbumForFile(${album.id})" id="album-${album.id}">
                    <i data-lucide="folder"></i>
                    <span>${escapeHtml(album.name)}</span>
                    <i data-lucide="check" class="selected-check hidden"></i>
                </div>
            `).join('');
            
            document.getElementById('album-actions').classList.remove('hidden');
        } else {
            container.innerHTML = '<p style="color: var(--text-tertiary); text-align: center; padding: 20px;">📁 Нет альбомов. Создайте сначала альбом.</p>';
            document.getElementById('album-actions').classList.add('hidden');
        }
        
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
    } catch (e) {
        console.error('Ошибка:', e);
        container.innerHTML = '<p style="color: var(--danger); text-align: center;">Ошибка загрузки альбомов</p>';
    }
}

let selectedAlbumId = null;

function selectAlbumForFile(albumId) {
    document.querySelectorAll('.album-select-item').forEach(item => {
        item.classList.remove('selected');
        const check = item.querySelector('.selected-check');
        if (check) check.classList.add('hidden');
    });
    
    const selectedItem = document.getElementById(`album-${albumId}`);
    selectedItem.classList.add('selected');
    const check = selectedItem.querySelector('.selected-check');
    if (check) check.classList.remove('hidden');
    
    selectedAlbumId = albumId;
}

async function addSelectedToAlbum() {
    if (!selectedAlbumId || !SELECTED_FILE_ID) {
        alert('Выберите альбом');
        return;
    }
    
    try {
        const res = await fetch(`/api/album/${selectedAlbumId}/add_files`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_ids: [SELECTED_FILE_ID] })
        });
        
        if (res.ok) {
            showUploadNotification('✅ Файл добавлен в альбом', 'success');
            toggleModal('add-to-album-modal');
            loadContent();
        } else {
            const error = await res.json();
            alert(error.error || 'Ошибка добавления файла');
        }
    } catch (e) {
        alert('Ошибка соединения');
    }
}

function openAddToAlbumModal(albumId) {
    CURRENT_ALBUM_ID = albumId;
    loadFilesForSelection();
    toggleModal('select-files-modal');
}

async function loadFilesForSelection() {
    try {
        const res = await fetch('/api/files');
        if (!res.ok) throw new Error('Ошибка загрузки файлов');
        
        const files = await res.json();
        const container = document.getElementById('files-select');
        SELECTED_FILES = [];
        
        if (files.length > 0) {
            container.innerHTML = `
                <div class="files-select-grid">
                    ${files.map(file => {
                const isImage = file.mime_type && file.mime_type.startsWith('image/');
                const imageUrl = isImage ? `/uploads/${file.filename}` : '';
                const isEncrypted = file.file_key_encrypted && file.file_key_encrypted.length > 0;
                
                return `
                            <div class="file-select-item" onclick="toggleFileSelection(${file.id})" id="file-${file.id}">
                                <div class="file-select-thumb">
                                    ${isImage
                        ? `<img src="${imageUrl}" alt="${escapeHtml(file.original_name)}">`
                        : `<div style="display: flex; align-items: center; justify-content: center; height: 100px; background: var(--bg-tertiary);">
                                                <i data-lucide="file"></i>
                                           </div>`}
                                    ${isEncrypted ? `<div class="encryption-badge-small"><i data-lucide="lock" width="10"></i></div>` : ''}
                                </div>
                                <div class="file-select-name">${escapeHtml(file.original_name)} ${isEncrypted ? '🔐' : ''}</div>
                            </div>
                        `;
            }).join('')}
                </div>
            `;
            
            document.getElementById('files-actions').classList.remove('hidden');
        } else {
            container.innerHTML = '<p style="color: var(--text-tertiary); text-align: center; padding: 20px;">📄 Нет файлов для добавления</p>';
            document.getElementById('files-actions').classList.add('hidden');
        }
        
        if (typeof lucide !== 'undefined') {
            setTimeout(() => lucide.createIcons(), 100);
        }
    } catch (e) {
        console.error('Ошибка загрузки файлов:', e);
        const container = document.getElementById('files-select');
        container.innerHTML = `<p style="color: var(--danger); text-align: center;">Ошибка загрузки файлов</p>`;
    }
}

function toggleFileSelection(fileId) {
    const index = SELECTED_FILES.indexOf(fileId);
    const fileElement = document.getElementById(`file-${fileId}`);
    
    if (index === -1) {
        SELECTED_FILES.push(fileId);
        fileElement.classList.add('selected');
        
        if (!fileElement.querySelector('.file-select-check')) {
            const checkDiv = document.createElement('div');
            checkDiv.className = 'file-select-check';
            checkDiv.innerHTML = '<i data-lucide="check"></i>';
            fileElement.querySelector('.file-select-thumb').appendChild(checkDiv);
        }
    } else {
        SELECTED_FILES.splice(index, 1);
        fileElement.classList.remove('selected');
        const check = fileElement.querySelector('.file-select-check');
        if (check) check.remove();
    }
    
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
}

async function addSelectedFilesToAlbum() {
    if (!CURRENT_ALBUM_ID || SELECTED_FILES.length === 0) {
        alert('Выберите файлы для добавления');
        return;
    }
    
    try {
        const res = await fetch(`/api/album/${CURRENT_ALBUM_ID}/add_files`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_ids: SELECTED_FILES })
        });
        
        if (res.ok) {
            showUploadNotification(`✅ Добавлено ${SELECTED_FILES.length} файлов в альбом`, 'success');
            toggleModal('select-files-modal');
            loadContent();
            if (CURRENT_ALBUM_ID) {
                viewAlbum(CURRENT_ALBUM_ID);
            }
        } else {
            const error = await res.json();
            alert(error.error || 'Ошибка добавления файлов');
        }
    } catch (e) {
        alert('Ошибка соединения');
    }
}

// ========== ЧАТЫ ==========

async function loadChats() {
    try {
        const res = await fetch('/api/chats');
        const chats = await res.json();
        const clItems = document.getElementById('cl-items');
        
        if (!clItems) return;
        
        if (chats.length > 0) {
            clItems.innerHTML = chats.map(chat => {
                const avatarText = getChatAvatar(chat);
                const chatName = getChatName(chat);
                const lastMessage = chat.last_message || 'Нет сообщений';
                
                return `
                    <div class="chat-item ${ACTIVE_CHAT_ID === chat.id ? 'active' : ''}" 
                         onclick="openChat(${chat.id}, '${escapeHtml(chat.other_user || chat.chat_type)}', '${chat.chat_type}')">
                        <div class="chat-avatar ${chat.chat_type === 'notifications' ? 'notification' : ''}">
                            ${avatarText}
                        </div>
                        <div class="chat-info">
                            <div class="chat-name">${escapeHtml(chatName)}</div>
                            <div class="chat-preview">${escapeHtml(lastMessage)}</div>
                        </div>
                    </div>
                `;
            }).join('');
        } else {
            clItems.innerHTML = '<p style="color: var(--text-tertiary); text-align: center; padding: 20px;">💬 Нет чатов</p>';
        }
        
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
    } catch (e) {
        console.error('Ошибка загрузки чатов:', e);
    }
}

function getChatAvatar(chat) {
    if (chat.chat_type === 'notifications') return '🔔';
    if (chat.other_user === 'support') return '🛟';
    return (chat.other_user || 'U').substring(0, 2).toUpperCase();
}

function getChatName(chat) {
    if (chat.chat_type === 'notifications') return 'Уведомления';
    if (chat.other_user === 'support') return 'Поддержка MOC';
    return chat.other_user || 'Чат';
}

async function openChat(chatId, otherUserName, chatType = 'regular') {
    ACTIVE_CHAT_ID = chatId;
    
    if (POLL_INTERVAL) {
        clearInterval(POLL_INTERVAL);
        POLL_INTERVAL = null;
    }
    
    const chatEmpty = document.getElementById('chat-empty');
    const chatInterface = document.getElementById('chat-interface');
    
    if (chatEmpty) chatEmpty.classList.add('hidden');
    if (chatInterface) {
        chatInterface.classList.remove('hidden');
        createChatInterface(otherUserName, chatType);
    }
    
    document.querySelectorAll('.chat-item').forEach(item => {
        item.classList.remove('active');
    });
    
    const activeItem = document.querySelector(`.chat-item[onclick*="${chatId}"]`);
    if (activeItem) activeItem.classList.add('active');
    
    await loadMessages();
    
    if (chatType !== 'notifications') {
        POLL_INTERVAL = setInterval(() => {
            loadMessages();
        }, 5000);
    }
    
    setTimeout(() => {
        const msgInput = document.getElementById('msg-in');
        if (msgInput) msgInput.focus();
    }, 100);
}

function createChatInterface(otherUserName, chatType) {
    const chatInterface = document.getElementById('chat-interface');
    if (!chatInterface) return;
    
    const chatName = chatType === 'notifications' ? 'Уведомления' :
        otherUserName === 'support' ? 'Поддержка MOC' :
            otherUserName || 'Чат';
    
    chatInterface.innerHTML = `
        <div class="cb-head">
            <span id="cb-name">${escapeHtml(chatName)}</span>
            <button class="btn-xs" onclick="loadMessages()" title="Обновить">
                <i data-lucide="refresh-cw"></i>
            </button>
        </div>
        <div class="chat-messages-container" id="chat-messages-container">
            <div class="messages-wrapper" id="cb-msgs-content"></div>
        </div>
        <div class="cb-input-fixed">
            <input type="text" id="msg-in" placeholder="Сообщение... (Enter для отправки)">
            <button onclick="sendMsg()"><i data-lucide="send"></i></button>
        </div>
    `;
    
    const msgInput = document.getElementById('msg-in');
    if (msgInput) {
        msgInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMsg();
            }
        });
    }
    
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
}

async function loadMessages() {
    if (!ACTIVE_CHAT_ID) return;
    
    try {
        const res = await fetch(`/api/messages/${ACTIVE_CHAT_ID}`);
        if (!res.ok) throw new Error('Ошибка загрузки сообщений');
        
        const messages = await res.json();
        const cbMsgs = document.getElementById('cb-msgs-content');
        if (!cbMsgs) return;
        
        const messagesContainer = document.getElementById('chat-messages-container');
        let wasAtBottom = false;
        let scrollPosition = 0;
        
        if (messagesContainer) {
            const scrollThreshold = 50;
            wasAtBottom = messagesContainer.scrollHeight - messagesContainer.scrollTop - messagesContainer.clientHeight < scrollThreshold;
            scrollPosition = messagesContainer.scrollTop;
        }
        
        cbMsgs.innerHTML = '';
        
        if (messages.length === 0) {
            cbMsgs.innerHTML = `
                <div class="message notification">
                    <div class="notification-content">
                        <i data-lucide="message-square"></i>
                        <div class="notification-text">
                            💬 Нет сообщений. Начните общение!
                        </div>
                    </div>
                </div>
            `;
        } else {
            for (const msg of messages) {
                const isMyMessage = parseInt(msg.sender_id) === parseInt(CURRENT_USER?.user_id);
                
                let fileHtml = '';
                if (msg.file_id) {
                    try {
                        const fileRes = await fetch(`/api/file_info/${msg.file_id}`);
                        if (fileRes.ok) {
                            const fileData = await fileRes.json();
                            const isImage = fileData.mime_type && fileData.mime_type.startsWith('image/');
                            const imageUrl = isImage ? `/uploads/${fileData.filename}` : '';
                            
                            fileHtml = `
                                <div class="file-message-content">
                                    <div class="file-preview" onclick="downloadFile(${msg.file_id})">
                                        ${isImage
                                    ? `<img src="${imageUrl}" alt="${escapeHtml(fileData.original_name || 'Файл')}" style="max-width: 200px; max-height: 200px; border-radius: 8px;">`
                                    : `<div class="file-info">
                                            <i data-lucide="file"></i>
                                            <div>
                                                <strong>${escapeHtml(fileData.original_name || 'Файл')}</strong>
                                                <p style="font-size:12px; color: var(--text-tertiary); margin-top:2px;">
                                                    📦 ${formatFileSize(fileData.file_size || 0)} • ${fileData.is_encrypted ? '🔐 Зашифрован' : '📄 Документ'}
                                                    <br>
                                                    👆 Нажмите для скачивания
                                                </p>
                                            </div>
                                        </div>`}
                                    </div>
                                    ${msg.text ? `<div class="file-text">${escapeHtml(msg.text)}</div>` : ''}
                                </div>
                            `;
                        }
                    } catch (e) {
                        console.error('Ошибка загрузки файла:', e);
                    }
                }
                
                const messageHtml = `
                    <div class="message ${isMyMessage ? 'my' : 'other'} ${msg.file_id ? 'file-message' : ''}">
                        ${msg.file_id
                        ? fileHtml || `<div class="message-content">[Файл]</div>`
                        : `<div class="message-content">${escapeHtml(msg.text || '')}</div>`}
                        <div class="message-time">
                            ${formatMoscowTimeShort(msg.timestamp)}
                            ${msg.sender_name && !isMyMessage ? ` • ${escapeHtml(msg.sender_name)}` : ''}
                        </div>
                    </div>
                `;
                
                cbMsgs.innerHTML += messageHtml;
            }
        }
        
        if (messagesContainer) {
            setTimeout(() => {
                if (wasAtBottom) {
                    messagesContainer.scrollTop = messagesContainer.scrollHeight;
                } else {
                    messagesContainer.scrollTop = scrollPosition;
                }
            }, 50);
        }
        
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
        
    } catch (e) {
        console.error('Ошибка загрузки сообщений:', e);
    }
}

async function sendMsg() {
    if (IS_SENDING) return;
    IS_SENDING = true;
    
    const input = document.getElementById('msg-in');
    if (!input) {
        IS_SENDING = false;
        return;
    }
    
    const text = input.value.trim();
    if (!text || !ACTIVE_CHAT_ID) {
        IS_SENDING = false;
        return;
    }
    
    try {
        input.value = '';
        
        const res = await fetch('/api/send_message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: ACTIVE_CHAT_ID,
                text: text
            })
        });
        
        if (res.ok) {
            await loadMessages();
            loadChats();
        } else {
            const error = await res.json();
            alert('Ошибка отправки: ' + (error.error || 'Неизвестная ошибка'));
        }
        
    } catch (e) {
        console.error('Ошибка сети:', e);
        alert('Ошибка соединения с сервером');
    } finally {
        IS_SENDING = false;
        setTimeout(() => {
            const msgInput = document.getElementById('msg-in');
            if (msgInput) msgInput.focus();
        }, 50);
    }
}

async function addChat() {
    const username = prompt('Введите имя пользователя для создания чата:');
    if (!username) return;
    
    try {
        const res = await fetch('/api/create_chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        
        const data = await res.json();
        
        if (res.ok) {
            loadChats();
            if (data.id) {
                openChat(data.id, username, 'regular');
            }
        } else {
            alert(data.error || 'Ошибка создания чата');
        }
    } catch (e) {
        console.error('Ошибка:', e);
        alert('Ошибка соединения');
    }
}

// ========== ПРОФИЛЬ ==========

async function loadProfile() {
    try {
        const res = await fetch('/api/profile');
        if (!res.ok) throw new Error('Ошибка загрузки');
        
        const data = await res.json();
        updateProfileUI(data);
    } catch (e) {
        console.error('Ошибка загрузки профиля:', e);
    }
}

function updateProfileUI(data) {
    if (!data.user) return;
    
    document.getElementById('p-username').innerText = data.user.username;
    document.getElementById('p-handle').innerText = `@${data.user.handle || data.user.username}`;
    document.getElementById('p-bio').innerText = data.user.bio || 'Нет информации';
    
    const avatarText = data.user.username.substring(0, 2).toUpperCase();
    document.getElementById('p-avatar').innerText = avatarText;
    document.getElementById('mini-avatar').innerText = avatarText;
    document.getElementById('mini-name').innerText = data.user.username;
    
    const stats = data.stats || {};
    document.getElementById('s-photos').innerText = stats.photos || 0;
    document.getElementById('s-albums').innerText = stats.albums || 0;
    document.getElementById('s-friends').innerText = stats.friends || 0;
    document.getElementById('s-chats').innerText = stats.chats || 0;
    
    const friendRequestsSec = document.getElementById('friend-requests-sec');
    const friendRequestsList = document.getElementById('friend-requests-list');
    
    if (data.friend_requests && data.friend_requests.length > 0) {
        friendRequestsSec.style.display = 'block';
        friendRequestsList.innerHTML = data.friend_requests.map(request => `
            <div class="friend-request-item">
                <div class="friend-request-info">
                    <div class="friend-avatar">
                        ${request.username.substring(0, 2).toUpperCase()}
                    </div>
                    <div class="friend-info">
                        <div class="friend-name">${escapeHtml(request.username)}</div>
                        <div class="friend-handle">@${escapeHtml(request.handle || request.username)}</div>
                    </div>
                </div>
                <div class="friend-request-actions">
                    <button class="btn-xs btn-success" onclick="handleFriendRequest(${request.id}, true)">
                        <i data-lucide="check"></i> Принять
                    </button>
                    <button class="btn-xs btn-danger" onclick="handleFriendRequest(${request.id}, false)">
                        <i data-lucide="x"></i> Отклонить
                    </button>
                </div>
            </div>
        `).join('');
    } else {
        friendRequestsSec.style.display = 'none';
    }
    
    const friendsList = document.getElementById('friends-list');
    if (friendsList) {
        if (data.friends_list && data.friends_list.length > 0) {
            friendsList.innerHTML = data.friends_list.map(friend => `
                <div class="friend-item">
                    <div class="friend-avatar">
                        ${friend.username.substring(0, 2).toUpperCase()}
                    </div>
                    <div class="friend-info">
                        <div class="friend-name">${escapeHtml(friend.username)}</div>
                        <div class="friend-handle">@${escapeHtml(friend.handle || friend.username)}</div>
                    </div>
                    <button class="btn-xs btn-danger" onclick="removeFriend(${friend.id})" title="Удалить из друзей">
                        <i data-lucide="user-minus"></i>
                    </button>
                </div>
            `).join('');
        } else {
            friendsList.innerHTML = '<p style="color: var(--text-tertiary); text-align: center; padding: 20px;">👥 Нет друзей</p>';
        }
    }
    
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
}

function openEditProfile() {
    document.getElementById('edit-handle').value = CURRENT_USER?.username || '';
    document.getElementById('edit-bio').value = document.getElementById('p-bio').innerText;
    toggleModal('edit-profile-modal');
}

async function saveProfile() {
    const handle = document.getElementById('edit-handle').value.trim();
    const bio = document.getElementById('edit-bio').value.trim();
    
    try {
        const res = await fetch('/api/update_profile', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ handle, bio })
        });
        
        if (res.ok) {
            toggleModal('edit-profile-modal');
            loadProfile();
            showUploadNotification('✅ Профиль обновлен', 'success');
        } else {
            const error = await res.json();
            alert(error.error || 'Ошибка обновления профиля');
        }
    } catch (e) {
        alert('Ошибка соединения');
    }
}

async function handleFriendRequest(requestId, accept) {
    try {
        const res = await fetch('/api/respond_friend_request', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ request_id: requestId, accept })
        });
        
        if (res.ok) {
            showUploadNotification(accept ? '✅ Запрос принят' : '✅ Запрос отклонен', 'success');
            loadProfile();
        } else {
            alert('Ошибка');
        }
    } catch (e) {
        alert('Ошибка соединения');
    }
}

async function addFriend() {
    const username = prompt('Введите имя пользователя для отправки запроса в друзья:');
    if (!username) return;
    
    try {
        const res = await fetch('/api/send_friend_request', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        
        const data = await res.json();
        
        if (res.ok) {
            showUploadNotification('✅ Запрос в друзья отправлен', 'success');
            loadProfile();
        } else {
            alert(data.error || 'Ошибка отправки запроса');
        }
    } catch (e) {
        alert('Ошибка соединения');
    }
}

async function removeFriend(friendId) {
    if (!confirm('Удалить из друзей?')) return;
    
    try {
        const res = await fetch('/api/remove_friend', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ friend_id: friendId })
        });
        
        if (res.ok) {
            showUploadNotification('✅ Пользователь удален из друзей', 'success');
            loadProfile();
        } else {
            const error = await res.json();
            alert(error.error || 'Ошибка удаления друга');
        }
    } catch (e) {
        alert('Ошибка соединения');
    }
}

// ========== ШАРИНГ ФАЙЛОВ ==========

async function shareFile(fileId) {
    SELECTED_FILE_ID = fileId;
    
    try {
        const shareInfo = document.getElementById('share-file-info');
        
        shareInfo.innerHTML = `
            <div class="file-info-share">
                <i data-lucide="loader"></i>
                <div>
                    <strong>Загрузка информации о файле...</strong>
                </div>
            </div>
        `;
        
        const chatsRes = await fetch('/api/chats');
        const chats = chatsRes.ok ? await chatsRes.json() : [];
        const chatSelect = document.getElementById('share-chat-select');
        
        chatSelect.innerHTML = '<option value="">Выберите чат...</option>';
        chats.forEach(chat => {
            if (chat.chat_type !== 'notifications') {
                chatSelect.innerHTML += `<option value="${chat.id}">${escapeHtml(getChatName(chat))}</option>`;
            }
        });
        
        document.getElementById('share-result').classList.add('hidden');
        toggleModal('share-file-modal');
        
        const fileInfoRes = await fetch(`/api/file_info/${fileId}`);
        if (fileInfoRes.ok) {
            const file = await fileInfoRes.json();
            
            shareInfo.innerHTML = `
                <div class="file-info-share">
                    <i data-lucide="${file.mime_type && file.mime_type.startsWith('image/') ? 'image' : 'file'}"></i>
                    <div>
                        <strong>${escapeHtml(file.original_name)} ${file.is_encrypted ? '🔐' : ''}</strong>
                        <p style="font-size: 12px; color: var(--text-tertiary); margin-top: 5px;">
                            ${file.is_encrypted ? 'Зашифрованный файл • ' : ''}
                            📦 ${formatFileSize(file.file_size || 0)} • 
                            📅 ${formatMoscowTime(file.uploaded_at)}
                        </p>
                    </div>
                </div>
            `;
            
            if (typeof lucide !== 'undefined') {
                lucide.createIcons();
            }
        }
        
    } catch (e) {
        console.error('Ошибка при открытии шаринга:', e);
        alert('Ошибка загрузки информации о файле');
    }
}

async function createShareLink() {
    const expires = document.getElementById('share-expires').value;
    
    if (!SELECTED_FILE_ID) {
        alert('Файл не выбран');
        return;
    }
    
    try {
        const res = await fetch('/api/share_file', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                file_id: SELECTED_FILE_ID,
                expires_hours: parseInt(expires)
            })
        });
        
        if (res.ok) {
            const data = await res.json();
            document.getElementById('share-link').value = data.share_url;
            document.getElementById('share-result').classList.remove('hidden');
            document.getElementById('share-link').select();
            showUploadNotification('✅ Ссылка создана', 'success');
        } else {
            const error = await res.json();
            alert('Ошибка создания ссылки: ' + (error.error || 'Попробуйте еще раз'));
        }
    } catch (e) {
        alert('Ошибка соединения с сервером');
    }
}

async function sendFileToChat() {
    const chatId = document.getElementById('share-chat-select').value;
    if (!chatId) {
        alert('Выберите чат');
        return;
    }
    
    if (!SELECTED_FILE_ID) {
        alert('Файл не выбран');
        return;
    }
    
    try {
        const res = await fetch('/api/share_file', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                file_id: SELECTED_FILE_ID,
                chat_id: parseInt(chatId)
            })
        });
        
        if (res.ok) {
            showUploadNotification('✅ Файл отправлен в чат', 'success');
            toggleModal('share-file-modal');
            
            if (parseInt(ACTIVE_CHAT_ID) === parseInt(chatId)) {
                setTimeout(() => loadMessages(), 500);
            }
        } else {
            const error = await res.json();
            alert('Ошибка отправки файла: ' + (error.error || 'Попробуйте еще раз'));
        }
    } catch (e) {
        console.error('Ошибка:', e);
        alert('Ошибка соединения');
    }
}

function copyShareLink() {
    const linkInput = document.getElementById('share-link');
    linkInput.select();
    document.execCommand('copy');
    showUploadNotification('✅ Ссылка скопирована', 'success');
}

// ========== МОДАЛЬНОЕ ОКНО ИЗОБРАЖЕНИЯ ==========

function openImageModal(imageUrl, filename, fileId = null) {
    if (fileId) {
        SELECTED_FILE_ID = fileId;
    }
    
    const modal = document.getElementById('image-modal');
    const modalImage = document.getElementById('modal-image');
    
    if (modal && modalImage) {
        modalImage.src = imageUrl;
        modalImage.alt = filename;
        modal.classList.remove('hidden');
        
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
    }
}

async function downloadImage() {
    const modalImage = document.getElementById('modal-image');
    if (!modalImage || !modalImage.src) return;
    
    if (SELECTED_FILE_ID) {
        await downloadFile(SELECTED_FILE_ID);
    } else {
        const link = document.createElement('a');
        link.href = modalImage.src;
        link.download = modalImage.alt || 'image.png';
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        document.body.appendChild(link);
        link.click();
        setTimeout(() => document.body.removeChild(link), 1000);
    }
}

// ========== БЕЗОПАСНОСТЬ ==========

async function checkSecurityStatus() {
    try {
        const res = await fetch('/api/security/overview');
        const data = await res.json();
        
        if (res.ok) {
            updateSecurityUI(data);
            return data;
        }
    } catch (e) {
        console.error('Ошибка проверки безопасности:', e);
    }
}

function updateSecurityUI(securityData) {
    const homeEncryptionInfo = document.getElementById('home-encryption-info');
    if (homeEncryptionInfo) {
        const encryption = securityData.encryption || { enabled: false, encrypted_files: 0 };
        const socialRecovery = securityData.social_recovery || { enabled: false, trusted_friends: 0, threshold: 0, total_shares: 0 };
        const securityScore = securityData.security_score || 0;
        
        if (!encryption.enabled) {
            homeEncryptionInfo.innerHTML = `
                <div class="security-setup-prompt">
                    <div class="security-prompt-icon">
                        <i data-lucide="shield" width="48" height="48"></i>
                    </div>
                    <h4>Защитите свои данные</h4>
                    <p>Включите шифрование для полной безопасности ваших файлов и сообщений</p>
                    <div style="display: flex; gap: 10px; margin-top: 20px; justify-content: center;">
                        <button class="btn-primary" onclick="initEncryption()">
                            <i data-lucide="lock"></i> Включить шифрование
                        </button>
                        <button class="btn-secondary" onclick="uploadEncryptedFile()">
                            <i data-lucide="upload"></i> Загрузить с шифрованием
                        </button>
                    </div>
                </div>
            `;
        } else {
            homeEncryptionInfo.innerHTML = `
                <div style="display: grid; gap: 15px;">
                    <div class="security-status-card active">
                        <div class="security-status-header">
                            <i data-lucide="lock"></i>
                            <h4>Шифрование файлов</h4>
                            <span class="security-badge badge-success">АКТИВНО</span>
                        </div>
                        <div class="security-status-body">
                            <p>Алгоритмы: XChaCha20-Poly1305, AES-GCM-SIV, Shamir SS</p>
                            <p>Зашифровано файлов: <strong>${encryption.encrypted_files || 0}</strong></p>
                            ${encryption.setup_date ?
                    `<p>Настроено: ${formatMoscowTime(encryption.setup_date)}</p>` : ''}
                        </div>
                    </div>
                    
                    <div class="security-status-card ${socialRecovery.enabled ? 'active' : 'inactive'}">
                        <div class="security-status-header">
                            <i data-lucide="${socialRecovery.enabled ? 'users' : 'user-x'}"></i>
                            <h4>Social Recovery</h4>
                            <span class="security-badge ${socialRecovery.enabled ? 'badge-success' : 'badge-warning'}">
                                ${socialRecovery.enabled ? 'АКТИВНО' : 'НЕ АКТИВНО'}
                            </span>
                        </div>
                        <div class="security-status-body">
                            ${socialRecovery.enabled ? `
                                <p>Порог восстановления: <strong>${socialRecovery.threshold || 0} из ${socialRecovery.total_shares || 0}</strong></p>
                                <p>Доверенных друзей: <strong>${socialRecovery.trusted_friends || 0}/5</strong></p>
                                ${socialRecovery.setup_date ?
                        `<p>Настроено: ${formatMoscowTime(socialRecovery.setup_date)}</p>` : ''}
                            ` : `
                                <p>Восстановление доступа через друзей не настроено</p>
                            `}
                        </div>
                    </div>
                    
                    <div class="security-score-display">
                        <div class="security-score-header">
                            <i data-lucide="shield"></i>
                            <h4>Оценка безопасности</h4>
                        </div>
                        <div class="security-score-progress">
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: ${securityScore}%"></div>
                            </div>
                            <span class="security-score-value">${securityScore}/100</span>
                        </div>
                    </div>
                </div>
            `;
        }
    }
    
    if (typeof lucide !== 'undefined') {
        setTimeout(() => lucide.createIcons(), 100);
    }
}

function openSecurityDashboard() {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-card security-dashboard" style="max-width: 700px;">
            <div class="modal-header-row">
                <h3><i data-lucide="shield"></i> Панель безопасности</h3>
                <div style="display: flex; gap: 10px; align-items: center;">
                    <button class="btn-xs btn-secondary" onclick="openSecurityTutorial()" title="Советы">
                        <i data-lucide="lightbulb"></i> Советы
                    </button>
                    <i data-lucide="x" class="close-icon" onclick="this.closest('.modal').remove()"></i>
                </div>
            </div>
            
            <div class="security-dashboard-content">
                <div class="security-overview" id="security-dashboard-overview">
                    <div class="loading-spinner" style="text-align: center; padding: 40px;">
                        <i data-lucide="loader" width="24" height="24" style="animation: spin 1s linear infinite;"></i>
                        <p style="margin-top: 10px;">Загрузка информации о безопасности...</p>
                    </div>
                </div>
                
                <div class="security-actions-grid" id="security-actions-grid"></div>
                
                <div class="security-tips-section">
                    <h4><i data-lucide="lightbulb"></i> Советы по безопасности</h4>
                    <div id="security-tips-list"></div>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    fetch('/api/security/overview')
        .then(res => res.json())
        .then(data => {
            const overview = document.getElementById('security-dashboard-overview');
            const actionsGrid = document.getElementById('security-actions-grid');
            
            overview.innerHTML = `
                <div class="security-score-large">
                    <div class="score-circle" style="--score: ${data.security_score};">
                        <span>${data.security_score}</span>
                    </div>
                    <div class="score-info">
                        <h3>Общая оценка безопасности</h3>
                        <p>${getSecurityRating(data.security_score)}</p>
                    </div>
                </div>
                
                <div class="security-stats">
                    <div class="stat-item">
                        <i data-lucide="lock"></i>
                        <div>
                            <span class="stat-value">${data.encryption.encrypted_files}</span>
                            <span class="stat-label">Зашифрованных файлов</span>
                        </div>
                    </div>
                    <div class="stat-item">
                        <i data-lucide="users"></i>
                        <div>
                            <span class="stat-value">${data.social_recovery.trusted_friends}/5</span>
                            <span class="stat-label">Доверенных друзей</span>
                        </div>
                    </div>
                    <div class="stat-item">
                        <i data-lucide="shield"></i>
                        <div>
                            <span class="stat-value">${data.encryption.enabled ? 'Да' : 'Нет'}</span>
                            <span class="stat-label">Шифрование</span>
                        </div>
                    </div>
                </div>
            `;
            
            let actionsHtml = '';
            
            if (!data.encryption.enabled) {
                actionsHtml += `
                    <div class="security-action-card" onclick="initEncryption()">
                        <div class="action-icon">
                            <i data-lucide="key"></i>
                        </div>
                        <h4>Мастер-ключ</h4>
                        <p>Сгенерировать случайный мастер-ключ</p>
                    </div>
                `;
            }
            
            actionsHtml += `
                <div class="security-action-card" onclick="setupSocialRecovery()">
                    <div class="action-icon">
                        <i data-lucide="users"></i>
                    </div>
                    <h4>Social Recovery</h4>
                    <p>${data.social_recovery.enabled ? 'Настроено' : 'Настроить восстановление'}</p>
                </div>
                
                <div class="security-action-card" onclick="uploadEncryptedFile()">
                    <div class="action-icon">
                        <i data-lucide="upload"></i>
                    </div>
                    <h4>Зашифровать файл</h4>
                    <p>Загрузить файл с шифрованием</p>
                </div>
                
                <div class="security-action-card" onclick="openSecurityTutorial()">
                    <div class="action-icon">
                        <i data-lucide="info"></i>
                    </div>
                    <h4>Обучение</h4>
                    <p>Как работает система безопасности</p>
                </div>
            `;
            
            actionsGrid.innerHTML = actionsHtml;
            
            const tipsList = document.getElementById('security-tips-list');
            tipsList.innerHTML = getSecurityTips(data).map(tip => `
                <div class="security-tip">
                    <i data-lucide="check-circle"></i>
                    <span>${tip}</span>
                </div>
            `).join('');
            
            if (typeof lucide !== 'undefined') {
                lucide.createIcons();
            }
        })
        .catch(e => {
            console.error('Error loading security data:', e);
            const overview = document.getElementById('security-dashboard-overview');
            overview.innerHTML = `
                <div style="text-align: center; padding: 40px;">
                    <i data-lucide="alert-circle" width="48" height="48" style="color: var(--danger);"></i>
                    <p style="margin-top: 15px; color: var(--text-tertiary);">Ошибка загрузки данных безопасности</p>
                    <button class="btn-secondary" onclick="checkSecurityStatus()" style="margin-top: 15px;">
                        <i data-lucide="refresh-cw"></i> Попробовать снова
                    </button>
                </div>
            `;
            
            if (typeof lucide !== 'undefined') {
                lucide.createIcons();
            }
        });
    
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
}

function getSecurityTips(securityData) {
    const tips = [];
    
    if (!securityData.encryption.enabled) {
        tips.push('🔐 Включите шифрование для защиты ваших файлов');
    } else {
        tips.push('✅ Шифрование активно - ваши файлы защищены');
    }
    
    if (!securityData.social_recovery.enabled) {
        tips.push('👥 Настройте Social Recovery для восстановления доступа');
    } else {
        tips.push(`✅ Social Recovery настроен (${securityData.social_recovery.trusted_friends}/5 друзей)`);
    }
    
    if (securityData.encryption.encrypted_files < 5) {
        tips.push('📁 Загрузите больше файлов с шифрованием');
    }
    
    if (securityData.social_recovery.enabled && securityData.social_recovery.trusted_friends < 5) {
        tips.push('👤 Добавьте больше доверенных друзей для восстановления');
    }
    
    if (securityData.security_score < 70) {
        tips.push('📈 Улучшите настройки безопасности для повышения оценки');
    }
    
    return tips.length > 0 ? tips : ['🎉 Ваша безопасность настроена оптимально!'];
}

function getSecurityRating(score) {
    if (score >= 90) return '🛡️ Отличная защита';
    if (score >= 70) return '👍 Хорошая защита';
    if (score >= 40) return '⚠️ Средняя защита';
    return '🔓 Требуется улучшение';
}

function openSecurityTutorial() {
    alert('🔐 MOC использует:\n\n' +
          '1. Случайный мастер-ключ (32 байта)\n' +
          '2. XChaCha20-Poly1305 для файлов\n' +
          '3. AES-GCM-SIV для ключей\n' +
          '4. Схему Шамира для Social Recovery\n' +
          '5. Proxy Re-Encryption для шаринга\n\n' +
          '✅ Все шифрование выполняется на клиенте!');
}

// ========== ШИФРОВАНИЕ ==========

async function initEncryption() {
    if (confirm('🛡️ Сгенерировать случайный мастер-ключ?\n\n• Ключ создается автоматически\n• Никогда не показывается пользователю\n• Защищает все ваши файлы')) {
        try {
            const res = await fetch('/api/init_encryption', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            });
            
            if (res.ok) {
                const data = await res.json();
                showUploadNotification('✅ Мастер-ключ успешно сгенерирован!', 'success');
                checkSecurityStatus();
                
                const modal = document.querySelector('.security-dashboard');
                if (modal) {
                    modal.closest('.modal').remove();
                    setTimeout(() => openSecurityDashboard(), 500);
                }
            } else {
                const error = await res.json();
                alert('Ошибка: ' + (error.error || 'Неизвестная ошибка'));
            }
        } catch (e) {
            console.error('Ошибка:', e);
            alert('Ошибка соединения с сервером');
        }
    }
}

// ========== СОЦИАЛЬНОЕ ВОССТАНОВЛЕНИЕ ==========

async function setupSocialRecovery() {
    try {
        const securityRes = await fetch('/api/security/overview');
        if (!securityRes.ok) throw new Error('Ошибка загрузки данных безопасности');
        
        const securityData = await securityRes.json();
        const friendsList = securityData.friends?.list || [];
        
        if (friendsList.length < 5) {
            alert('❌ Нужно минимум 5 друзей для настройки восстановления.\n\nДобавьте больше друзей через профиль.');
            return;
        }
        
        selectedRecoveryFriends = [];
        
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.id = 'social-recovery-modal';
        modal.innerHTML = `
            <div class="modal-card" style="max-width: 600px;">
                <div class="modal-header-row">
                    <h3><i data-lucide="users"></i> Настройка Social Recovery</h3>
                    <i data-lucide="x" class="close-icon" onclick="closeSocialRecoveryModal()"></i>
                </div>
                <p style="margin-bottom: 20px; color: var(--text-tertiary);">
                    🛡️ Ваш мастер-ключ будет разделен на 5 частей<br>
                    📊 Каждая часть хранится у одного из друзей<br>
                    🔑 Для восстановления потребуется собрать минимум 3 части
                </p>
                
                <div class="recovery-stats">
                    <div class="recovery-stat">
                        <span class="stat-value" id="selected-count">0</span>
                        <span class="stat-label">Выбрано</span>
                    </div>
                    <div class="recovery-stat">
                        <span class="stat-value">5</span>
                        <span class="stat-label">Нужно</span>
                    </div>
                </div>
                
                <div id="trusted-friends-select" style="max-height: 300px; overflow-y: auto; margin-bottom: 20px;">
                    ${friendsList.map(friend => {
                        const isTrusted = friend.is_trusted;
                        return `
                            <div class="friend-select-item ${isTrusted ? 'trusted' : ''}" 
                                 data-id="${friend.id}" 
                                 onclick="toggleFriendSelection(${friend.id})"
                                 id="friend-select-${friend.id}">
                                <div class="friend-avatar-small">
                                    ${friend.username.substring(0, 2).toUpperCase()}
                                    ${isTrusted ? '<span class="trusted-badge">✓</span>' : ''}
                                </div>
                                <div style="flex: 1;">
                                    <strong>${escapeHtml(friend.username)}</strong>
                                    <div style="font-size: 12px; color: var(--text-tertiary);">@${escapeHtml(friend.handle || friend.username)}</div>
                                    ${isTrusted ? '<div style="font-size: 11px; color: #10B981; margin-top: 2px;">✓ Уже доверенный</div>' : ''}
                                </div>
                                <i data-lucide="check" class="friend-check hidden"></i>
                            </div>
                        `;
                    }).join('')}
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <label style="display: flex; align-items: center; gap: 10px;">
                            <span>Минимум для восстановления:</span>
                            <select id="recovery-threshold" style="width: auto;">
                                <option value="3">3 друга</option>
                                <option value="4" selected>4 друга</option>
                                <option value="5">5 друзей</option>
                            </select>
                        </label>
                    </div>
                    <button class="btn-primary" onclick="confirmSocialRecovery()" id="confirm-recovery-btn" disabled>
                        <i data-lucide="shield"></i> <span id="btn-text">Разделить ключ (0/5)</span>
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
        
    } catch (e) {
        console.error('Ошибка загрузки друзей:', e);
        alert('Ошибка загрузки списка друзей');
    }
}

function closeSocialRecoveryModal() {
    const modal = document.getElementById('social-recovery-modal');
    if (modal) modal.remove();
    selectedRecoveryFriends = [];
}

function toggleFriendSelection(friendId) {
    const index = selectedRecoveryFriends.indexOf(friendId);
    
    if (index === -1) {
        if (selectedRecoveryFriends.length >= 5) {
            alert('Можно выбрать только 5 друзей');
            return;
        }
        selectedRecoveryFriends.push(friendId);
    } else {
        selectedRecoveryFriends.splice(index, 1);
    }
    
    updateSelectionUI();
}

function updateSelectionUI() {
    const selectedCount = document.getElementById('selected-count');
    if (selectedCount) {
        selectedCount.textContent = selectedRecoveryFriends.length;
    }
    
    const confirmBtn = document.getElementById('confirm-recovery-btn');
    const btnText = document.getElementById('btn-text');
    
    if (confirmBtn && btnText) {
        if (selectedRecoveryFriends.length === 5) {
            confirmBtn.disabled = false;
            btnText.textContent = `Разделить ключ (5/5)`;
        } else {
            confirmBtn.disabled = true;
            btnText.textContent = `Разделить ключ (${selectedRecoveryFriends.length}/5)`;
        }
    }
    
    selectedRecoveryFriends.forEach(friendId => {
        const friendElement = document.getElementById(`friend-select-${friendId}`);
        if (friendElement) {
            friendElement.classList.add('selected');
            const checkIcon = friendElement.querySelector('.friend-check');
            if (checkIcon) checkIcon.classList.remove('hidden');
        }
    });
    
    document.querySelectorAll('.friend-select-item').forEach(item => {
        const friendId = parseInt(item.getAttribute('data-id'));
        if (!selectedRecoveryFriends.includes(friendId)) {
            item.classList.remove('selected');
            const checkIcon = item.querySelector('.friend-check');
            if (checkIcon) checkIcon.classList.add('hidden');
        }
    });
}

async function confirmSocialRecovery() {
    if (selectedRecoveryFriends.length !== 5) {
        alert('Нужно выбрать ровно 5 друзей');
        return;
    }
    
    const threshold = parseInt(document.getElementById('recovery-threshold').value);
    
    try {
        const res = await fetch('/api/social_recovery/setup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                trusted_friends: selectedRecoveryFriends,
                threshold: threshold
            })
        });
        
        if (res.ok) {
            const data = await res.json();
            
            showUploadNotification(
                `✅ Social Recovery настроен!<br><small>Ключ разделен между ${data.trusted_friends?.length || 5} друзьями</small>`,
                'success'
            );
            
            closeSocialRecoveryModal();
            selectedRecoveryFriends = [];
            
            setTimeout(() => {
                checkSecurityStatus();
                loadProfile();
            }, 1000);
            
        } else {
            const error = await res.json();
            alert('Ошибка: ' + (error.error || 'Неизвестная ошибка'));
        }
    } catch (e) {
        console.error('Ошибка:', e);
        alert('Ошибка соединения с сервером');
    }
}

// ========== AI ЧАТ ==========

function insertAiSuggestion(text) {
    const input = document.getElementById('ai-input');
    if (input) {
        input.value = text;
        input.focus();
    }
}

async function sendAi() {
    const input = document.getElementById('ai-input');
    const text = input.value.trim();
    const messagesDiv = document.getElementById('ai-messages');
    
    if (!text) return;
    
    messagesDiv.innerHTML += `
        <div class="msg user">
            <div class="msg-header">
                <i data-lucide="user" width="16" height="16"></i>
                <strong>Вы:</strong>
            </div>
            <div class="msg-text">${escapeHtml(text)}</div>
        </div>
    `;
    
    input.value = '';
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
    
    messagesDiv.innerHTML += `
        <div class="msg ai loading">
            <div class="msg-header">
                <i data-lucide="bot" width="16" height="16"></i>
                <strong>MOC.AI:</strong>
            </div>
            <div class="msg-text">Думаю...</div>
        </div>
    `;
    
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
    
    try {
        const res = await fetch('/api/ai_response', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: text })
        });
        
        const data = await res.json();
        
        const loadingMsg = messagesDiv.querySelector('.loading');
        if (loadingMsg) loadingMsg.remove();
        
        if (res.ok) {
            messagesDiv.innerHTML += `
                <div class="msg ai">
                    <div class="msg-header">
                        <i data-lucide="bot" width="16" height="16"></i>
                        <strong>MOC.AI:</strong>
                    </div>
                    <div class="msg-text">${escapeHtml(data.response)}</div>
                </div>
            `;
        } else {
            messagesDiv.innerHTML += `
                <div class="msg ai">
                    <div class="msg-header">
                        <i data-lucide="bot" width="16" height="16"></i>
                        <strong>MOC.AI:</strong>
                    </div>
                    <div class="msg-text">Извините, произошла ошибка. Попробуйте позже.</div>
                </div>
            `;
        }
        
    } catch (e) {
        const loadingMsg = messagesDiv.querySelector('.loading');
        if (loadingMsg) loadingMsg.remove();
        
        messagesDiv.innerHTML += `
            <div class="msg ai">
                <div class="msg-header">
                    <i data-lucide="bot" width="16" height="16"></i>
                    <strong>MOC.AI:</strong>
                </div>
                <div class="msg-text">Ошибка соединения. Проверьте интернет.</div>
            </div>
        `;
    }
    
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
    
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
}

// ========== ОТЧЕТ ОБ ОШИБКАХ ==========

async function sendBug() {
    const text = document.getElementById('bug-text').value.trim();
    if (!text) {
        alert('Введите описание ошибки');
        return;
    }
    
    try {
        const res = await fetch('/api/report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text })
        });
        
        if (res.ok) {
            showUploadNotification('✅ Отчет отправлен в поддержку', 'success');
            toggleModal('bug-modal');
            document.getElementById('bug-text').value = '';
        } else {
            alert('Ошибка отправки отчета');
        }
    } catch (e) {
        alert('Ошибка соединения');
    }
}

// ========== УПРАВЛЕНИЕ МОДАЛКАМИ ==========

function toggleModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.toggle('hidden');
        
        if (!modal.classList.contains('hidden')) {
            const input = modal.querySelector('input, textarea');
            if (input) input.focus();
            
            if (typeof lucide !== 'undefined') {
                setTimeout(() => lucide.createIcons(), 100);
            }
        } else {
            if (modalId === 'select-files-modal') {
                SELECTED_FILES = [];
                CURRENT_ALBUM_ID = null;
            }
            if (modalId === 'share-file-modal') {
                SELECTED_FILE_ID = null;
            }
            if (modalId === 'add-to-album-modal') {
                SELECTED_FILE_ID = null;
                selectedAlbumId = null;
            }
        }
    }
}

// ========== ВЫХОД ==========

async function logout() {
    try {
        await fetch('/api/logout', { method: 'POST' });
        window.location.reload();
    } catch (e) {
        console.error('Ошибка выхода:', e);
    }
}