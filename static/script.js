let CURRENT_USER = null;
let ACTIVE_CHAT_ID = null;
let POLL_INTERVAL = null;
let IS_SENDING = false;
let CURRENT_ALBUM_ID = null;
let SELECTED_FILE_ID = null;
let SELECTED_FILES = [];
let selectedRecoveryFriends = [];
let selectedFileForChat = null;
let currentViewFileId = null;
let pendingDeleteMessageId = null;
let pendingDeleteChatId = null;
let isUserScrolling = false;
let scrollTimeout = null;
let shouldAutoScroll = true;

// ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================
function formatMoscowTime(timestamp) {
    if (!timestamp) return 'Неизвестно';
    try {
        const date = new Date(timestamp);
        if (isNaN(date.getTime())) return timestamp;
        const moscowTime = new Date(date.getTime() + (3 * 60 * 60 * 1000));
        return `${String(moscowTime.getDate()).padStart(2, '0')}.${String(moscowTime.getMonth() + 1).padStart(2, '0')}.${moscowTime.getFullYear()} ${String(moscowTime.getHours()).padStart(2, '0')}:${String(moscowTime.getMinutes()).padStart(2, '0')}`;
    } catch(e) { return timestamp; }
}

function formatMoscowTimeShort(timestamp) {
    if (!timestamp) return '';
    try {
        const date = new Date(timestamp);
        if (isNaN(date.getTime())) return timestamp;
        const moscowTime = new Date(date.getTime() + (3 * 60 * 60 * 1000));
        return `${String(moscowTime.getHours()).padStart(2, '0')}:${String(moscowTime.getMinutes()).padStart(2, '0')}`;
    } catch(e) { return timestamp; }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Б';
    const sizes = ['Б', 'КБ', 'МБ', 'ГБ'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return parseFloat((bytes / Math.pow(1024, i)).toFixed(1)) + ' ' + sizes[i];
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function getMessageStatusIcon(status) {
    if (status === 'read') return '✓✓';
    if (status === 'delivered') return '✓✓';
    if (status === 'sent') return '✓';
    return '';
}

// ==================== АВТОРИЗАЦИЯ ====================
document.addEventListener('DOMContentLoaded', () => {
    checkSession();
    initEventListeners();
    if (typeof lucide !== 'undefined') lucide.createIcons();
});

function initEventListeners() {
    const fileInput = document.getElementById('file-in');
    if (fileInput) fileInput.addEventListener('change', handleFileUpload);
    
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

async function checkSession() {
    try {
        const res = await fetch('/api/profile');
        if (res.ok) {
            const data = await res.json();
            if (data.user) {
                loginSuccess(data.user);
                updateProfileUI(data);
            } else showAuthModal();
        } else showAuthModal();
    } catch(e) { showAuthModal(); }
}

function showAuthModal() {
    document.getElementById('auth-modal').classList.remove('hidden');
}

let isRegister = false;

function toggleAuth() {
    isRegister = !isRegister;
    document.getElementById('modal-title').innerText = isRegister ? 'Регистрация' : 'Вход';
    const link = document.querySelector('.link');
    if (link) link.innerText = isRegister ? 'Есть аккаунт? Войти' : 'Нет аккаунта?';
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
        } else showError('auth-err', data.error || 'Ошибка авторизации');
    } catch(e) { showError('auth-err', 'Ошибка соединения'); }
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
    startMessagePolling();
    checkAndShowAdmin();
    
    if (typeof lucide !== 'undefined') lucide.createIcons();
}
async function checkAndShowAdmin() {
    try {
        const res = await fetch('/api/profile');
        const data = await res.json();
        if (data.user && data.user.username === 'support') {
            document.getElementById('l-admin').style.display = 'flex';
        }
    } catch(e) {}
}
function showError(elementId, message) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerText = message;
        element.style.display = 'block';
        setTimeout(() => element.style.display = 'none', 3000);
    }
}

function showUploadNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `upload-notification ${type}`;
    notification.innerHTML = `<i data-lucide="${type === 'success' ? 'check-circle' : type === 'error' ? 'alert-circle' : 'loader'}"></i><span>${message}</span>`;
    document.body.appendChild(notification);
    if (typeof lucide !== 'undefined') lucide.createIcons();
    setTimeout(() => notification.remove(), 3000);
    return notification;
}

// ==================== ПОЛЛИНГ ====================
function startMessagePolling() {
    if (POLL_INTERVAL) clearInterval(POLL_INTERVAL);
    POLL_INTERVAL = setInterval(() => {
        if (ACTIVE_CHAT_ID) loadMessages();
        loadChats();
        loadUnreadCounts();
    }, 2000);
}

async function loadUnreadCounts() {
    try {
        const res = await fetch('/api/unread_counts');
        const data = await res.json();
        const total = data.total || 0;
        const chatsLink = document.getElementById('l-chats');
        if (chatsLink) {
            let badge = chatsLink.querySelector('.unread-badge');
            if (total > 0) {
                if (!badge) {
                    badge = document.createElement('span');
                    badge.className = 'unread-badge';
                    chatsLink.appendChild(badge);
                }
                badge.textContent = total > 99 ? '99+' : total;
            } else if (badge) badge.remove();
        }
    } catch(e) {}
}

// ==================== НАВИГАЦИЯ ====================
function nav(view) {
    document.querySelectorAll('section[id^="v-"]').forEach(el => el.classList.add('hidden'));
    document.querySelectorAll('nav a').forEach(el => el.classList.remove('active'));
    
    const viewElement = document.getElementById(`v-${view}`);
    const linkElement = document.getElementById(`l-${view}`);
    if (viewElement) viewElement.classList.remove('hidden');
    if (linkElement) linkElement.classList.add('active');
    
    // Закрываем мобильное меню
    closeMobileMenu();
    
    switch(view) {
        case 'media': loadContent(); break;
        case 'chats': loadChats(); break;
        case 'profile': loadProfile(); break;
        case 'home': setTimeout(checkSecurityStatus, 100); break;
    }
}

function toggleMobileMenu() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    const menuBtn = document.getElementById('mobile-menu-btn');
    
    if (sidebar) {
        sidebar.classList.toggle('mobile-open');
        if (overlay) overlay.classList.toggle('active');
        if (menuBtn) menuBtn.classList.toggle('hide');
    }
}

// ==================== ФАЙЛЫ ====================
async function handleFileUpload(e) {
    const file = e.target.files[0];
    if (!file) return;
    const formData = new FormData();
    formData.append('file', file);
    try {
        const res = await fetch('/api/upload', { method: 'POST', body: formData });
        if (res.ok) {
            loadContent();
            showUploadNotification(`✅ ${file.name} загружен`, 'success');
        } else showUploadNotification('❌ Ошибка загрузки', 'error');
    } catch(e) { showUploadNotification('❌ Ошибка соединения', 'error'); }
    e.target.value = '';
}

async function uploadEncryptedFile() {
    showUploadNotification('⏳ Функция временно отключена', 'info');
}

async function loadContent() {
    try {
        const res = await fetch('/api/content');
        if (!res.ok) throw new Error();
        const data = await res.json();
        
        const albumsGrid = document.getElementById('albums-grid');
        if (albumsGrid) {
            if (data.albums && data.albums.length > 0) {
                albumsGrid.innerHTML = data.albums.map(album => `
                    <div class="album-card">
                        <div class="album-cover" onclick="viewAlbum(${album.id})"><i data-lucide="folder"></i></div>
                        <div class="album-info">
                            <h4 onclick="viewAlbum(${album.id})" style="cursor:pointer;">${escapeHtml(album.name)}</h4>
                            <p>${formatMoscowTime(album.created_at)}</p>
                            <div class="album-buttons">
                                <button class="btn-xs" onclick="event.stopPropagation(); openAddToAlbumModal(${album.id})"><i data-lucide="plus"></i></button>
                                <button class="btn-xs" onclick="event.stopPropagation(); deleteAlbum(${album.id})"><i data-lucide="trash-2"></i></button>
                            </div>
                        </div>
                    </div>
                `).join('');
            } else albumsGrid.innerHTML = '<p style="text-align:center;padding:20px;">📁 Нет альбомов</p>';
        }
        
        const filesGrid = document.getElementById('files-grid');
        if (filesGrid) {
            if (data.files && data.files.length > 0) {
                filesGrid.innerHTML = data.files.map(file => {
                    const isImage = file.mime_type && file.mime_type.startsWith('image/');
                    const imageUrl = isImage ? `/uploads/${file.filename}` : '';
                    return `
                        <div class="file-card">
                            <div class="file-thumb clickable" ${isImage ? `onclick="openImageViewer('${imageUrl}', '${escapeHtml(file.original_name)}', ${file.id})"` : ''}>
                                ${isImage ? `<img src="${imageUrl}" loading="lazy">` : `<i data-lucide="file"></i>`}
                            </div>
                            <div class="album-info">
                                <h4 title="${escapeHtml(file.original_name)}">${escapeHtml(file.original_name.length > 25 ? file.original_name.substring(0,22)+'...' : file.original_name)}</h4>
                                <p>${formatMoscowTime(file.uploaded_at)} • ${formatFileSize(file.file_size || 0)}</p>
                                <div class="file-buttons">
                                    <button class="btn-xs" onclick="renameFile(${file.id})"><i data-lucide="edit-2"></i></button>
                                    <button class="btn-xs" onclick="downloadFile(${file.id})"><i data-lucide="download"></i></button>
                                    <button class="btn-xs" onclick="shareFile(${file.id})"><i data-lucide="share-2"></i></button>
                                    <button class="btn-xs" onclick="openAddFileToAlbumModal(${file.id})"><i data-lucide="folder-plus"></i></button>
                                    <button class="btn-xs" onclick="deleteFile(${file.id})"><i data-lucide="trash-2"></i></button>
                                </div>
                            </div>
                        </div>
                    `;
                }).join('');
            } else filesGrid.innerHTML = '<p style="text-align:center;padding:20px;">📄 Нет файлов</p>';
        }
        
        if (typeof lucide !== 'undefined') lucide.createIcons();
    } catch(e) { console.error(e); }
}

async function downloadFile(fileId) {
    try {
        showUploadNotification('🔄 Подготовка файла...', 'info');
        window.open(`/api/download_file/${fileId}`, '_blank');
        setTimeout(() => showUploadNotification('✅ Скачивание началось', 'success'), 1000);
    } catch(e) { showUploadNotification('❌ Ошибка', 'error'); }
}

async function renameFile(fileId) {
    const newName = prompt('Введите новое имя файла:');
    if (!newName) return;
    try {
        const res = await fetch(`/api/rename_file/${fileId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ new_name: newName })
        });
        if (res.ok) {
            showUploadNotification(`✅ Переименован`, 'success');
            loadContent();
        } else alert('Ошибка');
    } catch(e) { alert('Ошибка соединения'); }
}

async function deleteFile(fileId) {
    if (!confirm('Удалить файл?')) return;
    try {
        const res = await fetch(`/api/delete_file/${fileId}`, { method: 'DELETE' });
        if (res.ok) {
            showUploadNotification('✅ Файл удален', 'success');
            loadContent();
        } else alert('Ошибка');
    } catch(e) { alert('Ошибка соединения'); }
}

async function shareFile(fileId) {
    SELECTED_FILE_ID = fileId;
    
    try {
        const shareInfo = document.getElementById('share-file-info');
        if (shareInfo) shareInfo.innerHTML = '<div>Загрузка...</div>';
        
        const chatsRes = await fetch('/api/chats');
        const chats = chatsRes.ok ? await chatsRes.json() : [];
        const chatSelect = document.getElementById('share-chat-select');
        if (chatSelect) {
            chatSelect.innerHTML = '<option value="">Выберите чат...</option>';
            chats.forEach(chat => {
                if (chat.chat_type !== 'notifications') {
                    chatSelect.innerHTML += `<option value="${chat.id}">${escapeHtml(chat.other_user || 'Чат')}</option>`;
                }
            });
        }
        
        const shareResult = document.getElementById('share-result');
        if (shareResult) shareResult.classList.add('hidden');
        toggleModal('share-file-modal');
        
        const fileInfoRes = await fetch(`/api/file_info/${fileId}`);
        if (fileInfoRes.ok && shareInfo) {
            const file = await fileInfoRes.json();
            shareInfo.innerHTML = `
                <div class="file-info-share">
                    <i data-lucide="${file.mime_type?.startsWith('image/') ? 'image' : 'file'}"></i>
                    <div>
                        <strong>${escapeHtml(file.original_name)}</strong>
                        <p style="font-size: 12px; margin-top: 5px;">
                            📦 ${formatFileSize(file.file_size || 0)}
                        </p>
                    </div>
                </div>
            `;
        }
        
        if (typeof lucide !== 'undefined') lucide.createIcons();
    } catch(e) {
        console.error(e);
        alert('Ошибка загрузки');
    }
}

// ==================== ПРОСМОТР ИЗОБРАЖЕНИЙ ====================
function openImageViewer(imageUrl, filename, fileId = null) {
    if (fileId) currentViewFileId = fileId;
    openFileViewModal(fileId, imageUrl, filename, 0, 'image/jpeg');
}

// ==================== АЛЬБОМЫ ====================
async function viewAlbum(albumId) {
    try {
        const res = await fetch(`/api/album/${albumId}`);
        if (!res.ok) throw new Error();
        const data = await res.json();
        CURRENT_ALBUM_ID = albumId;
        
        const modal = document.getElementById('album-view-modal');
        modal.innerHTML = `
            <div class="modal-card">
                <div class="modal-header-row">
                    <h3><i data-lucide="folder"></i> ${escapeHtml(data.album.name)}</h3>
                    <div style="display:flex;gap:10px;">
                        <button class="btn-xs" onclick="openAddToAlbumModal(${albumId})"><i data-lucide="plus"></i> Добавить</button>
                        <button class="btn-xs" onclick="deleteAlbum(${albumId})"><i data-lucide="trash-2"></i></button>
                        <i data-lucide="x" class="close-icon" onclick="toggleModal('album-view-modal')"></i>
                    </div>
                </div>
                <div class="files-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:15px;max-height:400px;overflow-y:auto;">
                    ${data.files.length > 0 ? data.files.map(file => {
                        const isImage = file.mime_type && file.mime_type.startsWith('image/');
                        const imageUrl = isImage ? `/uploads/${file.filename}` : '';
                        return `
                            <div class="file-select-item">
                                <div class="file-select-thumb">
                                    ${isImage ? `<img src="${imageUrl}" onclick="openImageViewer('${imageUrl}', '${escapeHtml(file.original_name)}', ${file.id})">` : `<div style="height:100px;display:flex;align-items:center;justify-content:center;"><i data-lucide="file"></i></div>`}
                                </div>
                                <div class="file-select-name">${escapeHtml(file.original_name)}</div>
                                <div style="display:flex;gap:5px;justify-content:center;margin-top:5px;">
                                    <button class="btn-xs" onclick="downloadFile(${file.id})"><i data-lucide="download"></i></button>
                                    <button class="btn-xs" onclick="removeFileFromAlbum(${albumId}, ${file.id})"><i data-lucide="x"></i></button>
                                </div>
                            </div>
                        `;
                    }).join('') : '<p style="text-align:center;">📭 Пусто</p>'}
                </div>
                <button class="btn-secondary" onclick="toggleModal('album-view-modal'); loadContent();"><i data-lucide="arrow-left"></i> Назад</button>
            </div>
        `;
        modal.classList.remove('hidden');
        if (typeof lucide !== 'undefined') lucide.createIcons();
    } catch(e) { alert('Ошибка'); }
}

async function createAlbum() {
    const name = document.getElementById('album-name').value.trim();
    if (!name) { alert('Введите название'); return; }
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
        } else alert('Ошибка');
    } catch(e) { alert('Ошибка соединения'); }
}

async function deleteAlbum(albumId) {
    if (!confirm('Удалить альбом? Файлы останутся.')) return;
    try {
        const res = await fetch(`/api/album/${albumId}/delete`, { method: 'DELETE' });
        if (res.ok) {
            showUploadNotification('✅ Альбом удален', 'success');
            toggleModal('album-view-modal');
            loadContent();
        } else alert('Ошибка');
    } catch(e) { alert('Ошибка соединения'); }
}

async function removeFileFromAlbum(albumId, fileId) {
    try {
        const res = await fetch(`/api/album/${albumId}/remove_file`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_id: fileId })
        });
        if (res.ok) {
            showUploadNotification('✅ Удалено из альбома', 'success');
            viewAlbum(albumId);
            loadContent();
        } else alert('Ошибка');
    } catch(e) { alert('Ошибка соединения'); }
}

function openAddFileToAlbumModal(fileId) {
    SELECTED_FILE_ID = fileId;
    loadAlbumsForSelection();
    toggleModal('add-to-album-modal');
}

async function loadAlbumsForSelection() {
    try {
        const res = await fetch('/api/albums');
        const albums = await res.json();
        const container = document.getElementById('albums-select');
        if (albums.length > 0) {
            container.innerHTML = albums.map(album => `
                <div class="album-select-item" onclick="selectAlbumForFile(${album.id})" id="album-${album.id}">
                    <i data-lucide="folder"></i> <span>${escapeHtml(album.name)}</span>
                    <i data-lucide="check" class="selected-check hidden"></i>
                </div>
            `).join('');
            document.getElementById('album-actions').classList.remove('hidden');
        } else {
            container.innerHTML = '<p>📁 Нет альбомов</p>';
            document.getElementById('album-actions').classList.add('hidden');
        }
        if (typeof lucide !== 'undefined') lucide.createIcons();
    } catch(e) { console.error(e); }
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
    if (!selectedAlbumId || !SELECTED_FILE_ID) { alert('Выберите альбом'); return; }
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
        } else alert('Ошибка');
    } catch(e) { alert('Ошибка соединения'); }
}

function openAddToAlbumModal(albumId) {
    CURRENT_ALBUM_ID = albumId;
    loadFilesForSelection();
    toggleModal('select-files-modal');
}

async function loadFilesForSelection() {
    try {
        const res = await fetch('/api/files');
        const files = await res.json();
        const container = document.getElementById('files-select');
        SELECTED_FILES = [];
        if (files.length > 0) {
            container.innerHTML = `
                <div class="files-select-grid">
                    ${files.map(file => {
                        const isImage = file.mime_type && file.mime_type.startsWith('image/');
                        const imageUrl = isImage ? `/uploads/${file.filename}` : '';
                        return `
                            <div class="file-select-item" onclick="toggleFileSelection(${file.id})" id="file-${file.id}">
                                <div class="file-select-thumb">
                                    ${isImage ? `<img src="${imageUrl}">` : `<div style="height:100px;display:flex;align-items:center;justify-content:center;"><i data-lucide="file"></i></div>`}
                                </div>
                                <div class="file-select-name">${escapeHtml(file.original_name)}</div>
                            </div>
                        `;
                    }).join('')}
                </div>
            `;
            document.getElementById('files-actions').classList.remove('hidden');
        } else {
            container.innerHTML = '<p>📄 Нет файлов</p>';
            document.getElementById('files-actions').classList.add('hidden');
        }
        if (typeof lucide !== 'undefined') setTimeout(() => lucide.createIcons(), 100);
    } catch(e) { console.error(e); }
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
    if (typeof lucide !== 'undefined') lucide.createIcons();
}

async function addSelectedFilesToAlbum() {
    if (!CURRENT_ALBUM_ID || SELECTED_FILES.length === 0) { alert('Выберите файлы'); return; }
    try {
        const res = await fetch(`/api/album/${CURRENT_ALBUM_ID}/add_files`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_ids: SELECTED_FILES })
        });
        if (res.ok) {
            showUploadNotification(`✅ Добавлено ${SELECTED_FILES.length} файлов`, 'success');
            toggleModal('select-files-modal');
            loadContent();
            if (CURRENT_ALBUM_ID) viewAlbum(CURRENT_ALBUM_ID);
        } else alert('Ошибка');
    } catch(e) { alert('Ошибка соединения'); }
}

// ==================== ЧАТЫ ====================
async function loadChats() {
    try {
        const res = await fetch('/api/chats');
        const chats = await res.json();
        const clItems = document.getElementById('cl-items');
        if (!clItems) return;
        
        if (chats.length > 0) {
            clItems.innerHTML = '';
            
            for (const chat of chats) {
                const chatName = chat.other_user === 'support' ? 'Поддержка MOC' : (chat.other_user || 'Чат');
                const lastMessage = chat.last_message || 'Нет сообщений';
                const unread = chat.unread_count || 0;
                const isActive = ACTIVE_CHAT_ID === chat.id;
                
                const chatDiv = document.createElement('div');
                chatDiv.className = `chat-item ${isActive ? 'active' : ''}`;
                chatDiv.setAttribute('data-chat-id', chat.id);
                chatDiv.onclick = () => openChat(chat.id, chat.other_user || '');
                
                // Аватар
                const avatarDiv = document.createElement('div');
                avatarDiv.className = 'chat-avatar';
                const defaultText = (chat.other_user || 'U').substring(0,2).toUpperCase();
                avatarDiv.innerText = defaultText;
                avatarDiv.style.backgroundColor = '#7C3AED';
                avatarDiv.style.backgroundSize = 'cover';
                avatarDiv.style.backgroundPosition = 'center';
                avatarDiv.style.display = 'flex';
                avatarDiv.style.alignItems = 'center';
                avatarDiv.style.justifyContent = 'center';

                // Загружаем аватарку - используем ID чата
                if (chat.other_user_id) {
                    (function(avatar, userId) {
                        fetch(`/api/get_avatar/${userId}`)
                            .then(res => {
                                if (res.ok) return res.blob();
                                throw new Error();
                            })
                            .then(blob => {
                                const url = URL.createObjectURL(blob);
                                avatar.style.backgroundImage = `url(${url})`;
                                avatar.style.backgroundSize = 'cover';
                                avatar.style.backgroundPosition = 'center';
                                avatar.innerText = '';
                            })
                            .catch(() => {});
                    })(avatarDiv, chat.other_user_id);
                }

                
                const infoDiv = document.createElement('div');
                infoDiv.className = 'chat-info';
                infoDiv.innerHTML = `
                    <div class="chat-name" style="${unread > 0 && !isActive ? 'font-weight:bold' : ''}">${escapeHtml(chatName)}</div>
                    <div class="chat-preview" style="${unread > 0 && !isActive ? 'font-weight:500' : ''}">${escapeHtml(lastMessage)}</div>
                    ${unread > 0 && !isActive ? `<span class="chat-unread-badge">${unread > 99 ? '99+' : unread}</span>` : ''}
                `;
                
                chatDiv.appendChild(avatarDiv);
                chatDiv.appendChild(infoDiv);
                clItems.appendChild(chatDiv);
            }
        } else {
            clItems.innerHTML = '<p style="text-align:center;padding:20px;">💬 Нет чатов</p>';
        }
        
        if (typeof lucide !== 'undefined') lucide.createIcons();
    } catch(e) { 
        console.error('Load chats error:', e);
    }
}

let lastScrollPosition = 0;


function initChatScroll() {
    const container = document.getElementById('chat-messages-container');
    if (!container) return;
    container.addEventListener('scroll', () => {
        const distanceFromBottom = container.scrollHeight - container.scrollTop - container.clientHeight;
        shouldAutoScroll = distanceFromBottom < 100;
        lastScrollPosition = container.scrollTop;
    });
}

async function openChat(chatId, otherUserName) {
    ACTIVE_CHAT_ID = chatId;
    
    if (window.innerWidth <= 768) showChatBox();
    
    const chatEmpty = document.getElementById('chat-empty');
    const chatInterface = document.getElementById('chat-interface');
    if (chatEmpty) chatEmpty.classList.add('hidden');
    if (chatInterface) {
        chatInterface.classList.remove('hidden');
        createChatInterface(otherUserName);
    }
    
    document.querySelectorAll('.chat-item').forEach(item => item.classList.remove('active'));
    const activeItem = document.querySelector(`.chat-item[data-chat-id="${chatId}"]`);
    if (activeItem) activeItem.classList.add('active');
    
    shouldAutoScroll = true;
    lastScrollPosition = 0;
    
    await loadMessages();
    await markMessagesRead(chatId);
    await loadChats();
    
    setTimeout(() => {
        const msgInput = document.getElementById('msg-in');
        if (msgInput) msgInput.focus();
    }, 100);
}

function createChatInterface(otherUserName) {
    const chatInterface = document.getElementById('chat-interface');
    if (!chatInterface) return;
    const chatName = otherUserName === 'support' ? 'Поддержка MOC' : (otherUserName || 'Чат');
    const isMobile = window.innerWidth <= 768;
    const backButton = isMobile ? `<button class="chat-back-btn" onclick="showChatList()"><i data-lucide="arrow-left"></i> Чаты</button>` : '';
    
    chatInterface.innerHTML = `
        <div class="cb-head">
            ${backButton}
            <span id="cb-name">${escapeHtml(chatName)}</span>
            <button class="btn-xs" onclick="loadMessages()"><i data-lucide="refresh-cw"></i></button>
        </div>
        <div class="chat-messages-container" id="chat-messages-container">
            <div class="messages-wrapper" id="cb-msgs-content"></div>
        </div>
        <div class="cb-input-fixed">
            <button class="btn-file" onclick="document.getElementById('chat-file-input').click()">
                <i data-lucide="paperclip"></i>
            </button>
            <input type="text" id="msg-in" placeholder="Сообщение... (Enter для отправки)">
            <button onclick="sendMsg()"><i data-lucide="send"></i></button>
            <input type="file" id="chat-file-input" style="display:none" accept="image/*,video/*,application/pdf">
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
    
    const chatFileInput = document.getElementById('chat-file-input');
    if (chatFileInput) {
        chatFileInput.removeEventListener('change', sendChatFile);
        chatFileInput.addEventListener('change', sendChatFile);
    }
    
    if (typeof lucide !== 'undefined') lucide.createIcons();
    initChatScroll();
}

async function loadMessages() {
    if (!ACTIVE_CHAT_ID) return;
    
    try {
        const res = await fetch(`/api/messages/${ACTIVE_CHAT_ID}`);
        if (!res.ok) throw new Error();
        const messages = await res.json();
        const wrapper = document.getElementById('cb-msgs-content');
        if (!wrapper) return;
        
        const container = document.getElementById('chat-messages-container');
        let wasAtBottom = false;
        let oldScrollHeight = 0;
        
        if (container) {
            oldScrollHeight = container.scrollHeight;
            const distanceFromBottom = container.scrollHeight - container.scrollTop - container.clientHeight;
            wasAtBottom = distanceFromBottom < 100;
            // Временно отключаем автоскролл если пользователь крутил
            if (!wasAtBottom && !shouldAutoScroll) {
                // сохраняем позицию
            }
        }
        
        wrapper.innerHTML = '';
        
        if (messages.length === 0) {
            wrapper.innerHTML = `<div class="message notification"><div class="notification-content"><i data-lucide="message-square"></i><div>💬 Нет сообщений</div></div></div>`;
        } else {
            for (const msg of messages) {
                const isMyMessage = parseInt(msg.sender_id) === parseInt(CURRENT_USER?.user_id);
                const time = formatMoscowTimeShort(msg.timestamp);
                const statusIcon = isMyMessage ? getMessageStatusIcon(msg.status) : '';
                const statusClass = msg.status === 'read' ? 'status-read' : (msg.status === 'delivered' ? 'status-delivered' : '');
                
                const messageDiv = document.createElement('div');
                messageDiv.className = `message ${isMyMessage ? 'my' : 'other'}`;
                
                if (msg.file_id) {
                    let fileUrl = '';
                    let fileName = 'Файл';
                    let fileSize = 0;
                    let fileType = '';
                    
                    if (msg.file_filename) {
                        fileUrl = `/uploads/${msg.file_filename}`;
                        fileName = msg.file_original_name || 'Файл';
                        fileSize = msg.file_size || 0;
                        fileType = msg.mime_type || '';
                    } else {
                        try {
                            const fileRes = await fetch(`/api/file_info/${msg.file_id}`);
                            if (fileRes.ok) {
                                const fileData = await fileRes.json();
                                fileUrl = `/uploads/${fileData.filename}`;
                                fileName = fileData.original_name || 'Файл';
                                fileSize = fileData.file_size || 0;
                                fileType = fileData.mime_type || '';
                            }
                        } catch(e) {}
                    }
                    
                    const isImage = fileType.startsWith('image/') || fileUrl.match(/\.(jpg|jpeg|png|gif|webp|bmp|svg)$/i);
                    
                    if (isImage && fileUrl) {
                        const previewHtml = `
                            <div class="file-preview" onclick="openFileViewModal(${msg.file_id}, '${fileUrl}', '${escapeHtml(fileName)}', ${fileSize}, '${fileType}')">
                                <img src="${fileUrl}" style="max-width: 200px; max-height: 150px; object-fit: cover; border-radius: 12px; cursor: pointer;">
                            </div>
                        `;
                        messageDiv.innerHTML = `
                            ${previewHtml}
                            <div class="message-content">${escapeHtml(msg.text || '')}</div>
                            <div class="message-time">${time} ${statusIcon ? `<span class="message-status ${statusClass}">${statusIcon}</span>` : ''}</div>
                        `;
                    } else {
                        const fileHtml = `
                            <div class="file-info" onclick="downloadFile(${msg.file_id})" style="cursor: pointer; display: flex; align-items: center; gap: 10px; padding: 8px 12px; background: var(--bg-tertiary); border-radius: 12px; margin-bottom: 6px;">
                                <i data-lucide="file" width="20" height="20"></i>
                                <div style="flex:1">
                                    <strong>${escapeHtml(fileName)}</strong>
                                    <br><small style="color: var(--text-tertiary);">${formatFileSize(fileSize)}</small>
                                </div>
                                <i data-lucide="download" width="16" height="16"></i>
                            </div>
                        `;
                        messageDiv.innerHTML = `
                            ${fileHtml}
                            <div class="message-content">${escapeHtml(msg.text || '')}</div>
                            <div class="message-time">${time} ${statusIcon ? `<span class="message-status ${statusClass}">${statusIcon}</span>` : ''}</div>
                        `;
                    }
                } else {
                    messageDiv.innerHTML = `
                        <div class="message-content">${escapeHtml(msg.text || '')}</div>
                        <div class="message-time">${time} ${statusIcon ? `<span class="message-status ${statusClass}">${statusIcon}</span>` : ''}</div>
                    `;
                }
                
                if (isMyMessage) {
                    const deleteBtn = document.createElement('button');
                    deleteBtn.className = 'delete-message-btn';
                    deleteBtn.innerHTML = '<i data-lucide="trash-2" width="14" height="14"></i>';
                    deleteBtn.onclick = (e) => {
                        e.stopPropagation();
                        confirmDeleteMessageModal(msg.id, ACTIVE_CHAT_ID);
                    };
                    messageDiv.appendChild(deleteBtn);
                }
                
                wrapper.appendChild(messageDiv);
            }
        }
        
        if (container) {
            setTimeout(() => {
                if (wasAtBottom && shouldAutoScroll) {
                    smoothScrollToBottom();
                } else if (!shouldAutoScroll && lastScrollPosition > 0) {
                    const newScrollHeight = container.scrollHeight;
                    const delta = newScrollHeight - oldScrollHeight;
                    container.scrollTop = lastScrollPosition + delta;
                }
            }, 50);
        }
        
        if (typeof lucide !== 'undefined') lucide.createIcons();
    } catch(e) { 
        console.error('Load messages error:', e);
    }
}

async function sendMsg() {
    if (IS_SENDING) return;
    IS_SENDING = true;
    
    const input = document.getElementById('msg-in');
    if (!input) { IS_SENDING = false; return; }
    
    const text = input.value.trim();
    if (!text || !ACTIVE_CHAT_ID) { IS_SENDING = false; return; }
    
    const tempId = 'temp_' + Date.now();
    addTempMessage(text, tempId);
    input.value = '';
    
    try {
        const res = await fetch('/api/send_message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: ACTIVE_CHAT_ID, text: text })
        });
        
        if (res.ok) {
            const tempMsg = document.getElementById(tempId);
            if (tempMsg) tempMsg.remove();
            await loadMessages();
            await loadChats();
        } else {
            markTempMessageError(tempId);
        }
    } catch(e) {
        markTempMessageError(tempId);
    } finally {
        IS_SENDING = false;
        setTimeout(() => {
            const msgInput = document.getElementById('msg-in');
            if (msgInput) msgInput.focus();
        }, 50);
    }
}

function addTempMessage(text, tempId) {
    const wrapper = document.getElementById('cb-msgs-content');
    if (!wrapper) return;
    
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message my temp';
    messageDiv.id = tempId;
    messageDiv.innerHTML = `
        <div class="message-content">${escapeHtml(text)}</div>
        <div class="message-time">⏳ Отправляется... <span class="message-status">✓</span></div>
    `;
    wrapper.appendChild(messageDiv);
    
    // Плавный скролл вниз
    smoothScrollToBottom();
}

function markTempMessageError(tempId) {
    const tempMsg = document.getElementById(tempId);
    if (tempMsg) {
        const timeDiv = tempMsg.querySelector('.message-time');
        if (timeDiv) timeDiv.innerHTML = '❌ Ошибка';
    }
}

async function sendChatFile(e) {
    const file = e.target.files[0];
    if (!file || !ACTIVE_CHAT_ID) {
        if (e.target) e.target.value = '';
        return;
    }
    
    const tempId = 'temp_' + Date.now();
    const wrapper = document.getElementById('cb-msgs-content');
    
    if (wrapper) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message my temp';
        messageDiv.id = tempId;
        messageDiv.innerHTML = `<div class="message-content">📎 ${escapeHtml(file.name)}</div><div class="message-time">⏳ Отправляется...</div>`;
        wrapper.appendChild(messageDiv);
        const container = document.getElementById('chat-messages-container');
        if (container) container.scrollTop = container.scrollHeight;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const uploadRes = await fetch('/api/upload', { method: 'POST', body: formData });
        const uploadData = await uploadRes.json();
        
        if (uploadRes.ok) {
            const res = await fetch('/api/send_message', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ chat_id: ACTIVE_CHAT_ID, text: `📎 ${file.name}`, file_id: uploadData.file_id })
            });
            
            if (res.ok) {
                const tempMsg = document.getElementById(tempId);
                if (tempMsg) tempMsg.remove();
                await loadMessages();
                await loadChats();
                loadContent();
            } else {
                const tempMsg = document.getElementById(tempId);
                if (tempMsg) tempMsg.querySelector('.message-time').innerHTML = '❌ Ошибка';
            }
        } else {
            const tempMsg = document.getElementById(tempId);
            if (tempMsg) tempMsg.querySelector('.message-time').innerHTML = '❌ Ошибка';
        }
    } catch(e) {
        const tempMsg = document.getElementById(tempId);
        if (tempMsg) tempMsg.querySelector('.message-time').innerHTML = '❌ Ошибка';
    }
    
    e.target.value = '';
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
            if (data.id) openChat(data.id, username);
        } else alert(data.error || 'Ошибка');
    } catch(e) { alert('Ошибка соединения'); }
}

async function markMessagesRead(chatId) {
    try {
        await fetch('/api/mark_read', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: chatId })
        });
    } catch(e) { console.error(e); }
}

function showChatList() {
    const chatList = document.querySelector('.chat-list');
    const chatBox = document.querySelector('.chat-box');
    
    if (chatList) chatList.classList.remove('hide-on-mobile');
    if (chatBox) chatBox.classList.remove('show-on-mobile');
    
    // Обновляем список чатов при возврате
    loadChats();
}

function showChatBox() {
    const chatList = document.querySelector('.chat-list');
    const chatBox = document.querySelector('.chat-box');
    
    if (chatList) chatList.classList.add('hide-on-mobile');
    if (chatBox) chatBox.classList.add('show-on-mobile');
}

// ==================== ПРОФИЛЬ ====================
async function loadProfile() {
    try {
        const res = await fetch('/api/profile');
        if (!res.ok) throw new Error();
        const data = await res.json();
        updateProfileUI(data);
    } catch(e) { console.error(e); }
}
// Загрузка возможных друзей
async function loadSuggestedFriends() {
    try {
        const res = await fetch('/api/suggested_friends');
        const suggested = await res.json();
        const container = document.getElementById('suggested-friends-list');
        if (!container) return;
        
        if (suggested.length > 0) {
            document.getElementById('suggested-friends-section').style.display = 'block';
            container.innerHTML = '';
            
            for (const friend of suggested) {
                const friendDiv = document.createElement('div');
                friendDiv.className = 'friend-item';
                
                // Аватар
                const avatarDiv = document.createElement('div');
                avatarDiv.className = 'friend-avatar';
                avatarDiv.innerText = friend.username.substring(0,2).toUpperCase();
                avatarDiv.style.backgroundColor = '#7C3AED';
                avatarDiv.style.backgroundSize = 'cover';
                avatarDiv.style.backgroundPosition = 'center';
                
                // Загружаем аватарку
                try {
                    const avatarRes = await fetch(`/api/get_avatar/${friend.id}`);
                    if (avatarRes.ok) {
                        const blob = await avatarRes.blob();
                        const url = URL.createObjectURL(blob);
                        avatarDiv.style.backgroundImage = `url(${url})`;
                        avatarDiv.style.backgroundSize = 'cover';
                        avatarDiv.style.backgroundPosition = 'center';
                        avatarDiv.innerText = '';
                    }
                } catch(e) {}
                
                // Информация
                const infoDiv = document.createElement('div');
                infoDiv.className = 'friend-info';
                infoDiv.innerHTML = `
                    <div class="friend-name">${escapeHtml(friend.username)}</div>
                    <div class="friend-handle">@${escapeHtml(friend.handle || friend.username)}</div>
                `;
                
                // Кнопка добавления
                const addBtn = document.createElement('button');
                addBtn.className = 'btn-xs btn-success';
                addBtn.innerHTML = '<i data-lucide="user-plus"></i> Добавить';
                addBtn.onclick = () => addFriendByName(friend.username);
                
                friendDiv.appendChild(avatarDiv);
                friendDiv.appendChild(infoDiv);
                friendDiv.appendChild(addBtn);
                container.appendChild(friendDiv);
            }
        } else {
            document.getElementById('suggested-friends-section').style.display = 'none';
        }
    } catch(e) { console.error(e); }
}

async function addFriend() {
    const username = prompt('Введите имя пользователя:');
    if (!username) return;
    
    try {
        const res = await fetch('/api/send_friend_request', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: username.trim() })
        });
        const data = await res.json();
        if (res.ok) {
            showUploadNotification(`✅ Запрос отправлен ${username}`, 'success');
            loadProfile();
        } else {
            alert(data.error || 'Пользователь не найден');
        }
    } catch(e) {
        alert('Ошибка соединения');
    }
}

loadSuggestedFriends();
async function updateProfileUI(data) {
    if (!data.user) return;
    
    document.getElementById('p-username').innerText = data.user.username;
    document.getElementById('p-handle').innerText = `@${data.user.handle || data.user.username}`;
    document.getElementById('p-bio').innerText = data.user.bio || 'Нет информации';
    
    // Загрузка аватара текущего пользователя
    const avatarDiv = document.getElementById('p-avatar');
    const miniAvatar = document.getElementById('mini-avatar');
    
    async function loadCurrentUserAvatar() {
        if (!CURRENT_USER) return;
        try {
            const res = await fetch(`/api/get_avatar/${CURRENT_USER.user_id}`);
            if (res.ok) {
                const blob = await res.blob();
                const url = URL.createObjectURL(blob);
                if (avatarDiv) {
                    avatarDiv.style.backgroundImage = `url(${url})`;
                    avatarDiv.style.backgroundSize = 'cover';
                    avatarDiv.style.backgroundPosition = 'center';
                    avatarDiv.innerText = '';
                }
                if (miniAvatar) {
                    miniAvatar.style.backgroundImage = `url(${url})`;
                    miniAvatar.style.backgroundSize = 'cover';
                    miniAvatar.style.backgroundPosition = 'center';
                    miniAvatar.innerText = '';
                }
            } else {
                const initials = (data.user.username || 'U').substring(0,2).toUpperCase();
                if (avatarDiv) {
                    avatarDiv.style.backgroundImage = '';
                    avatarDiv.style.backgroundColor = '#7C3AED';
                    avatarDiv.innerText = initials;
                }
                if (miniAvatar) {
                    miniAvatar.style.backgroundImage = '';
                    miniAvatar.style.backgroundColor = '#7C3AED';
                    miniAvatar.innerText = initials;
                }
            }
        } catch(e) {
            const initials = (data.user.username || 'U').substring(0,2).toUpperCase();
            if (avatarDiv) {
                avatarDiv.style.backgroundImage = '';
                avatarDiv.style.backgroundColor = '#7C3AED';
                avatarDiv.innerText = initials;
            }
            if (miniAvatar) {
                miniAvatar.style.backgroundImage = '';
                miniAvatar.style.backgroundColor = '#7C3AED';
                miniAvatar.innerText = initials;
            }
        }
    }
    loadCurrentUserAvatar();
    
    // Статистика
    const stats = data.stats || {};
    document.getElementById('s-photos').innerText = stats.photos || 0;
    document.getElementById('s-albums').innerText = stats.albums || 0;
    document.getElementById('s-friends').innerText = stats.friends || 0;
    document.getElementById('s-chats').innerText = stats.chats || 0;
    
    // Бейдж на заявки в друзья
    const friendRequestsCount = data.friend_requests?.length || 0;
    const profileLink = document.getElementById('l-profile');
    if (profileLink) {
        let badge = profileLink.querySelector('.requests-badge');
        if (friendRequestsCount > 0) {
            if (!badge) {
                badge = document.createElement('span');
                badge.className = 'requests-badge';
                profileLink.appendChild(badge);
            }
            badge.textContent = friendRequestsCount > 99 ? '99+' : friendRequestsCount;
        } else if (badge) {
            badge.remove();
        }
    }
    
    // Запросы в друзья
    const friendRequestsSec = document.getElementById('friend-requests-sec');
    const friendRequestsList = document.getElementById('friend-requests-list');
    if (data.friend_requests && data.friend_requests.length > 0) {
        friendRequestsSec.style.display = 'block';
        friendRequestsList.innerHTML = '';
        
        for (const request of data.friend_requests) {
            const reqDiv = document.createElement('div');
            reqDiv.className = 'friend-request-item';
            
            const avatarDivReq = document.createElement('div');
            avatarDivReq.className = 'friend-avatar';
            avatarDivReq.innerText = request.username.substring(0,2).toUpperCase();
            avatarDivReq.style.backgroundColor = '#7C3AED';
            avatarDivReq.style.backgroundSize = 'cover';
            avatarDivReq.style.backgroundPosition = 'center';
            
            try {
                const avatarRes = await fetch(`/api/get_avatar/${request.from_user_id}`);
                if (avatarRes.ok) {
                    const blob = await avatarRes.blob();
                    const url = URL.createObjectURL(blob);
                    avatarDivReq.style.backgroundImage = `url(${url})`;
                    avatarDivReq.style.backgroundSize = 'cover';
                    avatarDivReq.style.backgroundPosition = 'center';
                    avatarDivReq.innerText = '';
                }
            } catch(e) {}
            
            const infoDiv = document.createElement('div');
            infoDiv.className = 'friend-info';
            infoDiv.innerHTML = `<div class="friend-name">${escapeHtml(request.username)}</div>`;
            
            const actionsDiv = document.createElement('div');
            actionsDiv.className = 'friend-request-actions';
            actionsDiv.innerHTML = `
                <button class="btn-xs btn-success" onclick="handleFriendRequest(${request.id}, true)"><i data-lucide="check"></i> Принять</button>
                <button class="btn-xs btn-danger" onclick="handleFriendRequest(${request.id}, false)"><i data-lucide="x"></i> Отклонить</button>
            `;
            
            reqDiv.appendChild(avatarDivReq);
            reqDiv.appendChild(infoDiv);
            reqDiv.appendChild(actionsDiv);
            friendRequestsList.appendChild(reqDiv);
        }
    } else {
        friendRequestsSec.style.display = 'none';
    }
    
    // Список друзей
    const friendsList = document.getElementById('friends-list');
    if (friendsList) {
        if (data.friends_list && data.friends_list.length > 0) {
            friendsList.innerHTML = '';
            
            for (const friend of data.friends_list) {
                const friendDiv = document.createElement('div');
                friendDiv.className = 'friend-item';
                
                const avatarFriend = document.createElement('div');
                avatarFriend.className = 'friend-avatar';
                avatarFriend.innerText = friend.username.substring(0,2).toUpperCase();
                avatarFriend.style.backgroundColor = '#7C3AED';
                avatarFriend.style.backgroundSize = 'cover';
                avatarFriend.style.backgroundPosition = 'center';
                
                try {
                    const avatarRes = await fetch(`/api/get_avatar/${friend.id}`);
                    if (avatarRes.ok) {
                        const blob = await avatarRes.blob();
                        const url = URL.createObjectURL(blob);
                        avatarFriend.style.backgroundImage = `url(${url})`;
                        avatarFriend.style.backgroundSize = 'cover';
                        avatarFriend.style.backgroundPosition = 'center';
                        avatarFriend.innerText = '';
                    }
                } catch(e) {}
                
                const infoDiv = document.createElement('div');
                infoDiv.className = 'friend-info';
                infoDiv.innerHTML = `
                    <div class="friend-name">${escapeHtml(friend.username)}</div>
                    <div class="friend-handle">@${escapeHtml(friend.handle || friend.username)}</div>
                `;
                
                const removeBtn = document.createElement('button');
                removeBtn.className = 'btn-xs btn-danger';
                removeBtn.innerHTML = '<i data-lucide="user-minus"></i>';
                removeBtn.onclick = () => removeFriend(friend.id);
                
                friendDiv.appendChild(avatarFriend);
                friendDiv.appendChild(infoDiv);
                friendDiv.appendChild(removeBtn);
                friendsList.appendChild(friendDiv);
            }
        } else {
            friendsList.innerHTML = '<p style="text-align:center;padding:20px;">👥 Нет друзей</p>';
        }
    }
    
    // Мини-профиль
    document.getElementById('mini-name').innerText = data.user.username;
    
    // Загружаем возможных друзей
    loadSuggestedFriends();
    
    if (typeof lucide !== 'undefined') lucide.createIcons();
}

function openEditProfile() {
    document.getElementById('edit-username').value = CURRENT_USER?.username || '';
    document.getElementById('edit-handle').value = document.getElementById('p-handle').innerText.replace('@', '');
    document.getElementById('edit-bio').value = document.getElementById('p-bio').innerText;
    toggleModal('edit-profile-modal');
}

async function saveProfile() {
    const username = document.getElementById('edit-username').value.trim();
    const handle = document.getElementById('edit-handle').value.trim();
    const bio = document.getElementById('edit-bio').value.trim();
    
    if (!username) {
        alert('Имя пользователя не может быть пустым');
        return;
    }
    
    try {
        const res = await fetch('/api/update_profile', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, handle, bio })
        });
        const data = await res.json();
        if (res.ok) {
            toggleModal('edit-profile-modal');
            if (username !== CURRENT_USER?.username) {
                CURRENT_USER.username = username;
                document.getElementById('mini-name').innerText = username;
            }
            loadProfile();
            showUploadNotification('✅ Профиль обновлен', 'success');
        } else alert(data.error || 'Ошибка');
    } catch(e) { alert('Ошибка соединения'); }
}

function openAvatarModal() {
    toggleModal('avatar-modal');
}

async function uploadAvatar() {
    const input = document.getElementById('avatar-input');
    if (!input || !input.files[0]) {
        alert('Выберите файл');
        return;
    }
    const file = input.files[0];
    const formData = new FormData();
    formData.append('avatar', file);
    try {
        const res = await fetch('/api/upload_avatar', { method: 'POST', body: formData });
        if (res.ok) {
            showUploadNotification('✅ Аватар обновлен', 'success');
            toggleModal('avatar-modal');
            loadProfile();
        } else alert('Ошибка');
    } catch(e) { alert('Ошибка соединения'); }
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
        } else alert('Ошибка');
    } catch(e) { alert('Ошибка соединения'); }
}

async function addFriend() {
    const username = prompt('Введите имя пользователя:');
    if (!username) return;
    try {
        const res = await fetch('/api/send_friend_request', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        const data = await res.json();
        if (res.ok) {
            showUploadNotification('✅ Запрос отправлен', 'success');
            loadProfile();
        } else alert(data.error || 'Ошибка');
    } catch(e) { alert('Ошибка соединения'); }
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
            showUploadNotification('✅ Удален из друзей', 'success');
            loadProfile();
        } else alert('Ошибка');
    } catch(e) { alert('Ошибка соединения'); }
}

// ==================== МОДАЛЬНЫЕ ОКНА ====================
function toggleModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.classList.toggle('hidden');
}

function openChatSelectModal(fileId) {
    selectedFileForChat = fileId;
    const container = document.getElementById('chat-select-list');
    if (!container) return;
    container.innerHTML = '<div style="text-align:center; padding:20px;">Загрузка...</div>';
    toggleModal('chat-select-modal');
    
    fetch('/api/chats')
        .then(res => res.json())
        .then(chats => {
            const regularChats = chats.filter(c => c.chat_type !== 'notifications');
            if (regularChats.length === 0) {
                container.innerHTML = '<div style="text-align:center; padding:20px;">Нет чатов. Создайте чат!</div>';
                return;
            }
            container.innerHTML = regularChats.map(chat => `
                <div class="chat-select-item" onclick="sendFileToSelectedChat(${chat.id})">
                    <div class="chat-select-avatar">${(chat.other_user || 'U').substring(0,2).toUpperCase()}</div>
                    <div><strong>${escapeHtml(chat.other_user || 'Чат')}</strong></div>
                </div>
            `).join('');
            if (typeof lucide !== 'undefined') lucide.createIcons();
        })
        .catch(() => {
            container.innerHTML = '<div style="text-align:center; padding:20px;">Ошибка загрузки</div>';
        });
}

async function sendFileToSelectedChat(chatId) {
    if (!selectedFileForChat) return;
    try {
        const res = await fetch('/api/share_file', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_id: selectedFileForChat, chat_id: chatId })
        });
        if (res.ok) {
            showUploadNotification('✅ Файл отправлен в чат', 'success');
            toggleModal('chat-select-modal');
            if (ACTIVE_CHAT_ID === chatId) await loadMessages();
            loadChats();
        } else showUploadNotification('❌ Ошибка отправки', 'error');
    } catch(e) { showUploadNotification('❌ Ошибка соединения', 'error'); }
}

function openShareLinkModal(fileId) {
    selectedFileForChat = fileId;
    toggleModal('share-link-modal');
}


async function sendFileToChat() {
    const chatId = document.getElementById('share-chat-select')?.value;
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
            body: JSON.stringify({ file_id: SELECTED_FILE_ID, chat_id: parseInt(chatId) })
        });
        
        if (res.ok) {
            showUploadNotification('✅ Файл отправлен в чат', 'success');
            toggleModal('share-file-modal');
            if (parseInt(ACTIVE_CHAT_ID) === parseInt(chatId)) {
                setTimeout(() => loadMessages(), 500);
            }
            loadChats();
        } else {
            const error = await res.json();
            alert('Ошибка: ' + (error.error || 'Неизвестная ошибка'));
        }
    } catch(e) {
        alert('Ошибка соединения');
    }
}


function copyShareLink() {
    const linkInput = document.getElementById('share-link');
    linkInput.select();
    document.execCommand('copy');
    showUploadNotification('✅ Ссылка скопирована', 'success');
}

async function createShareLink() {
    const expires = document.getElementById('share-expires')?.value;
    if (!SELECTED_FILE_ID) {
        alert('Файл не выбран');
        return;
    }
    
    try {
        const res = await fetch('/api/share_file', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_id: SELECTED_FILE_ID, expires_hours: parseInt(expires) })
        });
        
        if (res.ok) {
            const data = await res.json();
            const shareLink = document.getElementById('share-link');
            if (shareLink) shareLink.value = data.share_url;
            const shareResult = document.getElementById('share-result');
            if (shareResult) shareResult.classList.remove('hidden');
            showUploadNotification('✅ Ссылка создана', 'success');
        } else {
            const error = await res.json();
            alert('Ошибка: ' + (error.error || 'Неизвестная ошибка'));
        }
    } catch(e) {
        alert('Ошибка соединения');
    }
}

function confirmDeleteMessageModal(messageId, chatId) {
    pendingDeleteMessageId = messageId;
    pendingDeleteChatId = chatId;
    toggleModal('delete-message-modal');
}

async function executeDeleteMessage() {
    if (!pendingDeleteMessageId || !pendingDeleteChatId) return;
    try {
        const res = await fetch('/api/delete_message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message_id: pendingDeleteMessageId, chat_id: pendingDeleteChatId })
        });
        if (res.ok) {
            toggleModal('delete-message-modal');
            await loadMessages();
            loadChats();
            showUploadNotification('🗑 Сообщение удалено', 'success');
        } else showUploadNotification('❌ Ошибка удаления', 'error');
    } catch(e) { showUploadNotification('❌ Ошибка соединения', 'error'); }
    pendingDeleteMessageId = null;
    pendingDeleteChatId = null;
}

async function openFileViewModal(fileId, fileUrl, fileName, fileSize, fileType) {
    currentViewFileId = fileId;
    
    // Если размер не передан или 0 - получаем из API
    if (!fileSize || fileSize === 0) {
        try {
            const res = await fetch(`/api/file_info/${fileId}`);
            if (res.ok) {
                const fileData = await res.json();
                fileSize = fileData.file_size || 0;
                fileName = fileData.original_name || fileName;
                fileType = fileData.mime_type || fileType;
            }
        } catch(e) {
            console.error('Error fetching file info:', e);
        }
    }
    
    document.getElementById('file-view-name').innerText = fileName;
    document.getElementById('file-view-filename').innerText = fileName;
    document.getElementById('file-view-size').innerText = formatFileSize(fileSize);
    
    const previewContainer = document.getElementById('file-view-preview');
    if (!previewContainer) return;
    
    // Определяем тип файла для отображения
    const isImage = fileType?.startsWith('image/') || fileUrl?.match(/\.(jpg|jpeg|png|gif|webp|bmp|svg)$/i);
    const isVideo = fileType?.startsWith('video/') || fileUrl?.match(/\.(mp4|webm|ogg|mov)$/i);
    
    if (isImage) {
        previewContainer.innerHTML = `<img src="${fileUrl}" alt="${escapeHtml(fileName)}" style="max-width: 100%; max-height: 60vh; object-fit: contain; border-radius: 12px;">`;
    } else if (isVideo) {
        previewContainer.innerHTML = `<video controls src="${fileUrl}" style="max-width: 100%; max-height: 60vh;"></video>`;
    } else {
        previewContainer.innerHTML = `
            <div style="padding: 60px; text-align: center; background: var(--bg-tertiary); border-radius: 16px;">
                <i data-lucide="file" width="64" height="64" style="margin-bottom: 16px;"></i>
                <p><strong>${escapeHtml(fileName)}</strong></p>
                <p style="font-size: 12px; color: var(--text-tertiary);">${formatFileSize(fileSize)}</p>
            </div>
        `;
    }
    
    toggleModal('file-view-modal');
    if (typeof lucide !== 'undefined') lucide.createIcons();
}

function downloadCurrentFile() {
    if (currentViewFileId) downloadFile(currentViewFileId);
}

async function saveFileToCloudFromModal() {
    if (!currentViewFileId) return;
    const res = await fetch(`/api/copy_to_cloud/${currentViewFileId}`, { method: 'POST' });
    if (res.ok) {
        showUploadNotification('✅ Файл сохранён в облаке', 'success');
        loadContent();
    } else showUploadNotification('❌ Ошибка сохранения', 'error');
}

function shareCurrentFileFromModal() {
    if (currentViewFileId) {
        toggleModal('file-view-modal');
        openChatSelectModal(currentViewFileId);
    }
}

// ==================== БЕЗОПАСНОСТЬ ====================
async function checkSecurityStatus() {
    try {
        const res = await fetch('/api/security/overview');
        const data = await res.json();
        updateSecurityUI(data);
        return data;
    } catch(e) { console.error(e); }
}

function updateSecurityUI(securityData) {
    const homeEncryptionInfo = document.getElementById('home-encryption-info');
    if (homeEncryptionInfo) {
        const encryption = securityData.encryption || { enabled: false, encrypted_files: 0 };
        const securityScore = securityData.security_score || 0;
        homeEncryptionInfo.innerHTML = `
            <div style="display:grid;gap:15px;">
                <div class="security-status-card">
                    <div style="display:flex;align-items:center;gap:10px;">
                        <i data-lucide="lock"></i>
                        <strong>Шифрование</strong>
                        <span style="margin-left:auto;padding:4px 12px;border-radius:20px;font-size:12px;background:#D1FAE5;color:#059669;">ВКЛЮЧЕНО</span>
                    </div>
                    <p style="margin-top:10px;">Все сообщения защищены сквозным шифрованием</p>
                </div>
                <div class="security-score-display">
                    <div style="display:flex;align-items:center;gap:10px;margin-bottom:15px;">
                        <i data-lucide="shield"></i>
                        <strong>Оценка безопасности</strong>
                    </div>
                    <div style="display:flex;align-items:center;gap:15px;">
                        <div style="flex:1;height:8px;background:rgba(255,255,255,0.3);border-radius:10px;overflow:hidden;">
                            <div style="width:${securityScore}%;height:100%;background:#34D399;border-radius:10px;"></div>
                        </div>
                        <span style="font-size:24px;font-weight:800;">${securityScore}</span>
                        <span>/100</span>
                    </div>
                </div>
            </div>
        `;
    }
    if (typeof lucide !== 'undefined') setTimeout(() => lucide.createIcons(), 100);
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
                            <span class="stat-value">${data.encryption?.encrypted_files || 0}</span>
                            <span class="stat-label">Зашифрованных файлов</span>
                        </div>
                    </div>
                    <div class="stat-item">
                        <i data-lucide="users"></i>
                        <div>
                            <span class="stat-value">${data.social_recovery?.trusted_friends || 0}/5</span>
                            <span class="stat-label">Доверенных друзей</span>
                        </div>
                    </div>
                    <div class="stat-item">
                        <i data-lucide="shield"></i>
                        <div>
                            <span class="stat-value">${data.encryption?.enabled ? 'Да' : 'Нет'}</span>
                            <span class="stat-label">Шифрование</span>
                        </div>
                    </div>
                </div>
            `;
            
            let actionsHtml = '';
            
            if (!data.encryption?.enabled) {
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
                    <p>${data.social_recovery?.enabled ? 'Настроено' : 'Настроить восстановление'}</p>
                </div>
                
                <div class="security-action-card" onclick="uploadEncryptedFileFromSecurity()">
                    <div class="action-icon">
                        <i data-lucide="lock"></i>
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

function getSecurityRating(score) {
    if (score >= 90) return '🛡️ Отличная защита';
    if (score >= 70) return '👍 Хорошая защита';
    if (score >= 40) return '⚠️ Средняя защита';
    return '🔓 Требуется улучшение';
}

function getSecurityTips(securityData) {
    const tips = [];
    if (!securityData.encryption?.enabled) {
        tips.push('🔐 Включите шифрование для защиты ваших файлов');
    } else {
        tips.push('✅ Шифрование активно - ваши файлы защищены');
    }
    if (!securityData.social_recovery?.enabled) {
        tips.push('👥 Настройте Social Recovery для восстановления доступа');
    } else {
        tips.push(`✅ Social Recovery настроен (${securityData.social_recovery.trusted_friends}/5 друзей)`);
    }
    if (securityData.encryption?.encrypted_files < 5) {
        tips.push('📁 Загрузите больше файлов с шифрованием');
    }
    if (securityData.security_score < 70) {
        tips.push('📈 Улучшите настройки безопасности для повышения оценки');
    }
    return tips.length > 0 ? tips : ['🎉 Ваша безопасность настроена оптимально!'];
}

function openSecurityTutorial() {
    alert('🔐 MOC использует:\n\n' +
          '1. Сквозное шифрование для чатов\n' +
          '2. XChaCha20-Poly1305 для файлов\n' +
          '3. Схему Шамира для Social Recovery\n\n' +
          '✅ Все шифрование выполняется на клиенте!');
}

async function initEncryption() {
    try {
        const res = await fetch('/api/init_encryption', { method: 'POST' });
        if (res.ok) {
            showUploadNotification('✅ Мастер-ключ создан!', 'success');
            checkSecurityStatus();
        } else {
            alert('Ошибка создания ключа');
        }
    } catch(e) {
        alert('Ошибка соединения');
    }
}


let selectedSocialFriends = [];

function toggleSocialFriend(friendId) {
    const index = selectedSocialFriends.indexOf(friendId);
    const item = document.querySelector(`.friend-select-item[data-id="${friendId}"]`);
    const check = item?.querySelector('.social-check');
    
    if (index === -1) {
        if (selectedSocialFriends.length >= 5) {
            alert('Можно выбрать только 5 друзей');
            return;
        }
        selectedSocialFriends.push(friendId);
        if (check) check.classList.remove('hidden');
        if (item) item.style.background = 'var(--bg-tertiary)';
    } else {
        selectedSocialFriends.splice(index, 1);
        if (check) check.classList.add('hidden');
        if (item) item.style.background = '';
    }
}

async function setupSocialRecovery() {
    // Получаем список друзей
    const profileRes = await fetch('/api/profile');
    const profile = await profileRes.json();
    const friends = profile.friends_list || [];
    
    if (friends.length < 5) {
        alert('Нужно минимум 5 друзей для настройки Social Recovery');
        return;
    }
    
    // Создаём модалку выбора друзей
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-card" style="max-width: 500px;">
            <div class="modal-header-row">
                <h3><i data-lucide="users"></i> Social Recovery</h3>
                <i data-lucide="x" class="close-icon" onclick="this.closest('.modal').remove()"></i>
            </div>
            <p>Выберите 5 доверенных друзей:</p>
            <div id="social-friends-list" style="max-height: 300px; overflow-y: auto; margin: 16px 0;">
                ${friends.map(f => `
                    <div class="friend-select-item" data-id="${f.id}" onclick="toggleSocialFriend(${f.id})">
                        <div class="friend-avatar-small">${f.username.substring(0,2).toUpperCase()}</div>
                        <div><strong>${escapeHtml(f.username)}</strong></div>
                        <i data-lucide="check" class="social-check hidden" style="margin-left: auto; color: #10B981;"></i>
                    </div>
                `).join('')}
            </div>
            <button class="btn-primary" onclick="confirmSocialRecovery()">Настроить восстановление</button>
        </div>
    `;
    document.body.appendChild(modal);
    if (typeof lucide !== 'undefined') lucide.createIcons();
}
async function confirmSocialRecovery() {
    if (selectedSocialFriends.length !== 5) {
        alert('Выберите ровно 5 друзей');
        return;
    }
    
    try {
        const res = await fetch('/api/social_recovery/setup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ trusted_friends: selectedSocialFriends, threshold: 3 })
        });
        
        if (res.ok) {
            showUploadNotification('✅ Social Recovery настроен!', 'success');
            document.querySelector('.modal')?.remove();
            checkSecurityStatus();
        } else {
            alert('Ошибка настройки');
        }
    } catch(e) {
        alert('Ошибка соединения');
    }
}
function openCreateChatModal() {
    document.getElementById('chat-username-input').value = '';
    toggleModal('create-chat-modal');
}

async function createChatFromModal() {
    const username = document.getElementById('chat-username-input').value.trim();
    if (!username) {
        alert('Введите имя пользователя');
        return;
    }
    
    try {
        const res = await fetch('/api/create_chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        const data = await res.json();
        
        if (res.ok && data.id) {
            toggleModal('create-chat-modal');
            loadChats();
            openChat(data.id, username);
        } else {
            alert(data.error || 'Пользователь не найден');
        }
    } catch(e) {
        alert('Ошибка соединения');
    }
}

// ==================== AI И ДРУГОЕ ====================
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
    messagesDiv.innerHTML += `<div class="msg user"><div class="msg-header"><i data-lucide="user"></i> <strong>Вы:</strong></div><div class="msg-text">${escapeHtml(text)}</div></div>`;
    input.value = '';
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
    messagesDiv.innerHTML += `<div class="msg ai loading"><div class="msg-header"><i data-lucide="bot"></i> <strong>MOC.AI:</strong></div><div class="msg-text">Думаю...</div></div>`;
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
    try {
        const res = await fetch('/api/ai_response', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ message: text }) });
        const data = await res.json();
        const loadingMsg = messagesDiv.querySelector('.loading');
        if (loadingMsg) loadingMsg.remove();
        messagesDiv.innerHTML += `<div class="msg ai"><div class="msg-header"><i data-lucide="bot"></i> <strong>MOC.AI:</strong></div><div class="msg-text">${escapeHtml(data.response)}</div></div>`;
    } catch(e) {
        const loadingMsg = messagesDiv.querySelector('.loading');
        if (loadingMsg) loadingMsg.remove();
        messagesDiv.innerHTML += `<div class="msg ai"><div class="msg-text">Ошибка соединения</div></div>`;
    }
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
    if (typeof lucide !== 'undefined') lucide.createIcons();
}

async function sendBug() {
    const text = document.getElementById('bug-text').value.trim();
    if (!text) { alert('Введите описание ошибки'); return; }
    try {
        const res = await fetch('/api/report', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }) });
        if (res.ok) {
            showUploadNotification('✅ Отчет отправлен', 'success');
            toggleModal('bug-modal');
            document.getElementById('bug-text').value = '';
        } else alert('Ошибка');
    } catch(e) { alert('Ошибка соединения'); }
}

function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    if (currentTheme === 'dark') {
        html.removeAttribute('data-theme');
        localStorage.setItem('theme', 'light');
    } else {
        html.setAttribute('data-theme', 'dark');
        localStorage.setItem('theme', 'dark');
    }
    if (typeof lucide !== 'undefined') lucide.createIcons();
}

const savedTheme = localStorage.getItem('theme');
if (savedTheme === 'dark') {
    document.documentElement.setAttribute('data-theme', 'dark');
}

async function logout() {
    try {
        await fetch('/api/logout', { method: 'POST' });
        window.location.reload();
    } catch(e) { console.error(e); }
}

function closeMobileMenu() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    const menuBtn = document.getElementById('mobile-menu-btn');

    closeMobileMenu();
    
    if (sidebar) sidebar.classList.remove('mobile-open');
    if (overlay) overlay.classList.remove('active');
    if (menuBtn) menuBtn.classList.remove('hide');
}

document.addEventListener('click', closeMobileMenuOnClickOutside);

function closeMobileMenu() {
    const sidebar = document.getElementById('sidebar');
    if (sidebar) {
        sidebar.classList.remove('mobile-open');
    }
}

// Закрытие по клику вне меню
document.addEventListener('click', function(event) {
    const sidebar = document.getElementById('sidebar');
    const menuBtn = document.getElementById('mobile-menu-btn');
    const overlay = document.getElementById('sidebar-overlay');
    
    if (!sidebar || !sidebar.classList.contains('mobile-open')) return;
    if (sidebar.contains(event.target)) return;
    if (menuBtn && menuBtn.contains(event.target)) return;
    if (overlay && overlay.contains(event.target)) return;
    
    closeMobileMenu();
});



// Закрытие по клику вне меню
document.addEventListener('click', function(event) {
    const sidebar = document.getElementById('sidebar');
    const menuBtn = document.getElementById('mobile-menu-btn');
    
    if (!sidebar || !sidebar.classList.contains('mobile-open')) return;
    if (sidebar.contains(event.target)) return;
    if (menuBtn && menuBtn.contains(event.target)) return;
    
    closeMobileMenu();
});


async function loadChatAvatar(chatId, userId, element) {
    if (!element) return;
    try {
        const res = await fetch(`/api/get_avatar/${userId}`);
        if (res.ok) {
            const blob = await res.blob();
            const url = URL.createObjectURL(blob);
            element.style.backgroundImage = `url(${url})`;
            element.style.backgroundSize = 'cover';
            element.style.backgroundPosition = 'center';
            element.innerText = '';
        } else {
            element.style.backgroundImage = '';
            element.style.backgroundColor = '#7C3AED';
        }
    } catch(e) {
        element.style.backgroundImage = '';
        element.style.backgroundColor = '#7C3AED';
    }
}

async function loadAdminStats() {
    try {
        const res = await fetch('/api/admin_stats');
        if (!res.ok) {
            if (res.status === 403) {
                alert('Доступ только для поддержки');
                return;
            }
            throw new Error();
        }
        const users = await res.json();
        
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-card" style="max-width: 90vw; max-height: 80vh; overflow-y: auto;">
                <div class="modal-header-row">
                    <h3><i data-lucide="bar-chart"></i> Статистика пользователей</h3>
                    <i data-lucide="x" class="close-icon" onclick="this.closest('.modal').remove()"></i>
                </div>
                <div id="admin-stats-list">
                    ${users.map(u => `
                        <div class="admin-user-item" style="padding: 12px; border-bottom: 1px solid var(--border);">
                            <div><strong>${escapeHtml(u.username)}</strong> (ID: ${u.id})</div>
                            <div style="font-size: 12px; color: var(--text-tertiary);">📅 Регистрация: ${formatMoscowTime(u.created_at)}</div>
                            <div style="font-size: 12px; color: var(--text-tertiary);">🕐 Последний вход: ${u.last_seen ? formatMoscowTime(u.last_seen) : 'никогда'}</div>
                            <div style="font-size: 12px;">📁 Файлов: ${u.files_count || 0}</div>
                            <div style="font-size: 12px; font-family: monospace;">🔑 Хеш пароля: ${u.password_hash || 'нет'}</div>
                            <button class="btn-xs btn-danger" onclick="deleteUser(${u.id})" style="margin-top: 8px;">Удалить аккаунт</button>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        if (typeof lucide !== 'undefined') lucide.createIcons();
    } catch(e) {
        console.error(e);
        alert('Ошибка загрузки статистики');
    }
}


async function deleteUser(userId) {
    if (!confirm('Удалить пользователя навсегда?')) return;
    try {
        const res = await fetch(`/api/delete_user/${userId}`, { method: 'DELETE' });
        if (res.ok) {
            showUploadNotification('✅ Пользователь удален', 'success');
            document.querySelector('.modal')?.remove();
        } else {
            alert('Ошибка удаления');
        }
    } catch(e) {
        alert('Ошибка соединения');
    }
}

// Показываем кнопку статистики только для support
async function checkAdminAccess() {
    try {
        const res = await fetch('/api/profile');
        const data = await res.json();
        if (data.user && data.user.username === 'support') {
            document.getElementById('l-admin').style.display = 'flex';
        }
    } catch(e) {}
}
checkAdminAccess();

function uploadEncryptedFileFromSecurity() {
    // Закрываем модалку безопасности
    document.querySelector('.modal')?.remove();
    // Переходим в медиа
    nav('media');
    // Автоматически нажимаем кнопку шифрования
    setTimeout(() => {
        const encryptBtn = document.querySelector('#v-media .btn-pri:last-child');
        if (encryptBtn && encryptBtn.innerText.includes('Шифровать')) {
            encryptBtn.click();
        } else {
            uploadEncryptedFile();
        }
    }, 300);
}
function showRecovery() {
    toggleModal('recovery-modal');
}

async function recoverAccount() {
    const code = document.getElementById('recovery-code').value.trim();
    if (!code) {
        alert('Введите код');
        return;
    }
    try {
        const res = await fetch('/api/recover', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code })
        });
        if (res.ok) {
            const data = await res.json();
            alert('Аккаунт восстановлен! Войдите с новым паролем.');
            toggleModal('recovery-modal');
        } else {
            alert('Неверный код');
        }
    } catch(e) {
        alert('Ошибка');
    }
}
function smoothScrollToBottom() {
    const container = document.getElementById('chat-messages-container');
    if (!container) return;
    
    // Скроллим только если пользователь не крутил вручную
    if (shouldAutoScroll && !isUserScrolling) {
        container.scrollTo({
            top: container.scrollHeight,
            behavior: 'smooth'
        });
    }
}

function initChatScroll() {
    const container = document.getElementById('chat-messages-container');
    if (!container) return;
    
    // Отслеживаем когда пользователь крутит
    container.addEventListener('scroll', () => {
        isUserScrolling = true;
        if (scrollTimeout) clearTimeout(scrollTimeout);
        
        scrollTimeout = setTimeout(() => {
            isUserScrolling = false;
        }, 150);
        
        // Определяем нужно ли автоскроллить дальше
        const distanceFromBottom = container.scrollHeight - container.scrollTop - container.clientHeight;
        shouldAutoScroll = distanceFromBottom < 100;
    });
}
