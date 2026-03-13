let currentSessionId = null;
let currentProfileSessionId = null;

function switchTab(tab) {
    const isReset = tab === 'reset';
    const isProfile = tab === 'profile';
    const isAbout = tab === 'about';
    const isAdmin = tab === 'admin';

    document.getElementById('reset-section').style.display = isReset ? 'block' : 'none';
    document.getElementById('profile-section').style.display = isProfile ? 'block' : 'none';
    document.getElementById('about-section').style.display = isAbout ? 'block' : 'none';
    document.getElementById('admin-section').style.display = isAdmin ? 'block' : 'none';
    
    document.getElementById('tab-reset').classList.toggle('active', isReset);
    document.getElementById('tab-profile').classList.toggle('active', isProfile);
    document.getElementById('tab-about').classList.toggle('active', isAbout);
    document.getElementById('tab-admin').classList.toggle('active', isAdmin);
    
    const titles = {
        reset: 'Güvenli Şifre Sıfırlama Portalı',
        profile: 'Güvenlik Bilgilerinizi Güncelleyin',
        about: 'ADselfer Hakkında',
        admin: 'Yönetim Paneli'
    };
    document.getElementById('sub-title').innerText = titles[tab];
    document.getElementById('error-msg').innerText = '';
    
    if (isReset) showStep('step-1');
    if (isProfile) showStep('profile-login');
    if (isAdmin) showStep('admin-login');
}

function showStep(stepId) {
    const sections = ['reset-section', 'profile-section', 'about-section', 'admin-section'];
    sections.forEach(secId => {
        const sec = document.getElementById(secId);
        if (sec.style.display !== 'none') {
            sec.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
        }
    });
    document.getElementById(stepId).classList.add('active');
    document.getElementById('error-msg').innerText = '';
}

function toggleLoader(show) {
    const loader = document.getElementById('loader');
    loader.className = show ? 'loader' : 'loader-hidden';
    document.querySelectorAll('button').forEach(b => b.disabled = show);
}

// Reset Flow
async function lookupUser() {
    const username = document.getElementById('username').value;
    if (!username) return showError('Lütfen kullanıcı adınızı girin.');

    toggleLoader(true);
    try {
        const response = await fetch('/api/lookup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        const data = await response.json();

        if (response.ok) {
            currentSessionId = data.sessionId;
            document.getElementById('email-hint').innerText = data.emailHint;
            showStep('step-2');
        } else {
            showError(data.error);
        }
    } catch (err) {
        showError('Sunucuya bağlanılamadı.');
    } finally {
        toggleLoader(false);
    }
}

async function verifyUser() {
    const otp = document.getElementById('otp').value;
    const answer = document.getElementById('answer').value;

    if (!otp || !answer) return showError('Lütfen tüm alanları doldurun.');

    toggleLoader(true);
    try {
        const response = await fetch('/api/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sessionId: currentSessionId, otp, answer })
        });
        const data = await response.json();

        if (response.ok) {
            showStep('step-3');
            initPasswordValidation();
        } else {
            showError(data.error);
        }
    } catch (err) {
        showError('Doğrulama hatası.');
    } finally {
        toggleLoader(false);
    }
}

async function unlockAccount() {
    const otp = document.getElementById('otp').value;
    const answer = document.getElementById('answer').value;

    if (!otp || !answer) return showError('Lütfen tüm alanları doldurun.');

    toggleLoader(true);
    try {
        // We reuse the same verification logic conceptually but with a different action in audit
        const response = await fetch('/api/unlock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sessionId: currentSessionId, otp, answer })
        });
        const data = await response.json();

        if (response.ok) {
            showStep('success-screen');
            document.querySelector('#success-screen h2').innerText = 'Hesap Kilidi Açıldı!';
            document.querySelector('#success-screen p').innerText = data.message;
        } else {
            showError(data.error);
        }
    } catch (err) {
        showError('İşlem hatası.');
    } finally {
        toggleLoader(false);
    }
}

function initPasswordValidation() {
    const pwdInput = document.getElementById('new-password');
    const confirmInput = document.getElementById('confirm-password');
    const submitBtn = document.getElementById('btn-submit-reset');

    const updateChecklist = () => {
        const val = pwdInput.value;
        const confirmVal = confirmInput.value;

        const rules = {
            length: val.length >= 8,
            upper: /[A-Z]/.test(val),
            lower: /[a-z]/.test(val),
            number: /[0-9]/.test(val),
            special: /[^A-Za-z0-9]/.test(val)
        };

        for (const [rule, met] of Object.entries(rules)) {
            document.getElementById(`rule-${rule}`).classList.toggle('met', met);
        }

        const allMet = Object.values(rules).every(Boolean);
        const match = val === confirmVal && val.length > 0;
        
        submitBtn.disabled = !(allMet && match);
    };

    pwdInput.addEventListener('input', updateChecklist);
    confirmInput.addEventListener('input', updateChecklist);
}

// --- ADMIN LOGIC ---
let adminToken = null;

async function loginAdmin() {
    const username = document.getElementById('admin-user').value;
    const password = document.getElementById('admin-pass').value;

    if (!username || !password) return showError('Lütfen bilgilerinizi girin.');

    toggleLoader(true);
    try {
        const response = await fetch('/api/admin/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();

        if (response.ok) {
            adminToken = data.token;
            showStep('admin-dashboard');
            loadLogs();
        } else {
            showError(data.error);
        }
    } catch (err) {
        showError('Giriş hatası.');
    } finally {
        toggleLoader(false);
    }
}

async function loadLogs() {
    const container = document.getElementById('log-container');
    container.innerText = 'Yükleniyor...';

    try {
        const response = await fetch('/api/admin/logs', {
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });
        const data = await response.json();

        if (response.ok) {
            container.innerHTML = data.logs.map(log => {
                const l = JSON.parse(log);
                return `<div class="log-item"><span>[${l.timestamp.split('T')[1].split('.')[0]}]</span> <b>${l.user}</b>: ${l.action} -> ${l.result}</div>`;
            }).join('');
        } else {
            container.innerText = 'Loglar yüklenemedi: ' + data.error;
        }
    } catch (err) {
        container.innerText = 'Loglar yüklenemedi.';
    }
}

async function resetPassword() {
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    if (newPassword !== confirmPassword) return showError('Şifreler uyuşmuyor.');
    if (newPassword.length < 8) return showError('Şifre en az 8 karakter olmalıdır.');

    toggleLoader(true);
    try {
        const response = await fetch('/api/reset', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sessionId: currentSessionId, newPassword })
        });
        const data = await response.json();

        if (response.ok) {
            showStep('success-screen');
        } else {
            showError(data.error);
        }
    } catch (err) {
        showError('Şifre güncelleme hatası.');
    } finally {
        toggleLoader(false);
    }
}

// Profile Flow
async function loginProfile() {
    const username = document.getElementById('prof-username').value;
    const password = document.getElementById('prof-password').value;

    if (!username || !password) return showError('Lütfen bilgilerinizi girin.');

    toggleLoader(true);
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();

        if (response.ok) {
            currentProfileSessionId = data.profileSessionId;
            showStep('profile-setup');
        } else {
            showError(data.error);
        }
    } catch (err) {
        showError('Giriş yapılamadı.');
    } finally {
        toggleLoader(false);
    }
}

async function setupProfile() {
    const answer = document.getElementById('new-answer').value;
    if (!answer) return showError('Cevap boş olamaz.');

    toggleLoader(true);
    try {
        const response = await fetch('/api/setup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ profileSessionId: currentProfileSessionId, answer })
        });
        const data = await response.json();

        if (response.ok) {
            showStep('success-screen');
            document.querySelector('#success-screen h2').innerText = 'Profil Güncellendi!';
            document.querySelector('#success-screen p').innerText = 'Güvenlik profiliniz başarıyla güncellendi.';
        } else {
            showError(data.error);
        }
    } catch (err) {
        showError('Kayıt hatası.');
    } finally {
        toggleLoader(false);
    }
}

function showError(msg) {
    document.getElementById('error-msg').innerText = msg;
}
