let currentSessionId = null;

function showStep(stepId) {
    document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
    document.getElementById(stepId).classList.add('active');
    document.getElementById('error-msg').innerText = '';
}

function toggleLoader(show) {
    const loader = document.getElementById('loader');
    loader.className = show ? 'loader' : 'loader-hidden';
    document.querySelectorAll('button').forEach(b => b.disabled = show);
}

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
        } else {
            showError(data.error);
        }
    } catch (err) {
        showError('Doğrulama hatası.');
    } finally {
        toggleLoader(false);
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

function showError(msg) {
    document.getElementById('error-msg').innerText = msg;
}
