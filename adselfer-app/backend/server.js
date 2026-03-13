const express = require('express');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const fs = require('fs');
const ldap = require('ldapjs');
const path = require('path');
const { bindUser, searchUser } = require('./ldap-client');
require('dotenv').config({ path: path.join(__dirname, '../config/.env') });

const app = express();
// Middleware: Security Headers
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self'");
    next();
});

app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// Audit Logging
const auditLog = (user, action, result, ip) => {
    const logEntry = {
        timestamp: new Date().toISOString(),
        user: user || 'anonymous',
        action,
        result,
        ip
    };
    const logPath = path.join(__dirname, 'audit.log');
    fs.appendFileSync(logPath, JSON.stringify(logEntry) + '\n');
};

// Robust Password Policy
const validatePassword = (password) => {
    const minLength = parseInt(process.env.PWD_MIN_LENGTH) || 8;
    const requirements = [
        { regex: /[A-Z]/, msg: 'En az bir büyük harf içermelidir.' },
        { regex: /[a-z]/, msg: 'En az bir küçük harf içermelidir.' },
        { regex: /[0-9]/, msg: 'En az bir rakam içermelidir.' },
        { regex: /[^A-Za-z0-9]/, msg: 'En az bir özel karakter içermelidir.' }
    ];

    if (password.length < minLength) return { valid: false, error: `Şifre en az ${minLength} karakter olmalıdır.` };
    
    for (const req of requirements) {
        if (!req.regex.test(password)) return { valid: false, error: req.msg };
    }
    
    return { valid: true };
};

// Rate Limiting and Session Store
const sessions = new Map();
const rateLimits = new Map();

// Session & Rate Limit Cleanup (Every 10 minutes)
setInterval(() => {
    const now = Date.now();
    // Cleanup Sessions
    for (const [id, session] of sessions) {
        if (session.expiry && now > session.expiry) {
            sessions.delete(id);
            console.log(`[Cleanup] Session ${id} expired.`);
        }
    }
    // Cleanup Rate Limits (Remove expired records)
    for (const [key, record] of rateLimits) {
        if (now > record.resetTime) {
            rateLimits.delete(key);
        }
    }
}, 10 * 60 * 1000);

// Helper: Hashing Utility
const hashAnswer = (answer) => {
    return crypto.createHash('sha256').update(answer.toLowerCase().trim() + process.env.SECRET_SALT).digest('hex');
};

// Middleware: Rate Limiter
const checkRateLimit = (key, res, limit = 5, windowMs = 15 * 60 * 1000) => {
    const now = Date.now();
    const record = rateLimits.get(key) || { count: 0, resetTime: now + windowMs };

    if (now > record.resetTime) {
        record.count = 1;
        record.resetTime = now + windowMs;
    } else {
        record.count++;
    }

    rateLimits.set(key, record);

    if (record.count > limit) {
        const waitMin = Math.ceil((record.resetTime - now) / 60000);
        res.status(429).json({ error: `Çok fazla deneme. Lütfen ${waitMin} dakika sonra tekrar deneyin.` });
        return false;
    }
    return true;
};

// Helper: Send Email with OTP
const sendOtpEmail = async (email, otp) => {
    const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT,
        secure: process.env.SMTP_PORT == 465,
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
        }
    });

    await transporter.sendMail({
        from: process.env.SMTP_FROM,
        to: email,
        subject: 'ADselfer - Şifre Sıfırlama Kodu',
        text: `Güvenliğiniz için tek kullanımlık kodunuz: ${otp}. Bu kod 5 dakika geçerlidir.`
    });
};

// Phase 1: Search User
app.post('/api/lookup', async (req, res) => {
    const { username } = req.body;
    const ip = req.ip;

    if (!checkRateLimit(`lookup:${ip}`, res)) return;

    let client;
    try {
        client = await bindUser(process.env.AD_SERVICE_ACCOUNT_DN, process.env.AD_SERVICE_ACCOUNT_PW);
        const user = await searchUser(client, username);

        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });

        // Generate OTP
        const otp = crypto.randomInt(100000, 999999).toString();
        const sessionId = crypto.randomUUID();

        sessions.set(sessionId, {
            username,
            dn: user.dn,
            email: user.mail,
            otp,
            securityQuestion: 'Güvenlik Sorusu (Hashlenmiş):', 
            securityAnswer: user.description, // AD description is the source of truth (hashed)
            expiry: Date.now() + 5 * 60 * 1000
        });

        console.log(`[Lookup] User: ${username}, Session: ${sessionId} created.`);

        if (user.mail) {
            await sendOtpEmail(user.mail, otp);
            res.json({ sessionId, emailHint: user.mail.replace(/(.{2})(.*)(?=@)/, '$1***') });
        } else {
            res.status(400).json({ error: 'Kullanıcının kayıtlı e-postası bulunamadı.' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Sunucu hatası: ' + err.message });
    } finally {
        if (client) client.unbind();
    }
});

// Phase 2: Verify OTP and Security Question
app.post('/api/verify', (req, res) => {
    const { sessionId, otp, answer } = req.body;
    const session = sessions.get(sessionId);

    if (!session) return res.status(400).json({ error: 'Oturum geçersiz.' });

    if (session.otp !== otp) {
        if (!checkRateLimit(`verify:${sessionId}`, res, 3)) return;
        return res.status(401).json({ error: 'Hatalı doğrulama kodu.' });
    }
    
    if (session.securityAnswer !== hashAnswer(answer)) {
        if (!checkRateLimit(`verify:${sessionId}`, res, 3)) return;
        return res.status(401).json({ error: 'Hatalı güvenlik sorusu cevabı.' });
    }

    session.verified = true;
    res.json({ message: 'Doğrulama başarılı. Yeni şifrenizi belirleyin.' });
});

// Profile Phase 1: Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    let client;
    try {
        client = await bindUser(process.env.AD_SERVICE_ACCOUNT_DN, process.env.AD_SERVICE_ACCOUNT_PW);
        const user = await searchUser(client, username);

        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });

        const userClient = await bindUser(user.dn, password);
        userClient.unbind();

        const profileSessionId = crypto.randomUUID();
        sessions.set(profileSessionId, { 
            username, 
            dn: user.dn, 
            authenticated: true,
            expiry: Date.now() + 15 * 60 * 1000
        });

        res.json({ profileSessionId, message: 'Giriş başarılı.' });
    } catch (err) {
        res.status(401).json({ error: 'Hatalı kullanıcı adı veya şifre.' });
    } finally {
        if (client) client.unbind();
    }
});

// Profile Phase 2: Setup Security Question
app.post('/api/setup', async (req, res) => {
    const { profileSessionId, answer } = req.body;
    const session = sessions.get(profileSessionId);

    if (!session || !session.authenticated) return res.status(403).json({ error: 'Yetkisiz erişim.' });

    let client;
    try {
        const hashed = hashAnswer(answer);
        client = await bindUser(process.env.AD_SERVICE_ACCOUNT_DN, process.env.AD_SERVICE_ACCOUNT_PW);
        
        const modification = new ldap.Modification({
            operation: 'replace',
            modification: {
                description: hashed
            }
        });

        client.modify(session.dn, modification, (err) => {
            if (err) return res.status(500).json({ error: 'Güvenlik cevabı kaydedilemedi: ' + err.message });
            
            sessions.delete(profileSessionId);
            res.json({ message: 'Güvenlik profiliniz başarıyla güncellendi!' });
        });
    } catch (err) {
        res.status(500).json({ error: 'AD hatası: ' + err.message });
    } finally {
        setTimeout(() => { if (client) client.unbind(); }, 1000); // Small delay to allow callback to finish if needed
    }
});

// Phase 3: Reset Password
app.post('/api/reset', async (req, res) => {
    const { sessionId, newPassword } = req.body;
    const session = sessions.get(sessionId);
    const ip = req.ip;

    if (!session || !session.verified) {
        auditLog(session?.username, 'PASSWORD_RESET', 'FAILED: Unverified Session', ip);
        return res.status(403).json({ error: 'Yetkisiz erişim veya oturum süresi dolmuş.' });
    }

    const policy = validatePassword(newPassword);
    if (!policy.valid) {
        return res.status(400).json({ error: policy.error });
    }

    let client;
    try {
        client = await bindUser(process.env.AD_SERVICE_ACCOUNT_DN, process.env.AD_SERVICE_ACCOUNT_PW);
        
        const modification = new ldap.Modification({
            operation: 'replace',
            modification: {
                unicodePwd: Buffer.from(`"${newPassword}"`, 'utf16le')
            }
        });

        client.modify(session.dn, modification, (err) => {
            if (err) {
                auditLog(session.username, 'PASSWORD_RESET', `FAILED: ${err.message}`, ip);
                return res.status(500).json({ error: 'Şifre güncellenemedi: ' + err.message });
            }

            auditLog(session.username, 'PASSWORD_RESET', 'SUCCESS', ip);
            sessions.delete(sessionId);
            res.json({ message: 'Şifreniz başarıyla güncellendi!' });
        });
    } catch (err) {
        auditLog(session.username, 'PASSWORD_RESET', `SERVER_ERROR: ${err.message}`, ip);
        res.status(500).json({ error: 'AD hatası: ' + err.message });
    } finally {
        setTimeout(() => { if (client) client.unbind(); }, 1000);
    }
});

// Phase 4: Account Unlock
app.post('/api/unlock', async (req, res) => {
    const { sessionId, otp, answer } = req.body;
    const session = sessions.get(sessionId);
    const ip = req.ip;

    if (!session || !session.verified) {
        auditLog(session?.username, 'ACCOUNT_UNLOCK', 'FAILED: Unverified Session', ip);
        return res.status(403).json({ error: 'Yetkisiz erişim veya oturum süresi dolmuş.' });
    }

    let client;
    try {
        client = await bindUser(process.env.AD_SERVICE_ACCOUNT_DN, process.env.AD_SERVICE_ACCOUNT_PW);
        
        const modification = new ldap.Modification({
            operation: 'replace',
            modification: {
                lockoutTime: '0'
            }
        });

        client.modify(session.dn, modification, (err) => {
            if (err) {
                auditLog(session.username, 'ACCOUNT_UNLOCK', `FAILED: ${err.message}`, ip);
                return res.status(500).json({ error: 'Hesap kilidi açılamadı: ' + err.message });
            }

            auditLog(session.username, 'ACCOUNT_UNLOCK', 'SUCCESS', ip);
            sessions.delete(sessionId);
            res.json({ message: 'Hesap kilidiniz başarıyla açıldı! Artık giriş yapabilirsiniz.' });
        });
    } catch (err) {
        auditLog(session.username, 'ACCOUNT_UNLOCK', `SERVER_ERROR: ${err.message}`, ip);
        res.status(500).json({ error: 'AD hatası: ' + err.message });
    } finally {
        setTimeout(() => { if (client) client.unbind(); }, 1000);
    }
});

// --- ADMIN ENDPOINTS ---
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    const ip = req.ip;

    if (!checkRateLimit(`admin_login:${ip}`, res, 3, 30 * 60 * 1000)) return;

    if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) {
        auditLog('ADMIN', 'LOGIN', 'SUCCESS', ip);
        const token = crypto.randomUUID();
        sessions.set(token, { isAdmin: true, expiry: Date.now() + 3600000 });
        res.json({ token });
    } else {
        auditLog('ADMIN', 'LOGIN', 'FAILED', ip);
        res.status(401).json({ error: 'Hatalı yönetici bilgileri.' });
    }
});

app.get('/api/admin/logs', (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'Yetkisiz erişim.' });
    
    const token = auth.replace('Bearer ', '');
    const session = sessions.get(token);
    
    if (!session || !session.isAdmin) return res.status(403).json({ error: 'Erişim reddedildi.' });

    try {
        const logPath = path.join(__dirname, 'audit.log');
        if (!fs.existsSync(logPath)) return res.json({ logs: [] });
        
        const logs = fs.readFileSync(logPath, 'utf8').trim().split('\n').reverse().slice(0, 100);
        res.json({ logs });
    } catch (err) {
        res.status(500).json({ error: 'Loglar okunamadı.' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`ADselfer is running on port ${PORT}`));
