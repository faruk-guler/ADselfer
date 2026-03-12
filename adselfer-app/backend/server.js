const express = require('express');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const ldap = require('ldapjs');
const path = require('path');
const { bindUser, searchUser } = require('./ldap-client');
require('dotenv').config({ path: path.join(__dirname, '../config/.env') });

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// Temporary in-memory store for OTPs and sessions (In production use Redis/Database)
const sessions = new Map();

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
    try {
        const client = await bindUser(process.env.AD_SERVICE_ACCOUNT_DN, process.env.AD_SERVICE_ACCOUNT_PW);
        const user = await searchUser(client, username);
        client.unbind();

        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });

        // Generate OTP
        const otp = crypto.randomInt(100000, 999999).toString();
        const sessionId = crypto.randomUUID();

        sessions.set(sessionId, {
            username,
            dn: user.dn,
            email: user.mail,
            otp,
            securityQuestion: 'Güvenlik Sorusu (AD description alanından):', 
            securityAnswer: user.description // AD description is the source of truth
        });

        // Hide sensitive email details for logging
        console.log(`[Lookup] User: ${username}, Session: ${sessionId} created.`);

        if (user.mail) {
            await sendOtpEmail(user.mail, otp);
            res.json({ sessionId, method: 'hybrid', emailHint: user.mail.replace(/(.{2})(.*)(?=@)/, '$1***') });
        } else {
            res.status(400).json({ error: 'Kullanıcının kayıtlı e-postası bulunamadı.' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Sunucu hatası: ' + err.message });
    }
});

// Phase 2: Verify OTP and Security Question
app.post('/api/verify', (req, res) => {
    const { sessionId, otp, answer } = req.body;
    const session = sessions.get(sessionId);

    if (!session) return res.status(400).json({ error: 'Oturum geçersiz.' });

    if (session.otp !== otp) return res.status(401).json({ error: 'Hatalı doğrulama kodu.' });
    if (session.securityAnswer !== answer) return res.status(401).json({ error: 'Hatalı güvenlik sorusu cevabı.' });

    session.verified = true;
    res.json({ message: 'Doğrulama başarılı. Yeni şifrenizi belirleyin.' });
});

// Phase 3: Reset Password
app.post('/api/reset', async (req, res) => {
    const { sessionId, newPassword } = req.body;
    const session = sessions.get(sessionId);

    if (!session || !session.verified) return res.status(403).json({ error: 'Yetkisiz işlem.' });

    try {
        const client = await bindUser(process.env.AD_SERVICE_ACCOUNT_DN, process.env.AD_SERVICE_ACCOUNT_PW);
        
        // AD Password change logic (Requires LDAPS)
        const modification = new ldap.Modification({
            operation: 'replace',
            modification: {
                unicodePwd: Buffer.from(`"${newPassword}"`, 'utf16le')
            }
        });

        client.modify(session.dn, modification, (err) => {
            client.unbind();
            if (err) return res.status(500).json({ error: 'Şifre güncellenemedi: ' + err.message });
            
            sessions.delete(sessionId);
            res.json({ message: 'Şifreniz başarıyla güncellendi!' });
        });
    } catch (err) {
        res.status(500).json({ error: 'AD hatası: ' + err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`ADselfer is running on port ${PORT}`));
