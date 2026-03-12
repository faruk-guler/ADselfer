# ADselfer - Kurumsal Active Directory SSPR Çözümü

ADselfer, kullanıcıların kendi parolalarını güvenli bir şekilde sıfırlamasına olanak tanıyan, modern ve tamamen özelleştirilebilir bir Self-Service Password Reset (SSPR) çözümüdür.

## 🚀 Öne Çıkan Özellikler

- **Çift Katmanlı Doğrulama:** E-posta OTP (kod) ve Güvenlik Soruları ile maksimum güvenlik.
- **Premium Tasarım:** Modern Glassmorphism arayüzü ile kurumsal kimliğe uygun görünüm.
- **Full Docker Desteği:** Tek komutla imaj oluşturma ve dağıtım.
- **On-Premise Fokus:** Verileriniz kendi sunucunuzda, Active Directory ile LDAPS üzerinden güvenli iletişim.

## 📂 Proje Yapısı

```
/
├── adselfer-app/          # Özel geliştirilen Node.js uygulaması
│   ├── backend/          # LDAP & İş Mantığı
│   ├── frontend/         # Kullanıcı Arayüzü
│   ├── config/           # Yapılandırma (.env)
│   └── Dockerfile        # İmaj tanımı
└── README.md             # Ana dökümantasyon (şu an okuduğunuz)
```

## 🛠 Kurulum Adımları

### 1. Projenin Sunucuya Aktarılması ve Başlatılması
1. Bu dizindeki (`Antigravity`) tüm dosyaları sunucunuza (örn: `/opt/adselfer` altına) kopyalayın.
2. Yapılandırmayı düzelten:
   ```bash
   cd adselfer-app
   cp config/.env.example config/.env
   nano config/.env
   cd ..
   ```
3. Uygulamayı başlatın (Ana dizinden):
   ```bash
   # Docker V2 için:
   docker compose up -d --build

   # Eğer hata alırsanız (V1):
   docker-compose up -d --build
   ```

Uygulamanıza `http://<sunucu-ip>:3000` adresinden erişebilirsiniz.

## 🔐 Active Directory Tarafındaki İşlemler

Uygulamanın şifre sıfırlayabilmesi için AD üzerinde şu hazırlıkları yapmalısınız:

### 1. Servis Hesabı Oluşturma
AD üzerinde `svc_adselfer` adında standart bir kullanıcı hesabı oluşturun. ("Password never expires" seçeneği önerilir).

### 2. Yetkilendirme (Delegasyon)
Kullanıcıların bulunduğu OU üzerinde sağ tıklayın -> **Delegate Control**:
1. `svc_adselfer` hesabını ekleyin.
2. **Create a custom task to delegate** seçin.
3. **Only the following objects in the folder** -> **User objects** seçin.
4. İzin listesinden şunları işaretleyin:
   - Reset Password
   - Write lockoutTime
   - Write pwdLastSet

## 📕 Dökümantasyon ve Teknik Detaylar

### Uygulama Bileşenleri
- **backend/**: Node.js tabanlı Express API (LDAP iletişimi ve OTP yönetimi).
- **frontend/**: Modern, Glassmorphism tarzı kullanıcı arayüzü.
- **config/**: Hassas bilgilerin yönetildiği `.env` yapılandırması.

### LDAPS ve Güvenlik
- **Güvenli Bağlantı:** Şifre değiştirme işlemi için AD sunucunuzda SSL sertifikası (LDAPS) yüklü olmalıdır.
- **OTP Süresi:** Varsayılan olarak doğrulama kodları 5 dakika geçerlidir.
- **Güvenlik Sorusu:** AD üzerindeki `description` alanı, kullanıcının girmesi gereken cevap olarak okunur.

---
**ADselfer** projesi, güvenliğiniz ve kullanım kolaylığınız ön planda tutularak tasarlandırılmıştır.
