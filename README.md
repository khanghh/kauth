# kauth

**kauth** is self-hosted **CAS** with social login built with **Go**, **MySQL**, and **Redis**.  
It provides a secure, scalable, and easy-to-deploy authentication service for managing user access across multiple applications.

---

## Features

✅ **Centralized Authentication** – Single sign-on across multiple applications with one secure identity provider.  
✅ **OAuth Login** – Authenticate users via trusted third-party providers (e.g., Google), with account linking and access control.  
✅ **Two-Factor Authentication (2FA)** – Supports email OTP, time-based OTP (TOTP), and token verification  
✅ **Service Registry & Access Control** –  Register and manage services that support login via the CAS server  
✅ **Audit & Security Events** –  Track authentication events such as logins, 2FA attempts, and service authorizations.  

---

## Getting Started

### 1. Clone and Build the Repository
```bash
git clone https://github.com/khanghh/kauth.git
cd kauth
make
```

### 2. Configure the Application
Copy the example configuration file and edit it to match your environment:
```bash
cp config.example.yaml config.yaml
```

### 3. Set Up Environment and Run
Ensure MySQL and Redis are running, then start the server:
```bash
./build/bin/kauth --config ./config.yaml
```
## Configuration
Edit the config.yaml file to define:

```yaml
debug: false
baseURL: http://localhost:3000
listenAddr : ":3000" 
staticDir: "./static"
templateDir: "./templates"
allowOrigins: 
 - http://localhost:8080

session:
  sessionMaxAge: "24h"
  cookieName: "sid"
  cookieSecure: false
  cookieHttpOnly: true

redisURL: redis://default:123456@localhost:6379/0

mysql:
  dsn: user:password@tcp(localhost:3306)/kauth?charset=utf8mb4&parseTime=True&loc=Local
  maxIdleConns: 10
  maxOpenConns: 10
  connMaxIdleTime: 10
  connMaxLifetime: 10

authProviders: 
  oauth:
    google:
      clientId: xxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.apps.googleusercontent.com
      clientSecret: xxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxx
    discord:
      clientId: xxxxxxx
      clientSecret: xxxxxx

mail:
  backend: smtp
  smtp:
    host: smtp.example.com
    port: 587
    username: admin@example.com
    password: password
    from: noreply@example.com
    tls: true
    certFile: "./cert.pem"
    keyFile: "./keypem"
    caFile: "./ca.pem"

captcha:
  provider: turnstile
  turnstile:
    siteKey: "YOUR_TURNSTILE_SITE_KEY"
    secretKey: "YOUR_TURNSTILE_SECRET_KEY"
```

## 🖥️ Screenshots
<p float="left">
  <img src="https://github.com/khanghh/kauth/blob/screenshots/recent-activities.png?raw=true" width="49%"> 
  <img src="https://github.com/khanghh/kauth/blob/screenshots/2fa-settings.png?raw=true" width="49%"> 
</p>

---

## Contributing

Pull requests are welcome!
For major changes, please open an issue first to discuss what you’d like to change.

**Bug Reports & Feature Requests**

Please use the issue tracker to report bugs or request new features.

## License

This project is licensed under the MIT License.
See the [LICENSE](LICENSE.txt) file for details.

## Acknowledgements

- [Go](https://golang.org/)
- [MySQL](https://www.mysql.com/)
- [Redis](https://redis.io/)
- [go-fiber](https://github.com/gofiber/fiber)
