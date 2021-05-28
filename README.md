# Tiny-Auth-Service
[![](https://goreportcard.com/badge/github.com/lemon-mint/Tiny-Auth-Service)](https://goreportcard.com/report/github.com/lemon-mint/Tiny-Auth-Service)

Multipurpose external authentication server made with Go


## Environment variable config

`TINY_AUTH_SERVICE_SECRET_KEY`: Secret key used to encrypt and sign cookies

(If not set, it will be generated automatically)

`TINY_AUTH_SERVICE_DATABASE_TYPE`: Specify the type of DB server storing user information. (Default: `sqlite3`)

`TINY_AUTH_SERVICE_CAPTCHA_ENABLE`: `true` or `false` (Default: `false`)

`TINY_AUTH_SERVICE_CAPTCHA_SITEKEY`: site key for recaptcha or hcaptcha

`TINY_AUTH_SERVICE_CAPTCHA_SECRETKEY`: site key for recaptcha or hcaptcha

`TINY_AUTH_SERVICE_CAPTCHA_VERIFY_URL`: 
(ex: `https://hcaptcha.com/siteverify` or `https://www.google.com/recaptcha/api/siteverify` or `https://www.recaptcha.net/recaptcha/api/siteverify`)

`TINY_AUTH_SERVICE_CAPTCHA_TYPE`: (`recaptcha` or `hcaptcha`)

`TINY_AUTH_SERVICE_INITDB_ADMIN_ID`

`TINY_AUTH_SERVICE_INITDB_ADMIN_PASSWORD`

# TODO 

- [x] signin
- [x] signup
- [ ] 2FA
