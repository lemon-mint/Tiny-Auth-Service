# Tiny-Auth-Service
External authentication server made in Go to use Nginx's http_auth_request_module


# Environment variable config

`TINY_AUTH_SERVICE_SECRET_KEY`: Secret key used to encrypt and sign cookies

(If not set, it will be generated automatically)
