package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"html/template"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lemon-mint/godotenv"
	"github.com/lemon-mint/macaronsign"
	"golang.org/x/crypto/argon2"
)

var signer *macaronsign.Signer = func() *macaronsign.Signer {
	godotenv.Load()
	key := make([]byte, 64)
	io.ReadFull(rand.Reader, key)
	if v, ok := os.LookupEnv("TINY_AUTH_SERVICE_SECRET_KEY"); ok {
		key = []byte(v)
	}
	s := macaronsign.NewSigner(86400, key, 1, 1)
	return &s
}()

func get(a string, backup string) string {
	if a != "" {
		return a
	}
	return backup
}

//Template wrapper
type Template struct {
	templates *template.Template
}

//Render template
func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func main() {
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	t := &Template{
		templates: template.Must(template.ParseGlob("views/*.html")),
	}
	e.Renderer = t
	dbConnect()
	//db.Create(newUser("admin", "qwerty001", []string{"user"}))
	e.GET("/authserver/signin", func(c echo.Context) error {
		return c.Render(
			http.StatusOK,
			"signin.html",
			map[string]interface{}{
				"captchaType": os.Getenv("TINY_AUTH_SERVICE_CAPTCHA_TYPE"),
				"sitekey":     os.Getenv("TINY_AUTH_SERVICE_CAPTCHA_SITEKEY"),
			},
		)
	})
	e.GET("/authserver/verify", verifySession)
	e.POST("/authserver/auth.go", signin)
	e.Logger.Fatal(e.Start(":18080"))
}

func parseBase64(a string) []byte {
	if a == "" {
		return []byte{}
	}
	data, _ := base64.RawURLEncoding.DecodeString(a)
	return data
}

func signin(c echo.Context) error {
	userC := new(struct {
		Username          string `form:"username" json:"username"`
		Password          string `form:"password" json:"password"`
		RecaptchaResponse string `form:"g-recaptcha-response" json:"g-recaptcha-response"`
		HCaptchaResponse  string `form:"h-captcha-response" json:"h-captcha-response"`
	})
	err := c.Bind(userC)
	if err != nil {
		return c.String(http.StatusForbidden, "Username or password do not match.")
	}
	if os.Getenv("TINY_AUTH_SERVICE_CAPTCHA_ENABLE") == "true" {
		if os.Getenv("TINY_AUTH_SERVICE_CAPTCHA_TYPE") == "recaptcha" {
			if !verifyCaptcha(userC.RecaptchaResponse) {
				return c.String(http.StatusForbidden, "Recaptcha Error")
			}
		} else if os.Getenv("TINY_AUTH_SERVICE_CAPTCHA_TYPE") == "hcaptcha" {
			if !verifyCaptcha(userC.HCaptchaResponse) {
				return c.String(http.StatusForbidden, "hCaptcha Error")
			}
		}
	}
	u := new(user)
	t := db.First(u, "username = ?", userC.Username)
	if t.Error != nil {
		return c.String(http.StatusForbidden, "Username or password do not match.")
	}
	xpass := sha512.Sum512([]byte(userC.Password + userC.Username))
	hash := argon2.IDKey(xpass[:], parseBase64(u.Salt), 1, 512, 4, 32)
	if !bytes.Equal(hash, parseBase64(u.PassHash)) {
		return c.String(http.StatusForbidden, "Username or password do not match.")
	}
	db.Model(u).Update("LastSignin", time.Now())
	c.SetCookie(&http.Cookie{
		Name: "_GOAUTHSSID",
		Value: signer.SignAndEncrypt(encodeSession(session{
			SessionID: getCRand(),
			TimeStamp: time.Now().UTC().String(),
			ACLS:      strings.Split(u.ACLS, "$"),
		})),
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
	})
	return c.String(http.StatusOK, "OK")
}

func verifySession(c echo.Context) error {
	type response struct {
		Success   bool     `json:"success"`
		Msg       string   `json:"msg"`
		SessionID string   `json:"id"`
		ACLS      []string `json:"acls"`
	}
	m, err := c.Cookie("_GOAUTHSSID")
	if err != nil {
		return c.JSON(http.StatusForbidden, response{
			Success: false,
			Msg:     "Unauthenticated User",
		})
	}
	d, err := signer.DecryptAndVerify(m.Value)
	if err != nil {
		return c.JSON(http.StatusForbidden, response{
			Success: false,
			Msg:     "Expired Session",
		})
	}
	s, err := decodeSession(d)
	if err != nil {
		return c.JSON(http.StatusForbidden, response{
			Success: false,
			Msg:     "Expired Session",
		})
	}
	return c.JSON(http.StatusOK, response{
		Success:   true,
		Msg:       "Verification was successful",
		SessionID: s.SessionID,
		ACLS:      s.ACLS,
	})
}
