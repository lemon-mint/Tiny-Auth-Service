package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
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

func main() {
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	dbConnect()
	e.File("/authserver/signin", "views/signin.html")
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
		Username string `form:"username" json:"username"`
		Password string `form:"password" json:"password"`
	})
	err := c.Bind(userC)
	if err != nil {
		return c.Redirect(http.StatusTemporaryRedirect, "/authserver/signin")
	}
	u := new(user)
	t := db.First(u, userC.Username)
	if t.Error != nil {
		return c.Redirect(http.StatusTemporaryRedirect, "/authserver/signin")
	}
	xpass := sha512.Sum512([]byte(userC.Password))
	hash := argon2.IDKey(xpass[:], parseBase64(u.Salt), 1, 512, 4, 32)
	if !bytes.Equal(hash, parseBase64(u.PassHash)) {
		return c.Redirect(http.StatusTemporaryRedirect, "/authserver/signin")
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
	return c.Redirect(http.StatusTemporaryRedirect, "/authserver/verify")
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
