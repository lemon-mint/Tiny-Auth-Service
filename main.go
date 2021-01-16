package main

import (
	"crypto/rand"
	"io"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lemon-mint/godotenv"
	"github.com/lemon-mint/macaronsign"
)

var signer *macaronsign.Signer = func() *macaronsign.Signer {
	key := make([]byte, 64)
	io.ReadFull(rand.Reader, key)
	s := macaronsign.NewSigner(86400, key, 1, 1)
	return &s
}()

func main() {
	godotenv.Load()

	e := echo.New()
	e.Use(middleware.Logger())

	e.GET("/verify", verifySession)
	e.Logger.Fatal(e.Start(":18080"))
}

func verifySession(c echo.Context) error {
	type response struct {
		Success   bool   `json:"success"`
		Msg       string `json:"msg"`
		SessionID string `json:"id"`
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
	})
}
