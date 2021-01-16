package main

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

func newUser(username string, password string, acls []string) *user {
	salt := make([]byte, 32)
	io.ReadFull(rand.Reader, salt)
	xpass := sha512.Sum512([]byte(password + username))
	hash := argon2.IDKey(xpass[:], salt, 1, 512, 4, 32)
	return &user{
		Username:   username,
		PassHash:   base64.RawURLEncoding.EncodeToString(hash),
		Salt:       base64.RawURLEncoding.EncodeToString(salt),
		LastSignin: time.Now(),
		ACLS:       strings.Join(acls, "$"),
	}
}
