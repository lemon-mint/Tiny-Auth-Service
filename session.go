package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
)

type session struct {
	SessionID string   `json:"sessionid"`
	TimeStamp string   `json:"ts"`
	ACLS      []string `json:"acls"`
}

func getCRand() string {
	buf := make([]byte, 16)
	io.ReadFull(rand.Reader, buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

func encodeSession(data session) []byte {
	d, _ := json.Marshal(data)
	return d
}

func decodeSession(data []byte) (session, error) {
	s := new(session)
	err := json.Unmarshal(data, s)
	if err != nil {
		return session{}, err
	}
	return *s, nil
}
