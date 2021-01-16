package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func verifyCaptcha(response string) bool {
	cType := "application/x-www-form-urlencoded"
	v := url.Values{}
	v.Set("response", response)
	v.Set("secret", os.Getenv("TINY_AUTH_SERVICE_CAPTCHA_SECRETKEY"))
	client := http.Client{}
	client.Timeout = time.Second * 10
	resp, err := client.Post(
		os.Getenv("TINY_AUTH_SERVICE_CAPTCHA_VERIFY_URL"),
		cType,
		strings.NewReader(v.Encode()),
	)
	if err != nil {
		return false
	}
	respdata, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	JSONResponse := new(struct {
		Success     bool   `json:"success"`
		ChallengeTs string `json:"challenge_ts"`
		HostName    string `json:"hostname"`
	})
	if json.Unmarshal(respdata, JSONResponse) != nil {
		return false
	}
	if !JSONResponse.Success {
		return false
	}
	return true
}
