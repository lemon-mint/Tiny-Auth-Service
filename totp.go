package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"math"
	"strconv"
	"strings"
	"time"
)

func totpVerify(key string, input string, counter string) (success bool, newcounter string) {
	rawkey, err := base32.StdEncoding.DecodeString(key)
	if err != nil {
		return false, counter
	}
	mac := hmac.New(sha1.New, rawkey)
	currentTime := math.Floor(float64(time.Now().UTC().Unix() / 30))
	timebuf := make([]byte, 8)
	binary.BigEndian.PutUint64(timebuf, uint64(currentTime))
	mac.Write(timebuf)
	hmacResult := mac.Sum(nil)
	offset := int(hmacResult[19] & 0xf)
	bincode := int(
		(int(hmacResult[offset]&0x7f))<<24 |
			(int(hmacResult[offset+1]&0xff))<<16 |
			(int(hmacResult[offset+2]&0xff))<<8 |
			(int(hmacResult[offset+3] & 0xff)),
	)
	code := strconv.Itoa(bincode % 1000000)
	code = strings.Repeat("0", 6-len(code)) + code
	codeRune := []rune(code)
	inputRune := []rune(input)
	RuneEQ := true
	for i := 0; i < 6; i++ {
		if codeRune[i] != inputRune[i] {
			RuneEQ = false
		}
	}
	if !RuneEQ {
		return RuneEQ, counter
	}
	return RuneEQ, code
}
