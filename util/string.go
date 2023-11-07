package util

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
)

const encodeURL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-."

func ServerName() string {
	var data = make([]byte, 32)
	rand.Read(data)
	encoding := base64.NewEncoding(encodeURL)
	v := encoding.EncodeToString(data)
	v = strings.Trim(v, "=")
	return v
}
