package util

import (
	"crypto/rand"
	"encoding/base64"
)

const encodeURL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-."

// ServerName 256 bit
func ServerName() string {
	var data = make([]byte, 32)
	rand.Read(data)
	encoding := base64.NewEncoding(encodeURL)
	v := encoding.EncodeToString(data)
	return v
}
