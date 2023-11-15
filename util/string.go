package util

import (
	"crypto/sha256"
	"encoding/hex"
)

// ServerName 256 bit
func ServerName(data []byte) string {
	v := sha256.Sum256(data)
	return hex.EncodeToString(v[0:])
}
