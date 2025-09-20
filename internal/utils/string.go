package utils

import (
	"crypto/md5"
	"encoding/hex"
)

func GetMd5(text string) string {
	// Create a new MD5 hash object
	hasher := md5.New()
	hasher.Write([]byte(text))
	hashBytes := hasher.Sum(nil)

	// Convert the byte slice to a hexadecimal string
	hashString := hex.EncodeToString(hashBytes)

	return hashString
}
