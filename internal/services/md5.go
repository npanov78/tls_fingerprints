package app

import (
	"crypto/md5"
	"fmt"
)

// MD5 вычисляет MD5 хэш для строки
func MD5(data string) string {
	hasher := md5.New()
	hasher.Write([]byte(data))
	return fmt.Sprintf("%x", hasher.Sum(nil))
}
