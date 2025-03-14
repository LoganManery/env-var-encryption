package main

import (
	"crypto/rand"

	"io"
)

// generateKey creates a new random encryption key
func generateKey() []byte {
	key := make([]byte, keyLength)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err.Error())
	}
	return key
}
