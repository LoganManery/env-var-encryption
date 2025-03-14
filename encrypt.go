package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"

	"encoding/base64"

	"io"

	"golang.org/x/crypto/pbkdf2"
)

// encrypt takes a plaintext and key, returns base64-encoded encrypted string
func encrypt(plaintext, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Create nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt and prepend nounce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Return as base64 encoded string
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// encryptWithPassword encrypts data using a password
func encryptWithPassword(data, password []byte) (string, error) {
	// Generate a salt
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	// Generate key from password using PBKDF2
	key := pbkdf2.Key(password, salt, 10000, 32, sha256.New)

	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil
	}

	// Create nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// Prepend salt to the ciphertext
	ciphertext = append(salt, ciphertext...)

	// Return as base64 encoded string
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
