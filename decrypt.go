// decrypt takes a base64-encoded encrypted string and key, returns decrypted string
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"

	"encoding/base64"

	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

func decrypt(encryptedStr string, key []byte) (string, error) {
	// Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedStr)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func decryptWithPassword(encryptedStr string, password []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedStr)
	if err != nil {
		return nil, err
	}

	// Extract salt (first 16 bytes)
	if len(ciphertext) < 16 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	salt, ciphertext := ciphertext[:16], ciphertext[16:]

	// generate key from password using PBKDF2
	key := pbkdf2.Key(password, salt, 10000, 32, sha256.New)

	// Create a cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
