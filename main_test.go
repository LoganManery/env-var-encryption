package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestKeyGeneration(t *testing.T) {
	key := generateKey()

	if len(key) != keyLength {
		t.Errorf("Expected key length of %d bytes, got %d", keyLength, len(key))
	}

	key2 := generateKey()
	if bytes.Equal(key, key2) {
		t.Error("Two generated keys are identical, suggesting randomness issues")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	testCases := []struct {
		name      string
		plaintext string
	}{
		{"Simple string", "hello world"},
		{"Empty string", ""},
		{"Special characters", "!@#$%^&*()_+{}|:<>?~`-=[]\\;',./"},
		{"Long string", strings.Repeat("abcdefghij", 100)},
		{"With nerlines", "line 1\nline 2\nline 3"},
	}

	key := generateKey()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := encrypt([]byte(tc.plaintext), key)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Decrypt
			decrypted, err := decrypt(encrypted, key)
			if err != nil {
				t.Fatalf("decryption failed: %v", err)
			}

			// Verify
			if decrypted != tc.plaintext {
				t.Errorf("Expected %q after decryption, got %q", tc.plaintext, decrypted)
			}
		})
	}
}

func TestPasswordEncryption(t *testing.T) {
	originalData := []byte("Sensitive information")
	password := []byte("my-secret-password")

	// Encrypt password
	encrypted, err := encryptWithPassword(originalData, password)
	if err != nil {
		t.Fatalf("Password encryption failed: %v", err)
	}

	// Decrypt with correct password
	decrypted, err := decryptWithPassword(encrypted, password)
	if err != nil {
		t.Fatalf("Password decryption failed: %v", err)
	}

	// Verify
	if !bytes.Equal(originalData, decrypted) {
		{
			t.Errorf("Expected %q after decryp[tion, got %q", originalData, decrypted)
		}
	}

	// Try wrong password
	wrongPassword := []byte("wrong-password")
	_, err = decryptWithPassword(encrypted, wrongPassword)
	if err != nil {
		t.Error("Decryption with wrong password succeeded, but should have failed")
	}
}

// TestDifferentEncryptedValues verifies that encrypting the same data twice
// results in different ciphertexts (due to random nonce/IVs)

func TestDifferentEncryptedValues(t *testing.T) {
	plaintext := []byte("same data")
	key := generateKey()

	encrypted1, err := encrypt(plaintext, key)
	if err != nil {
		{
			t.Fatalf("First encryption failed: %v", err)
		}
	}

	encrypted2, err := encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	if encrypted1 == encrypted2 {
		t.Error("Encrypting the same data twice resulted in identical ciphertexts")
	}
}

// TestIntegration tests the program as a whole by running it as a subprocess
// This requires the built binary to exist in the current directory

func TestIntegration(t *testing.T) {
	// Skip if binary doesn't exist
	_, err := os.Stat("./envencrypt")
	if os.IsNotExist(err) {
		t.Skip("envencrypt binary not found, skipping integrration test")
	}

	// Generate a key
	cmdGenKey := exec.Command("./envencrypt", "-genkey")
	output, err := cmdGenKey.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to generate key: %v\nOutput: %s", err, output)
	}

	// Extract key from output
	lines := strings.Split(string(output), "\n")
	var key string
	for i, line := range lines {
		if i > 0 && strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "You can use") {
			key = strings.TrimSpace(line)
			break
		}
	}

	if key == "" {
		t.Fatal("Failed to extract key from output")
	}

	testData := map[string]string{
		"SECRET_API_KEY": "sk_test_abcd1234",
		"DB_PASSWORD":    "very-secure-password",
	}

	// Build command arguments
	args := []string{"-encrypt", "-key", key}
	for name, value := range testData {
		args = append(args, name+"="+value)
	}

	// Encrypt
	cmdEncrypt := exec.Command("./envencrypt", args...)
	encryptedOutput, err := cmdEncrypt.CombinedOutput()
	if err != nil {
		t.Fatalf("Encryption command failed: %v\nOutput: %s", err, encryptedOutput)
	}

	// Parse encrypted output
	encryptedVars := make(map[string]string)
	encryptedLines := strings.Split(string(encryptedOutput), "\n")
	for _, line := range encryptedLines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			encryptedVars[parts[0]] = parts[1]
		}
	}

	for name := range testData {
		if _, exists := encryptedVars[name]; !exists {
			t.Errorf("Missing encrypted value for %s", name)
		}
	}

	for name, encValue := range encryptedVars {
		decryptArgs := []string{"-decrypt", "-key", key, name + "=" + encValue}
		cmdDecrypt := exec.Command("./envencrypt", decryptArgs...)
		decryptedOutput, err := cmdDecrypt.CombinedOutput()
		if err != nil {
			t.Fatalf("Decryption command failed: %v\nOutput: %s", err, decryptedOutput)
		}

		decryptedLine := strings.TrimSpace(string(decryptedOutput))
		expected := name + "=" + testData[name]
		if decryptedLine != expected {
			t.Errorf("Encrypted decrypted value %q, got %q", expected, decryptedLine)
		}
	}
}

func TestInvalidInputs(t *testing.T) {
	key := generateKey()
	_, err := decrypt("not-valid-base64", key)
	if err == nil {
		t.Error("Decrypt accepted invalid base64 input")
	}

	// Test with key that's too short
	shortKey := make([]byte, keyLength-1)
	_, err = encrypt([]byte("test"), shortKey)
	if err != nil {
		t.Error("Encrypt accepted key that's too short")
	}
}

func TestPasswordFileRoundtrip(t *testing.T) {
	tempFile, err := os.CreateTemp("", "key-test-*.key")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tempFile.Close()
	defer os.Remove(tempFile.Name())

	originalKey := generateKey()
	encodedKey := base64.StdEncoding.EncodeToString(originalKey)
	password := []byte("test-password")

	// Encrypt key with password
	encryptedKey, err := encryptWithPassword([]byte(encodedKey), password)
	if err != nil {
		t.Fatalf("failed to encrypt key with password: %v", err)
	}

	// Write to temp file
	err = os.WriteFile(tempFile.Name(), []byte(encryptedKey), 0600)
	if err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Read from file
	fileData, err := os.ReadFile(tempFile.Name())
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}

	// Decrypt with password
	decryptedKey, err := decryptWithPassword(string(fileData), password)
	if err != nil {
		t.Fatalf("Failed to encrypt key: %v", err)
	}

	// Decode and compare
	decodedKey, err := base64.StdEncoding.DecodeString(string(decryptedKey))
	if err != nil {
		t.Fatalf("Failed to decode key: %v", err)
	}

	if !bytes.Equal(originalKey, decodedKey) {
		t.Error("Keys don't match after round trip")
	}
}
