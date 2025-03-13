package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const keyLength = 32

func main() {
	// Define command line flags
	encryptCmd := flag.Bool("encrypt", false, "Encrypt enviroment variables")
	decryptCmd := flag.Bool("decrypt", false, "Decrypt enviroment variables")
	keyCmd := flag.Bool("genkey", false, "Generate a new encryption key")
	keyFlag := flag.String("key", "", "Encryption key (required for encryption/decryption)")
	outputFlag := flag.String("output", "", "Output file (optional, default is stdout)")

	flag.Parse()

	args := flag.Args()

	if *keyCmd && (*encryptCmd || *decryptCmd || *keyFlag != "" || len(args) > 0) {
		fmt.Println("Error: -genkkey should be used alone")
		os.Exit(1)
	}

	if *encryptCmd && *decryptCmd {
		fmt.Println("Error: cannot use bot -encrypt and -decrypt flags")
		os.Exit(1)
	}

	if (*encryptCmd || *decryptCmd) && *keyFlag == "" {
		fmt.Println("Error: encryption key is required. Use -key flag or set ENV_ENCRYPTION_KEY enviroment variable")
		os.Exit(1)
	}

	if *keyCmd {
		key := generateKey()
		encodedKey := base64.StdEncoding.EncodeToString(key)
		fmt.Println("Generated encryption key (save this securely):")
		fmt.Println(encodedKey)
		fmt.Println("\nYou can use this key with the -key flag or set it as ENV_ENCRYPTION_KEY environment variable")
		return
	}

	var key []byte
	var err error

	if *keyFlag != "" {
		// use key from command line flag
		key, err = base64.StdEncoding.DecodeString(*keyFlag)
	} else {
		// Try to get key from envrioment variable
		envKey := os.Getenv("ENV_ENCRYPTION_KEY")
		if envKey != "" {
			key, err = base64.StdEncoding.DecodeString(envKey)
		} else {
			fmt.Println("Error: encryption key not provided")
			os.Exit(1)
		}
	}
	if err != nil {
		fmt.Printf("Error decoding encryption key: %v\n", err)
		os.Exit(1)
	}

	if len(key) != keyLength {
		fmt.Printf("Error: encryption key must be %d bytes (got %d bytes)\n", keyLength, len(key))
		os.Exit(1)
	}

	var output *os.File
	if *outputFlag != "" {
		output, err = os.Create(*outputFlag)
		if err != nil {
			fmt.Printf("Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	if *encryptCmd {
		for _, arg := range args {
			parts := strings.SplitN(arg, "=", 2)
			if len(parts) != 2 {
				fmt.Printf("Warning: skipping invalid format for'%s. Use NAME=VALUE format.\n", arg)
				continue
			}

			name := parts[0]
			value := parts[1]

			encrypted, err := encrypt([]byte(value), key)
			if err != nil {
				fmt.Printf("Error encrypting %s: %v\n")
				continue
			}

			fmt.Fprintf(output, "%s=%s\n", name, encrypted)
		}
	} else if *decryptCmd {
		// Format: NAME=ENCRYPTED_VALUE
		for _, arg := range args {
			parts := strings.SplitN(arg, "=", 2)
			if len(parts) != 2 {
				fmt.Printf("Warning: skipping invalid format for '%s'. Use NAME=EXPECTED_VALUE format.\n", arg)
				continue
			}
			name := parts[0]
			encryptedValue := parts[1]

			decrypted, err := decrypt(encryptedValue, key)
			if err != nil {
				fmt.Printf("Error decrypting %s: %v\n", name, err)
				continue
			}
			fmt.Fprintf(output, "%s=%s\n", name, decrypted)
		}
	} else {
		fmt.Println("Please specify either -encrypt or -decrypt flag")
		flag.Usage()
		os.Exit(1)
	}
}

func generateKey() []byte {
	key := make([]byte, keyLength)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err.Error())
	}
	return key
}

func encrypt(plaintext, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(encryptedStr string, key []byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedStr)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

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
