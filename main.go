package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const keyLength = 32

func main() {
	// Define command line flags
	encryptCmd := flag.Bool("encrypt", false, "Encrypt enviroment variables")
	decryptCmd := flag.Bool("decrypt", false, "Decrypt enviroment variables")
	keyCmd := flag.Bool("genkey", false, "Generate a new encryption key")
	keyFlag := flag.String("key", "", "Encryption key (required for encryption/decryption)")
	outputFlag := flag.String("output", "", "Output file (optional, default is stdout)")
	keyFileFlag := flag.String("keyfile", "", "Output file (optional, default is stdout)")
	passwordProtect := flag.Bool("password", false, "Password protect the key file")

	flag.Parse()

	args := flag.Args()

	// Basic commad validation
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

	// Handle command execution
	if *keyCmd {
		// Generate and print a new encryption key
		key := generateKey()
		encodedKey := base64.StdEncoding.EncodeToString(key)
		fmt.Println("Generated encryption key (save this securely):")
		fmt.Println(encodedKey)

		// Check if a file path was provided to save the key
		if *keyFileFlag != "" {
			if *passwordProtect {
				// Get password from user
				fmt.Print("Enter password to protect ket file: ")
				password, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				if err != nil {
					fmt.Println("Error reading password: %v\n", err)
					return
				}

				fmt.Print("Confirm password: ")
				confirmPassword, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				if err != nil {
					fmt.Printf("Error reading password: %v\n", err)
					return
				}

				if string(password) != string(confirmPassword) {
					fmt.Println("Passwords don't match")
					return
				}

				// encrypt the key with the password
				encryptedKey, err := encryptWithPassword([]byte(encodedKey), password)
				if err != nil {
					fmt.Printf("Error encrypting key: %v\n", err)
					return
				}

				// Save encrypted key
				err = os.WriteFile(*keyFileFlag, []byte(encryptedKey), 0600)
				if err != nil {
					fmt.Printf("Error saving key to file: %v\n", err)
				} else {
					fmt.Printf("Password-protected key saved to %s\n", *keyFileFlag)
				}
			} else {
				// Save the key to the specified file with restricted permissions
				err := os.WriteFile(*keyFileFlag, []byte(encodedKey), 0600) // Read/write for owner only
				if err != nil {
					fmt.Printf("Error saving key to file: %v\n", err)
				} else {
					fmt.Printf("Encryption key saved to: %s\n", *keyFileFlag)
				}
			}
		}

		fmt.Println("\nYou can use this key with the -key flag or set it as ENV_ENCRYPTION_KEY environment variable")
		return
	}

	// Get encryption key
	var key []byte
	var err error

	if *keyFlag != "" {
		// use key from command line flag
		key, err = base64.StdEncoding.DecodeString(*keyFlag)
	} else if *keyFileFlag != "" {
		// Try to load key from file
		keyData, err := os.ReadFile(*keyFileFlag)
		if err != nil {
			fmt.Printf("Error reading key file: %v\n")
			os.Exit(1)
		}

		keyStr := string(keyData)

		// Check if the key is password-protected (it won't be valid base64)
		_, decodeErr := base64.StdEncoding.DecodeString(keyStr)
		if decodeErr != nil {
			// Key appears to be password-protected
			fmt.Print("Enter password to decrypt key file: %v\n")
			password, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				fmt.Printf("Error reading password: %v\n", err)
				os.Exit(1)
			}

			decryptedKey, err := decryptWithPassword(keyStr, password)
			if err != nil {
				fmt.Printf("Error decrypting key (wrong password): %v\n", err)
				os.Exit(1)
			}
			keyStr = string(decryptedKey)
		}

		key, err = base64.StdEncoding.DecodeString(keyStr)
		if err != nil {
			fmt.Printf("Invalid key format in file: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Try to get key from enviroment varible
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

	// Validate key length
	if len(key) != keyLength {
		fmt.Printf("Error: encryption key must be %d bytes (got %d bytes)\n", keyLength, len(key))
		os.Exit(1)
	}

	// Set up output
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

	// Process enviroment variables
	if *encryptCmd {
		// Format: NAME=VALUE
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

// generateKey creates a new random encryption key
func generateKey() []byte {
	key := make([]byte, keyLength)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err.Error())
	}
	return key
}

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

// decrypt takes a base64-encoded encrypted string and key, returns decrypted string
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
