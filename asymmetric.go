package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"bufio"
)

// Fungsi untuk enkripsi menggunakan kunci publik RSA
func encrypt(plaintext string, publicKey *rsa.PublicKey) (string, error) {
	label := []byte("")
	hash := sha256.New()

	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, []byte(plaintext), label)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Fungsi untuk dekripsi menggunakan kunci privat RSA
func decrypt(ciphertext string, privateKey *rsa.PrivateKey) (string, error) {
	label := []byte("")
	hash := sha256.New()

	ciphertextBytes, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, ciphertextBytes, label)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating keys:", err)
		return
	}
	publicKey := &privateKey.PublicKey

	// Membaca input plaintext dari pengguna
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Masukkan teks yang ingin dienkripsi: ")
	plaintext, _ := reader.ReadString('\n')

	// Mengenkripsi plaintext menggunakan kunci publik
	ciphertext, err := encrypt(plaintext, publicKey)
	if err != nil {
		fmt.Println("Error enkripsi:", err)
		return
	}
	fmt.Println("Ciphertext:", ciphertext)

	// Mendekripsi ciphertext menggunakan kunci privat
	decryptedText, err := decrypt(ciphertext, privateKey)
	if err != nil {
		fmt.Println("Error dekripsi:", err)
		return
	}
	fmt.Println("Decrypted text:", decryptedText)
}
