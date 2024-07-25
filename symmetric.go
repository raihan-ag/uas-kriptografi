package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"bufio"
)

// Fungsi untuk enkripsi menggunakan AES
func encrypt(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Fungsi untuk dekripsi menggunakan AES
func decrypt(ciphertext string, key []byte) (string, error) {
	ciphertextBytes, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertextBytes) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext terlalu pendek")
	}
	iv := ciphertextBytes[:aes.BlockSize]
	ciphertextBytes = ciphertextBytes[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertextBytes, ciphertextBytes)

	return string(ciphertextBytes), nil
}

func main() {
	key := []byte("examplekey123456") // 16 bytes key untuk AES-128

	// Membaca input plaintext dari pengguna
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Masukkan teks yang ingin dienkripsi: ")
	plaintext, _ := reader.ReadString('\n')

	// Mengenkripsi plaintext
	ciphertext, err := encrypt(plaintext, key)
	if err != nil {
		fmt.Println("Error enkripsi:", err)
		return
	}
	fmt.Println("Ciphertext:", ciphertext)

	// Mendekripsi ciphertext
	decryptedText, err := decrypt(ciphertext, key)
	if err != nil {
		fmt.Println("Error dekripsi:", err)
		return
	}
	fmt.Println("Decrypted text:", decryptedText)
}
