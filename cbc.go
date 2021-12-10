package cbc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/pkg/errors"
)

func Encrypt(key, content []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("NewCipher failed: %s", err.Error())
	}
	var iv [16]byte
	ecb := cipher.NewCBCEncrypter(block, iv[:])
	content = PKCS5Padding(content, block.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)

	return crypted, nil
}

func Decrypt(key []byte, ciphertext []byte) (b []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic recovered: %v", r)
		}
	}()
	var iv [16]byte
	c, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("NewCipher failed: %s", err.Error())
	}
	cbc := cipher.NewCBCDecrypter(c, iv[:])
	plain := make([]byte, len(ciphertext))
	cbc.CryptBlocks(plain, ciphertext)

	return PKCS5Trimming(plain), err
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	if len(encrypt)-int(padding) < 0 {
		return nil
	}
	return encrypt[:len(encrypt)-int(padding)]
}

func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.Wrap(err, "Read failed")
	}
	return key, nil
}
