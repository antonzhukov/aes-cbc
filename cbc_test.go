package cbc

import (
	"encoding/hex"
	"testing"
)

func Test_encrypt_e2e(t *testing.T) {
	tests := []struct {
		name      string
		plaintext string
	}{
		{
			"happy path",
			"All is good here, any text could be encrypted",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateKey()
			if err != nil {
				t.Errorf("getKey() failed: %s", err.Error())
			}
			got, err := Encrypt(key, []byte(tt.plaintext))
			if err != nil {
				t.Errorf("encrypt() failed: %s", err.Error())
			}
			res, err := Decrypt(key, got)
			if err != nil {
				t.Errorf("decrypt() failed: %s", err.Error())
			}
			if string(res) != tt.plaintext {
				t.Errorf("test failed. Expected %s, got %s", tt.plaintext, string(res))
			}
		})
	}
}

func Test_encrypt_decrypt(t *testing.T) {
	tests := []struct {
		name      string
		plaintext string
		key       string
		want      string
	}{
		{
			name:      "simple example",
			plaintext: "hello world!",
			key:       "3faa209856518a53411d93c76c44ca73c02daae1bda71ded958d82f9c1ea8ff2",
			want:      "f37b5ec2133abf48ebad8fe1c2d964cb",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := hex.DecodeString(tt.key)
			if err != nil {
				t.Errorf("DecodeString() failed: %s", err.Error())
			}
			bin, err := Encrypt(key, []byte(tt.plaintext))
			if err != nil {
				t.Errorf("Encrypt failed: %s", err.Error())
			}
			got := hex.EncodeToString(bin)
			if got != tt.want {
				t.Errorf("EncodeToString. Expected %s, got %s", tt.want, got)
			}

			res, err := Decrypt(key, bin)
			if err != nil {
				t.Errorf("decrypt() failed: %s", err.Error())
			}

			if string(res) != tt.plaintext {
				t.Errorf("test failed. Expected %s, got %s", tt.plaintext, string(res))
			}

		})
	}
}
