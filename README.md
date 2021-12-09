# AES-CBC
Library provides encrypting and decrypting functions using AES CBC encryption

## Usage

```
import "github.com/antonzhukov/aes-cbc"

...

    key, err := cbc.GenerateKey()
    if err != nil {
        t.Errorf("getKey() failed: %s", err.Error())
    }
    encrypted, err := cbc.Encrypt(key, []byte("Hello World"))
    if err != nil {
        t.Errorf("encrypt() failed: %s", err.Error())
    }
    decrypted, err := cbc.Decrypt(key, encrypted)
    if err != nil {
        t.Errorf("decrypt() failed: %s", err.Error())
    }
```