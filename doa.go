package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base32"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	keyLength    = 32
)

func deriveKey(password, salt []byte) []byte {
	argonKey := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, keyLength)
	hkdfReader := hkdf.New(sha512.New, argonKey, salt, []byte("onion_key_derivation"))
	finalKey := make([]byte, keyLength)
	if _, err := hkdfReader.Read(finalKey); err != nil {
		panic(err)
	}
	return finalKey
}

func generateDeterministic(password, salt []byte) (ed25519.PublicKey, ed25519.PrivateKey) {
        seed := deriveKey(password, salt)
        publicKey, privateKey, err := ed25519.GenerateKey(bytes.NewReader(seed))
        if err != nil {
            panic(err)
        }
        return publicKey, privateKey
}



func expandSecretKey(secretKey ed25519.PrivateKey) [64]byte {
	hash := sha512.Sum512(secretKey[:32])
	hash[0] &= 248
	hash[31] &= 127
	hash[31] |= 64
	return hash
}

func encodePublicKey(publicKey ed25519.PublicKey) string {
	var checksumBytes bytes.Buffer
	checksumBytes.Write([]byte(".onion checksum"))
	checksumBytes.Write([]byte(publicKey))
	checksumBytes.Write([]byte{0x03})
	checksum := sha3.Sum256(checksumBytes.Bytes())

	var onionAddressBytes bytes.Buffer
	onionAddressBytes.Write([]byte(publicKey))
	onionAddressBytes.Write([]byte(checksum[:2]))
	onionAddressBytes.Write([]byte{0x03})
	onionAddress := base32.StdEncoding.EncodeToString(onionAddressBytes.Bytes())

	return strings.ToLower(onionAddress)
}

func save(onionAddress string, publicKey ed25519.PublicKey, secretKey [64]byte) {
	os.MkdirAll(onionAddress, 0700)

	secretKeyFile := append([]byte("== ed25519v1-secret: type0 ==\x00\x00\x00"), secretKey[:]...)
	if err := ioutil.WriteFile(onionAddress+"/hs_ed25519_secret_key", secretKeyFile, 0600); err != nil {
		panic(err)
	}

	publicKeyFile := append([]byte("== ed25519v1-public: type0 ==\x00\x00\x00"), publicKey...)
	if err := ioutil.WriteFile(onionAddress+"/hs_ed25519_public_key", publicKeyFile, 0600); err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile(onionAddress+"/hostname", []byte(onionAddress+".onion\n"), 0600); err != nil {
		panic(err)
	}
}

func main() {
	password := flag.String("p", "", "Password for key generation")
	salt := flag.String("s", "", "Salt for key generation")
	flag.Parse()

	if *password == "" || *salt == "" {
		fmt.Println("Password (-p) and salt (-s) are required")
		flag.Usage()
		os.Exit(1)
	}

	publicKey, privateKey := generateDeterministic([]byte(*password), []byte(*salt))
	onionAddress := encodePublicKey(publicKey)

	fmt.Printf("Deterministic Onion Address: %s.onion\n", onionAddress)
	save(onionAddress, publicKey, expandSecretKey(privateKey))
}
