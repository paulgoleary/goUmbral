package umbral

import (
	"crypto/cipher"
	"goUmbral/field"
	"golang.org/x/crypto/chacha20poly1305"
	"log"
)

type DEM struct {
	cipher.AEAD
	noncer func() []byte
}

func MakeDEM(key []byte) *DEM {

	theCypher, err := chacha20poly1305.New(key)
	if err != nil {
		log.Panicf("Failed to init DEM w/ chacha20poly1305: %v", err)
	}
	noncer := func() []byte { return field.GetRandomBytes(chacha20poly1305.NonceSize) }
	return &DEM{theCypher, noncer}
}

// only for testing yo
func (d *DEM) setTestNonce(testNonce []byte) {
	d.noncer = func() []byte { return testNonce }
}

func (d *DEM) encrypt(plainText, authData []byte) []byte {
	nonce := d.noncer()
	dst := make([]byte, 0) // let chacha decide the size ...
	return append(nonce, d.AEAD.Seal(dst, nonce, plainText, authData)...)
}

func (d *DEM) decrypt(cipherBytes, authData []byte) []byte {
	nonce := cipherBytes[:chacha20poly1305.NonceSize]
	dst := make([]byte, 0) // let chacha decide the size ...
	dst, err := d.AEAD.Open(dst, nonce, cipherBytes[chacha20poly1305.NonceSize:], authData)
	if err != nil {
		log.Panicf("Failed DEM decryption")
	}
	return dst
}
