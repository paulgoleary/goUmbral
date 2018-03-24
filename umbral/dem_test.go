package umbral

import (
	"goUmbral/field"
	"golang.org/x/crypto/chacha20poly1305"
	"reflect"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	testDEM(t, nil)
	testDEM(t, []byte("launch code 0000"))
}

func testDEM(t *testing.T, authData []byte) {

	key := field.GetRandomBytes(32)

	dem := MakeDEM(key)

	plaintext := []byte("attack at dawn")

	ciphertext0 := dem.encrypt(plaintext, authData)
	ciphertext1 := dem.encrypt(plaintext, authData)

	if reflect.DeepEqual(ciphertext0, ciphertext1) {
		t.Errorf("Same plaintext should encrypt to different ciphertext")
	}

	cleartext0 := dem.decrypt(ciphertext0, authData)
	cleartext1 := dem.decrypt(ciphertext1, authData)

	if !reflect.DeepEqual(plaintext, cleartext0) || !reflect.DeepEqual(plaintext, cleartext1) {
		t.Errorf("DEM did not decrypt to correct clear text")
	}
}

func TestPyUmbralCompat(t *testing.T) {

	testKey := []byte{
		0x72, 0x4d, 0x4a, 0xca, 0xa3, 0x1f, 0x42, 0xd7, 0x4d, 0x59, 0x28, 0xd5, 0x40, 0x9d, 0xa3, 0x24,
		0xee, 0x3b, 0xa4, 0x3d, 0xd2, 0x69, 0x7b, 0x7e, 0x9b, 0x7b, 0x2e, 0xa7, 0x57, 0x9b, 0x73, 0xfc}

	dem := MakeDEM(testKey)

	testEncrypt := []byte{
		0x5c, 0x13, 0x76, 0xd3, 0xbf, 0xd7, 0x27, 0xb6, 0x76, 0xbc, 0xdb, 0xbf, 0x2b, 0x9b, 0xab, 0x36,
		0x73, 0x51, 0x69, 0x4e, 0xbb, 0x1e, 0xf4, 0xe1, 0x76, 0x86, 0x35, 0xe8, 0xb5, 0x6e, 0x9b, 0xf4,
		0xbb, 0x7d, 0x66, 0xae, 0x1e, 0x36, 0x02, 0xbb, 0x7f, 0x68}

	testNonce := testEncrypt[:chacha20poly1305.NonceSize]
	dem.setTestNonce(testNonce)

	plaintext := []byte("attack at dawn")

	ciphertext := dem.encrypt(plaintext, nil)

	if !reflect.DeepEqual(ciphertext, testEncrypt) {
		t.Errorf("Failed compatible DEM encryption")
	}
}
