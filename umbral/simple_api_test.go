package umbral

import (
	"testing"
	"goUmbral/field"
	"reflect"
)

func TestAPIBasics(t *testing.T) {

	cxt := MakeDefaultContext()

	privKeyAlice := GenPrivateKey(cxt)
	pubKeyAlice := privKeyAlice.GetPublicKey(cxt)

	privKeyBob := GenPrivateKey(cxt)
	pubKeyBob := privKeyBob.GetPublicKey(cxt)
	field.Trace(pubKeyBob)

	plainText := []byte("attack at dawn")
	cipherText, capsule := Encrypt(cxt, pubKeyAlice, plainText)

	testDecrypt := Decrypt(cxt, capsule, privKeyAlice, cipherText)

	if !reflect.DeepEqual(plainText, testDecrypt) {
		t.Errorf( "Direct decryption failed")
	}
}
