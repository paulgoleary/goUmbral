package umbral

import (
	"testing"
	"reflect"
)

func TestAPIBasics(t *testing.T) {

	cxt := MakeDefaultContext()

	privKeyAlice := GenPrivateKey(cxt)
	pubKeyAlice := privKeyAlice.GetPublicKey(cxt)

	privKeyBob := GenPrivateKey(cxt)
	pubKeyBob := privKeyBob.GetPublicKey(cxt)

	plainText := []byte("attack at dawn")
	cipherText, capsule := Encrypt(cxt, pubKeyAlice, plainText)

	testDecrypt := DecryptDirect(cxt, capsule, privKeyAlice, cipherText)

	if !reflect.DeepEqual(plainText, testDecrypt) {
		t.Errorf( "Direct decryption failed")
	}

	kFrags := SplitReKey(cxt, privKeyAlice, pubKeyBob, 1, 1 )

	cFrags := make([]*CFrag, len(kFrags))
	for i := range kFrags {
		cFrags[i] = ReEncapsulate(kFrags[i], capsule)
	}

	testDecryptFrags := DecryptFragments(cxt, capsule, privKeyBob, pubKeyAlice, cipherText)
	println(testDecryptFrags)
}
