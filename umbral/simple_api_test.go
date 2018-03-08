package umbral

import (
	"testing"
	"goUmbral/crypto"
	"goUmbral/field"
)

func TestAPIBasics(t *testing.T) {

	// TODO? explicit param object?
	testField := crypto.MakeSecp256k1()

	privKeyAlice := GenPrivateKey(testField)
	pubKeyAlice := privKeyAlice.GetPublicKey(testField)
	field.Trace(pubKeyAlice)

	privKeyBob := GenPrivateKey(testField)
	pubKeyBob := privKeyBob.GetPublicKey(testField)
	field.Trace(pubKeyBob)

	plainText := []byte("attack at dawn")
	_, _ = Encrypt(testField, pubKeyAlice, plainText)
}
