package umbral

import (
	"testing"
	"goUmbral/crypto"
)

// TODO: implement serde functions and test ...

func TestBasics(t *testing.T) {
	testField := crypto.MakeSecp256k1()
	testPrivKey := GenPrivateKey(testField)

	if !(testPrivKey.ElemField.FieldOrder == testField.GetTargetField().FieldOrder) {
		t.Errorf("Trivial test - generated key should have same order as target field of specified field")
	}

	testPubKey := testPrivKey.GetPublicKey(testField)
	if testPubKey.IsInf() {
		t.Errorf("Trivial test - derived public key should be valid (non-inf)")
	}
}
