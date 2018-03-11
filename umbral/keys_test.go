package umbral

import (
	"testing"
	"goUmbral/crypto"
	"math/big"
	"encoding/base64"
)

// TODO: implement serde functions and test ...

func TestBasics(t *testing.T) {
	cxt := MakeDefaultContext()
	testPrivKey := GenPrivateKey(cxt)

	if !(testPrivKey.GetMod() == cxt.curveField.FieldOrder) {
		t.Errorf("Trivial test - generated key should have same order as specified field")
	}

	testPubKey := testPrivKey.GetPublicKey(cxt)
	if testPubKey.IsInf() {
		t.Errorf("Trivial test - derived public key should be valid (non-inf)")
	}
}

func TestKeyToBytes(t *testing.T) {
	testField := crypto.MakeSecp256k1()

	testX, _ := big.NewInt(0).SetString("47562691317070847468022097844632650133098817998180866487247995040060529430665", 10)
	testY, _ := big.NewInt(0).SetString("89179178472444449832801213632708383777709824238364572095136102025536035486433", 10)

	testKey := UmbralPublicKey{*testField.MakeElement(testX, testY)}

	encExpect := "A2knh3_D6FcwLcny1dZCHGSRI17UHl9rgFlkH9gG_9CJ"

	result := testKey.toBytes(true)
	encResult := base64.URLEncoding.EncodeToString(result)
	if encExpect != encResult {
		t.Errorf("Encoded compressed point not compatible: expect '%s', got '%s'", encExpect, encResult)
	}
}
