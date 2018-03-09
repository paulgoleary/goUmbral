package umbral

import (
	"testing"
	"goUmbral/crypto"
	"math/big"
	"reflect"
	"encoding/hex"
	"goUmbral/field"
)

func TestPreBasics(t *testing.T) {

	testField := crypto.MakeSecp256k1()

	testMinVal := getMinValSha512(testField)
	// expected val from pyUmbral
	expectMinVal, _ := big.NewInt(0).SetString("71195301480278335217902614543643724933430614355449737089222010364394701574464", 10)
	if testMinVal.Cmp(expectMinVal) != 0 {
		t.Errorf("Incompatible calc of CURVE_MINVAL_SHA512: expect %d, got %d", expectMinVal, testMinVal)
	}
}

func TestHashToModInt(t *testing.T) {

	testField := crypto.MakeSecp256k1()

	items := []([]byte){{0xDE, 0xAD, 0xBE, 0xEF}, {0xCA, 0xFE, 0xBA, 0xBE}}
	testResult := hashToModInt(testField, items)

	expectResult, _ := big.NewInt(0).SetString("25995041633682703655811824485328222867845357606727537858371991100866687428737", 10)

	// testing for compat with pyUmbral
	if testResult.GetValue().Cmp(expectResult) != 0 {
		t.Errorf("Incompatible calc of hash to mod in: expect %d, got %d", expectResult, testResult.GetValue())
	}
}

func makeTestKeys(testField *field.CurveField, i int64) (*field.ZElement, *UmbralPublicKey) {
	testElement := testField.GetTargetField().NewElement(big.NewInt(i))
	privKey := UmbralPrivateKey{*testElement}
	pubKey := privKey.GetPublicKey(testField)
	return testElement, pubKey
}

func TestKDF(t *testing.T) {

	testField := crypto.MakeSecp256k1()

	_, pubKey := makeTestKeys(testField, 7)

	keyLength := 32
	testData := kdf(&pubKey.CurveElement, keyLength)

	// testing for compat with pyUmbral
	expectData := []byte {
		0x65, 0x5e, 0x25, 0xcf, 0x51, 0x9b, 0x03, 0x85, 0xeb, 0x41, 0xea, 0x6c, 0xb1, 0xe1, 0xce, 0x34,
		0x54, 0x86, 0xab, 0x1f, 0x02, 0x08, 0x35, 0x6b, 0xb5, 0xe4, 0x09, 0x26, 0x47, 0xb4, 0xbc, 0xde}

	if !reflect.DeepEqual(expectData, testData) {
		t.Errorf("Incompatible calc of KDF: expect %d, got %d", expectData, testData)
	}
}

func TestCapsuleSer(t *testing.T) {

	testField := crypto.MakeSecp256k1()

	_, pubKey7 := makeTestKeys(testField, 7)

	testElement10k, pubKey10k := makeTestKeys(testField, 10 * 1000)

	expectSerStr := "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc037a36d7efeac579690f7b89c8982329303a02bd710bc87f4eaaf5cfd84c2f6fae0000000000000000000000000000000000000000000000000000000000002710"

	c := Capsule{pubKey7, pubKey10k, testElement10k}
	cSer := c.toBytes()
	cSerString := hex.EncodeToString(cSer)

	if expectSerStr != cSerString {
		t.Errorf("Incompatible serialization of Capsule: expect %d, got %d", expectSerStr, cSerString)
	}
}