package umbral

import (
	"testing"
	"goUmbral/crypto"
	"math/big"
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
