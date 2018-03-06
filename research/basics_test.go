package research

import (
	"testing"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"goUmbral/crypto"
	"goUmbral/field"
)

var secp256k1 *elliptic.CurveParams

// cribbed from https://play.golang.org/p/4T0dfjoVnm
// TODO: don't know if i need this...
func makeSecp256k1Params() *elliptic.CurveParams  {
	secp256k1 = new(elliptic.CurveParams)
	secp256k1.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	secp256k1.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	secp256k1.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	secp256k1.Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	secp256k1.Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	secp256k1.BitSize = 256

	b, _ := big.NewInt(0).SetString("AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522", 16)

	k, err := secp256k1.ScalarBaseMult(b.Bytes())
	fmt.Println("Acquired Values:", k, err)
	fmt.Println("Expected Values: 23960696573610029253367988531088137163395307586261939660421638862381187549638 5176714262835066281222529495396963740342889891785920566957581938958806065714")
	return secp256k1
}

func TestUmbralBasics(t *testing.T) {

	curve := crypto.MakeSecp256k1()

	// these test values were lifted from a test run of pyUmbral, using the Secp256k1 curve
	testPrivKey, _ := new(big.Int).SetString("105749124218559003340042447088256087476338141549671889717442884680249208242835", 10)
	expectXPublic, _ := new(big.Int).SetString("15252548197152981137808455918108515211139706004457180447117952272837885536450", 10)
	expectYPublic, _ := new(big.Int).SetString("102397219317300099176446148571623407962489503529490854693424425530330736754983", 10)

	expectPublicKey := curve.MakeElement(expectXPublic, expectYPublic)

	calcPublicKey := curve.GetGen().MulScalar(testPrivKey)
	field.Trace(calcPublicKey)

	if !calcPublicKey.IsValEqual(expectPublicKey) {
		t.Errorf("Invalid public key compat result: expected %s, got %s", expectPublicKey, calcPublicKey)
	}
}
