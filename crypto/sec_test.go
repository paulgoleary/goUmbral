package crypto

import (
	"testing"
	"math/big"
)

// TODO: could be useful (?) to write some tests that check for correctness / compatibility against the go elliptic package implementations
// for now I'm going to focus on compatibility with pyUmbral. this curve field has been checked against a few external implementations - e.g. pbc and jpbc

func TestSecp256k1Basics(t *testing.T) {

	curve := MakeSecp256k1()

	b, _ := big.NewInt(0).SetString("AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522", 16)

	// cribbed from https://play.golang.org/p/4T0dfjoVnm
	// don't know where the author got the expected results but they check with our implementation.
	// interestingly, the point of the example seems to be to show that the standard go elliptic curve implementation is not compatible
	//  with Secp256k1, which is trivially true because - for reasons I don't grok (optimizations?) - the elliptic package only supports
	//  curves with fixed a = -3 where Secp256k1 requires a = 0.
	testX, _ := big.NewInt(0).SetString("23960696573610029253367988531088137163395307586261939660421638862381187549638", 10)
	testY, _ := big.NewInt(0).SetString("5176714262835066281222529495396963740342889891785920566957581938958806065714", 10)

	expectPoint := curve.MakeElement(testX, testY)

	k := curve.GetGen().MulScalar(b)

	if !k.IsValEqual(expectPoint) {
		t.Errorf("Invalid curve element mul result: expected %s, got %s", expectPoint, k)
	}
}
