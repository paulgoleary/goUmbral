package umbral

import (
	"testing"
	"goUmbral/crypto"
	"math/big"
	"reflect"
	"encoding/hex"
	"goUmbral/field"
	"fmt"
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

	cxt := MakeDefaultContext()

	items := []([]byte){{0xDE, 0xAD, 0xBE, 0xEF}, {0xCA, 0xFE, 0xBA, 0xBE}}
	testResult := hashToModInt(cxt, items)

	expectResult, _ := big.NewInt(0).SetString("25995041633682703655811824485328222867845357606727537858371991100866687428737", 10)

	// testing for compat with pyUmbral
	if testResult.GetValue().Cmp(expectResult) != 0 {
		t.Errorf("Incompatible calc of hash to mod in: expect %d, got %d", expectResult, testResult.GetValue())
	}
}

func makeTestKeys(cxt *Context, i int64) (*field.ZElement, *UmbralCurveElement) {
	testElement := cxt.targetField.NewElement(big.NewInt(i))
	privKey := UmbralFieldElement{*testElement}
	pubKey := privKey.GetPublicKey(cxt)
	return testElement, pubKey
}

func TestKDF(t *testing.T) {

	cxt := MakeDefaultContext()

	_, pubKey := makeTestKeys(cxt, 7)

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

	cxt := MakeDefaultContext()

	_, pubKey7 := makeTestKeys(cxt, 7)

	testElement10k, pubKey10k := makeTestKeys(cxt, 10 * 1000)

	expectSerStr := "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc037a36d7efeac579690f7b89c8982329303a02bd710bc87f4eaaf5cfd84c2f6fae0000000000000000000000000000000000000000000000000000000000002710"

	c := Capsule{pubKey7, pubKey10k, testElement10k}
	cSer := c.toBytes()
	cSerString := hex.EncodeToString(cSer)

	if expectSerStr != cSerString {
		t.Errorf("Incompatible serialization of Capsule: expect %s, got %s", expectSerStr, cSerString)
	}
}

func TestPoly(t *testing.T) {

	bigMod := big.NewInt(1000 * 1000)

	// trivial case
	// Evaluate f(x)=2x^3-6x^2+2x-1} for x=3
	coeffs := []*field.ModInt{
		field.MakeModInt(2, true, bigMod),
		field.MakeModInt(-6, true, bigMod),
		field.MakeModInt(2, true, bigMod),
		field.MakeModInt(-1, true, bigMod)}

	eval := hornerPolyEval(coeffs, field.MakeModInt(3, true, bigMod))
	expect := field.MakeModInt(5, true, bigMod)

	if !eval.IsValEqual(expect) {
		t.Errorf("Incorrect poly eval expected %v, got %v", expect, eval)
	}

}

func TestPolyCompat(t *testing.T) {

	cxt := MakeDefaultContext()

	// assume pyUmbal generates poly parameters like this, with the shamir secret at ordinal 0 ...
	compatCoeffs := []*field.ModInt {
		field.MakeModIntStr("07f7037578510daae683e3a0c230977b67c015ec817a9553c6f49e5f1b901dd9", 16, cxt.GetOrder()),
		field.MakeModIntStr("c639df1809706263ca78f613e016c0d392766ca6517199d618a7e765349a00c1", 16, cxt.GetOrder()),
		field.MakeModIntStr("d60ee33c1b6438494b493d4ead371ab8b5b10006b8411ee142e73605f19d856d", 16, cxt.GetOrder()),
		field.MakeModIntStr("0a1372445ab848d740b3a3c9316adfac0e452b7f7ab6e8b363e640004d97ff21", 16, cxt.GetOrder()),
		field.MakeModIntStr("4803e4cc7250576fdeaa0d2667d1bdf4bcd70c0b76adbc97f9d91bbc79f53aff", 16, cxt.GetOrder()),
	}

	// ... we evaluate from left to right with the secret at (here) ordinal 4
	testCoeffs := []*field.ModInt {compatCoeffs[4], compatCoeffs[3], compatCoeffs[2], compatCoeffs[1], compatCoeffs[0]}

	// the important part is that the secret is at the correct (i.e. constant) position in the evaluation

	testPolyEval := func (testIdStr string, expectRkString string) {
		testId := field.MakeModIntStr(testIdStr, 16, cxt.GetOrder())

		expectRk := field.MakeModIntStr(expectRkString, 16, cxt.GetOrder())
		calcRk := hornerPolyEval(testCoeffs, testId)

		if !calcRk.IsValEqual(expectRk) {
			t.Errorf("Incorrect compat poly eval expected %v, got %v", expectRk, calcRk)
		}
	}

	// input values and results derived from pyUmbral - validate that calc is the same

	testPolyEval("04ce5fb04b5c751c7223f5f30832285472952a3716baf4463181ba719de8b4e6",
		"97a70f529c273693657c6977bc81395fd416463eb435cf71e0413f8d48afe4b9")

	testPolyEval("7597081f9407fea226d97a1ff87b5d622adac49aa9c5ff6c41c76d3679026152",
		"52eb1301852cff46c71dcbf145d9e71b35ad0383ec58d7e30fda648c53b73712")

	testPolyEval("39262fcba3883418fed57eb3ab52e956f7f8f4c77fb4e819d3ff0383a0c33d17",
		"9dc31359fbfc62f521d6f280bb0be4daf0732aab7faf26dd954d4f451fda606d")

	testPolyEval("04589aa1f0b2f49beb68f425f4e5d2713656d4acf26cf4d24caeada1c5d71950",
		"9356564954a5bbd474785b416dfbe864261aabb47ba3b9117870f23cc664ca83")

	testPolyEval("f6065f0e116c91971615ebcb568c3ddaad0a1dc25ea952374bdfacc89a7b85c8",
		"df1e495dc8fb81119a86bec9ec15d308a162c9932dff52666858f780e2f59e75")
}

func TestCapDecap(t *testing.T) {

	cxt := MakeDefaultContext()

	alicePriv := MakePrivateKey(cxt,
		field.MakeModIntStr("706e365373416535326e73346573576847324b546a7862787978456e685452343736427a4e3830787070773d", 16, cxt.GetOrder()))
	alicePub := alicePriv.GetPublicKey(cxt)

	capKey, cap := encapsulate(cxt, alicePub)

	decapKey := decapDirect(cxt, alicePriv, cap)

	if !reflect.DeepEqual(decapKey, capKey ) {
		t.Errorf("Incorrect key cap/decap, expected %v, got %v", capKey, decapKey)
	}
}

type TestPoint struct {
	x *field.ModInt
	y *field.ModInt
}

func (tp TestPoint) String() string {
	return fmt.Sprintf("[%v, %v]", tp.x, tp.y)
}

func testShamirWithSecret(t *testing.T, cxt *Context, coeff0 *field.ModInt) {

	// make the coefficients ...
	// coeff0 is the 'secret'
	coeffs := makeShamirPolyCoeffs(cxt, coeff0, 10)

	// ... make and calc the points ...
	points := make([]TestPoint, 20)
	for i, _ := range points {
		points[i].x = field.MakeModIntRandom(cxt.GetOrder())
		points[i].y = hornerPolyEval(coeffs, points[i].x)
		field.Trace(points[i])
	}

	xs := make([]*field.ModInt, len(points) / 2)
	for i := 0; i < len(points); i += 2 {
		xs[i / 2] = points[i].x
	}

	calcSecret := field.MakeModInt(0, true, cxt.GetOrder())

	// ... now the testing. recover from complete subset of shares.
	for i := 0; i < len(points); i += 2 {
		lambda := calcLambdaCoeff(points[i].x, xs)
		calcSecret = calcSecret.Add(lambda.Mul(points[i].y))
	}

	if !coeff0.IsValEqual(calcSecret) {
		t.Errorf("Incorrect recovered secret value, expected %v, got %v", coeff0, calcSecret)
	}
}

func TestShamirs(t *testing.T) {

	cxt := MakeDefaultContext()

	testShamirWithSecret(t, cxt, field.MakeModInt(1, true, cxt.GetOrder()))

	for i := 0; i < 100; i++ {
		testSecret := field.MakeModIntRandom(cxt.GetOrder())
		testShamirWithSecret(t, cxt, testSecret)
	}
}
