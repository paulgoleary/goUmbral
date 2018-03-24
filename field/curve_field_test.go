package field

import (
	"math/big"
	"testing"
)

func makeTestCurve() *CurveField {
	// borrow r and q from elsewhere
	rstr := "730750818665451621361119245571504901405976559617"
	qstr := "8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791"

	r := &big.Int{}
	r.SetString(rstr, 10)
	q := &big.Int{}
	q.SetString(qstr, 10)

	return makeTestCurveField(ONE, ZERO, r, q)
}

func TestCurveSpec(t *testing.T) {

	testField := makeTestCurve()

	testElem1 := testField.MakeElementFromX(ONE)
	if !testElem1.frozen() {
		t.Errorf("CurveElements should be frozen by default")
	}
	if testElem1.IsInf() {
		t.Errorf("Element should have been created correctly and not be INF: %s", testElem1.String())
	}

	// cross-check with external data
	checkElem1 := testField.newElementFromStrings(
		"1",
		"7723037104313405959565094238364965768271169914406684097333516603233244640449270089891894971336153383271692231855775588895034431645889814356778459865649104")
	if !testElem1.isEqual(checkElem1) {
		t.Errorf("Curve elements should be equal: expected %s, got %s", checkElem1.String(), testElem1.String())
	}

	testInf := testElem1.dup()
	if !testInf.frozen() {
		t.Errorf("INF CurveElement is considered frozen")
	}
	testInf.freeze() // don't crash - TODO: explicit recovery?

	testMulScalar := testElem1.MulScalar(big.NewInt(11))
	if !checkElem1.isEqual(testElem1) {
		t.Errorf("Calculations should not mutate an element")
	}

	// also validated externally
	checkMulScalar := testField.newElementFromStrings(
		"1",
		"1057673695349906562872687746389084047535713285007524113695136796033230990430952867186730208086508838151463626913806728564243281721427666968146670132575687")
	if !testMulScalar.isEqual(testMulScalar) {
		t.Errorf("Invalid curve element mul (pow) result: expected %s, got %s", checkMulScalar.String(), testMulScalar.String())
	}

	testElem2 := testField.MakeElementFromX(TWO)
	testMul2 := testElem2.MulPow(testElem2) // multiply by self - internally hits twiceInternal()
	if testElem2.isEqual(testMul2.(*CurveElement)) {
		t.Errorf("Failed invariance check - testElem2 should not change")
	}

	checkMul2 := testField.newElementFromStrings(
		"219517769991582813060944549618851245395172079985355205275716334981661890772005573926965629485566555535578896469239557936481942834182937033123128249955620",
		"3942409689725344731353139363386336459457275012328221735831877413826835008794860182931225284909304869309607973365549973284120510458395748317261221459163899")
	if !checkMul2.isEqual(testMul2.(*CurveElement)) {
		t.Errorf("Failed multiplication check: expected %s, got %s", checkMul2.String(), testMul2.String())
	}

	testElem3 := testField.MakeElementFromX(THREE)
	testMul3 := testElem3.MulPow(testElem2) // general multiplication
	if testElem3.isEqual(testMul3.(*CurveElement)) {
		t.Errorf("Failed invariance check - testElem3 should not change")
	}

	checkMul3 := testField.newElementFromStrings(
		"5985539393679187230662657557207800251798151062830402074407769166725988687734430785349592725546693827678808690553654885980525887516847853787007939985476501",
		"2188446834538147874570020204636980223493911922885212652534904061074255291433422278208236156510907953289782867101553310377539776723014044760831495590426505")
	if !checkMul3.isEqual(testMul3.(*CurveElement)) {
		t.Errorf("Failed multiplication check: expected %s, got %s", checkMul3.String(), testMul3.String())
	}
}

func TestCurveBasics(t *testing.T) {

	testField := makeTestCurve()

	testYFromX := func(xStr string, expectedYStr string) {
		testElem := testField.newElementFromStrings(xStr, expectedYStr)
		testCalc := testField.MakeElementFromX(&testElem.dataX.v)

		if !testCalc.dataY.IsValEqual(testElem.dataY) {
			// need to test the negative as well
			// TODO: need to account for sign in newElementFromX
			negY := testCalc.dataY.Negate()
			if !negY.IsValEqual(testElem.dataY) {
				t.Errorf("Failed to derive Y from X: expected %s, got %s", expectedYStr, testCalc.dataY.String())
			}
		}
	}

	// curve instance is y^2 = x^3 + x
	// 1^3 + 1 = 2
	testYFromX("1", MakeModInt(2, false, testField.GetTargetField().FieldOrder).sqrt().String())

	testYFromX(
		"7852334875614213225969535005319230321249629225894318783946607976937179571030765324627135523985138174020408497250901949150717492683934959664497943409406486",
		"8189589736511278424487290408486860952887816120897672059241649987466710766123126805204101070682864313793496226965335026128263318306025907120292056643404206")

	testYFromX(
		"3179305015224135534600913697529322474159056835318317733023669075672623777446135077445204913153064372784513253897383442505556687490792970594174506652914922",
		"6224780198151226873973489249032341465791104108959675858554195681300248102506693704394812888080668305563719500114924024081270783773410808141172779117133345")

	testYFromX(
		"2280014378744220144146373205831932526719685024545487661471834655738123196933971699437542834115250416780965121862860444719075976277314039181516434962834201",
		"5095219617050150661236292739445977344231341334112418835906977843435788249723740037212827151314561006651269984991436149205169409973600265455370653168534480")

}
