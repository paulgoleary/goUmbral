package field

import (
	"math/big"
	"log"
)

type CurveField struct {
	CurveParams
	cofactor   *big.Int      // TODO: do we need this ...?
	gen        *CurveElement // TODO: not sure here...
	genNoCofac *CurveElement // TODO: don't need this ...?
}

type CurveParams struct {
	BaseField
	a          *ZElement
	b          *ZElement
}

type CurveElement struct {
	elemParams *CurveParams
	PointLike
}

// CurveField

// TODO: JPBC (PBC?) handles case w/o bytes and cofactor
func (field *CurveField) initGenFromBytes(genNoCofacBytes []byte) {
	if genNoCofacBytes == nil {
		return
	}
	newGenNoCoFac := field.MakeElementFromBytes(genNoCofacBytes)
	field.genNoCofac = newGenNoCoFac
	field.gen = field.genNoCofac.MulScalar(field.cofactor)
	if !field.gen.isValid(){
		panic("Curve field generator needs to be valid")
	}
}

func (field *CurveField) GetGen() *CurveElement {
	return field.gen
}

func (curveParams *CurveParams) GetTargetField() *ZField {
	return curveParams.a.ElemField
}

func (field *CurveField) MakeElementFromBytes(elemBytes []byte) *CurveElement {

	pnt := MakePointFromBytes(elemBytes, &field.GetTargetField().BaseField)

	elem := &CurveElement{ &field.CurveParams, *pnt}

	// needs to be frozen before validation
	elem.freeze()
	if !elem.isValid() {
		elem.setInf()
	}
	return elem
}

// general curve is y^2 = x^3 + ax + b
func (params *CurveParams) calcYSquared(xIn *ModInt) *ModInt {
	if !xIn.frozen {
		panic("xIn needs to be frozen")
	}
	validateModulo(params.GetTargetField().FieldOrder, xIn.m)
	return xIn.Square().Add(params.a.ModInt).Mul(xIn).Add(params.b.ModInt)
}

// this function constructs a point on the curve from the input hash-derived bytes.
// since the input is assumed to be random when we use it as an initial X value it is not guaranteed to lie on the curve
// therefore - unlike MakeElementFromX - we iterate in a stable way to find a value that does satisfy the curve equation
// the size of the hash must be such that we can guarantee that its value as an integer is less than our target order
func (field *CurveField) MakeElementFromHash(h []byte) *CurveElement {
	maxSafeBytes := field.GetTargetField().LengthInBytes - 1
	if len(h) > maxSafeBytes {
		log.Panicf("Cannot construct point from hash when byte length exceeds field capacity: max bytes %v, got %v", maxSafeBytes, len(h) )
	}
	calcX := copyFromBytes(h, true, field.GetTargetField().FieldOrder)

	calcY2 := MI_ONE
	gotIt := false
	for !gotIt {
		calcY2 = field.calcYSquared(calcX)
		if calcY2.isSquare() {
			gotIt = true
		} else {
			calcX = calcX.Square().Add(MI_ONE)
			calcX.Freeze()
		}
	}

	calcY := calcY2.sqrt()
	if calcY.v.Sign() < 0 {
		calcY = calcY.Negate()
	}

	elem := &CurveElement{&field.CurveParams, PointLike{calcX, calcY2.sqrt()}}
	elem.freeze()
	if field.cofactor != nil {
		elem = elem.MulScalar(field.cofactor)
	}

	return elem
}

func (field *CurveField) MakeElement(x *big.Int, y *big.Int) *CurveElement {
	copyX := CopyFrom(x, true, field.GetTargetField().FieldOrder)
	copyY := CopyFrom(y, true, field.GetTargetField().FieldOrder)
	elem := CurveElement{&field.CurveParams, PointLike{copyX, copyY}}
	elem.freeze()
	return &elem
}

// TODO: needs to account for sign
func (field *CurveField) MakeElementFromX(x *big.Int) *CurveElement {

	copyX := CopyFrom(x, true, field.GetTargetField().FieldOrder)
	calcY2 := field.calcYSquared(copyX)
	if !calcY2.isSquare() {
		log.Panicf("Expected to calculate square: value %s", calcY2.String())
	}
	dataY := calcY2.sqrt()

	elem := CurveElement{&field.CurveParams, PointLike{copyX, dataY}}
	elem.freeze()
	return &elem
}

func (field *CurveField) newElementFromStrings(xStr string, yStr string) *CurveElement {
	targetOrder := field.GetTargetField().FieldOrder
	return &CurveElement{&field.CurveParams,
	PointLike{MakeModIntStr(xStr, true, targetOrder), MakeModIntStr(yStr, true, targetOrder)}}
}

func getLengthInBytes( field *CurveField ) int {
	return field.GetTargetField().LengthInBytes * 2
}

func MakeCurveField(
	a *ZElement,
	b *ZElement,
	order *big.Int,
	genX *big.Int,
	genY *big.Int ) *CurveField {

	field := new(CurveField)
	field.a = a
	field.b = b
	field.FieldOrder = order
	field.LengthInBytes = getLengthInBytes(field)

	field.gen = field.MakeElement(genX, genY)

	if !field.gen.isValid(){
		panic("Curve field generator needs to be valid")
	}

	field.cofactor = nil // TODO: not sure if we need / want this...

	return field
}

// TODO: need to reconcile this and the other make function - not sure I both ...?
// make minimal field for testing purposes - TODO: might need a generator?
func makeTestCurveField(a *big.Int, b *big.Int, r *big.Int, q *big.Int) *CurveField {

	zfield := MakeZField(q)

	cfield := new(CurveField)
	cfield.a = zfield.NewElement(a)
	cfield.b = zfield.NewElement(b)
	cfield.FieldOrder = r
	cfield.LengthInBytes = getLengthInBytes(cfield)

	return cfield
}

// CurveElement

// TODO: Make function?

var _ PointElement = (*CurveElement)(nil)
var _ PowElement = (*CurveElement)(nil)

func (elem *CurveElement) getTargetOrder() *big.Int {
	return elem.elemParams.GetTargetField().FieldOrder
}

func (elem *CurveElement) NegateY() PointElement {
	if elem.IsInf() {
		return &CurveElement{elem.elemParams, PointLike{nil, nil}}
	}
	elem.PointLike.freeze() // make sure we're frozen
	yNeg := elem.dataY.Negate()
	return &CurveElement{elem.elemParams, PointLike{elem.dataX, yNeg}}
}

func (elem *CurveElement) Invert() PointElement {
	if elem.IsInf() {
		return elem
	}
	elem.dataY = elem.dataY.Negate()
	elem.dataY.Freeze()
	return elem
}

func (elem *CurveElement) Square() PointElement {
	// TODO !?
	return nil
}

func (elem *CurveElement) Add(elemIn PointElement) PointElement {
	return elem.MulPoint(elemIn)
}

func (elem *CurveElement) Sub(_ PointElement) PointElement {
	return nil // TODO!?
}

/*
func (elem *CurveElement) IsInf() bool {
	return elem.dataY == nil && elem.dataY == nil
}
*/

func (elem *CurveElement) setInf() {
	elem.dataX = nil
	elem.dataY = nil
}

// don't return elem to emphasize that call mutates elem
func (elem *CurveElement) freeze() {
	if elem.IsInf() {
		return // already frozen by def
	}
	elem.PointLike.freeze()
	return
}

func (elem *CurveElement) frozen() bool {
	if (elem.IsInf()) {
		return true
	}
	return elem.PointLike.frozen()
}

func (elem *CurveElement) MulScalar(n *big.Int) *CurveElement {
	result := powWindow(elem, n).(*CurveElement)
	result.freeze()
	return result
}

func (elem *CurveElement) PowZn(in *big.Int) *CurveElement {
	result := powWindow(elem, in).(*CurveElement)
	result.freeze()
	return result
}

func (elem *CurveElement) Pow(in *ModInt) PointElement {
	return elem.PowZn(&in.v)
}

func validateModulo( mod1 *big.Int, mod2 *big.Int) {
	// TODO: this is intentionally pointer comparison because we expect the ModInt m's to point to the same object
	// need to think about this tho ...
	if mod1 == nil || mod1 != mod2 {
		log.Panicf("Field components must have valid and equal modulo")
	}
}

func (elem *CurveElement) isValid() bool {

	if elem.IsInf() {
		return true
	}

	validateModulo(elem.dataX.m, elem.dataY.m)

	calcY2 := elem.elemParams.calcYSquared(elem.dataX)
	calcY2Check := elem.dataY.Square()

	return calcY2.IsValEqual(calcY2Check)
}

func (elem *CurveElement) isEqual(cmpElem *CurveElement) bool {
	if !elem.dataX.IsValEqual(cmpElem.dataX) {
		return false
	}
	return elem.dataY.IsValEqual(cmpElem.dataY)
}

func (elem *CurveElement) CopyPow() PowElement {
	theCopy := elem.dup()
	theCopy.freeze()
	return theCopy
}

func (elem *CurveElement) dup() *CurveElement {
	newElem := new(CurveElement)
	newElem.elemParams = elem.elemParams
	newElem.dataX = elem.dataX.Copy()
	newElem.dataY = elem.dataY.Copy()
	return newElem
}

func (elem *CurveElement) MakeOnePow() PowElement {
	return &CurveElement{elem.elemParams, PointLike{nil, nil}}
}

func (elem *CurveElement) MulPoint(elemIn PointElement) PointElement {
	res := elem.mul(elemIn.(*CurveElement))
	return res
}

func (elem *CurveElement) MulPow(elemIn PowElement) PowElement {
	res := elem.mul(elemIn.(*CurveElement))
	return res
}

func (elem *CurveElement) set(in *CurveElement) {
	elem.dataX = in.dataX
	elem.dataY = in.dataY
}

func (elem *CurveElement) twiceInternal() *CurveElement {

	if !elem.frozen() {
		panic("elem input must be frozen")
	}

	// We have P1 = P2 so the tangent line T at P1 ha slope
	// lambda = (3x^2 + a) / 2y
	lambdaNumer := elem.dataX.Square().Mul(MI_THREE).Add(elem.elemParams.a.ModInt)
	lambdaDenom := elem.dataY.Add(elem.dataY).Invert()
	lambda := lambdaNumer.Mul(lambdaDenom)
	lambda.Freeze()

	// x3 = lambda^2 - 2x
	x3 := lambda.Square().Sub(elem.dataX.Add(elem.dataX))

	// y3 = (x - x3) lambda - y
	y3 := elem.dataX.Sub(x3).Mul(lambda).Sub(elem.dataY)

	x3.Freeze()
	y3.Freeze()
	return &CurveElement{ elem.elemParams, PointLike {x3, y3}}
}

func (elem *CurveElement) mul(elemIn *CurveElement) *CurveElement {

	if !elemIn.frozen() {
		panic("elemIn param must be frozen")
	}

	if elem.IsInf() {
		return elemIn
	}

	if elemIn.IsInf() {
		return elem
	}

	if elem.dataX.IsValEqual(elemIn.dataX) {
		if elem.dataY.IsValEqual(elemIn.dataY) {
			if elem.dataY.IsValEqual(MI_ZERO) {
				return &CurveElement{elem.elemParams, PointLike{nil, nil}}
			} else {
				return elem.twiceInternal()
			}
		}
		return &CurveElement{elem.elemParams, PointLike{nil, nil}}
	}

	// P1 != P2, so the slope of the line L through P1 and P2 is
	// lambda = (y2-y1)/(x2-x1)
	lambdaNumer := elemIn.dataY.Sub(elem.dataY)
	lambdaDenom := elemIn.dataX.Sub(elem.dataX)
	lambda := lambdaNumer.Mul(lambdaDenom.Invert())
	lambda.Freeze()

	// x3 = lambda^2 - x1 - x2
	x3 := lambda.Square().Sub(elem.dataX).Sub(elemIn.dataX)

	// y3 = (x1-x3) lambda - y1
	y3 := elem.dataX.Sub(x3).Mul(lambda).Sub(elem.dataY)

	x3.Freeze()
	y3.Freeze()
	return &CurveElement{elem.elemParams, PointLike {x3, y3}}
}
