package umbral

import (
	"goUmbral/field"
	"math/big"
)

type UmbralFieldElement struct {
	field.ZElement
}

type UmbralCurveElement struct {
	field.CurveElement
}

// TODO: hmmm... need to think about this ...
func toUmbralBytes(elem *field.CurveElement, compressed bool, keySize int) []byte {
	if compressed {
		yBit := big.NewInt(0).And(elem.Y().GetValue(), field.ONE)
		yBit = yBit.Add(yBit, field.TWO)
		return append(yBit.Bytes(), field.BytesPadBigEndian(elem.X().GetValue(), keySize)...)
	} else {
		data := make([]byte, 1)
		data[0] = 0x04
		data = append(data, field.BytesPadBigEndian(elem.X().GetValue(), keySize)...)
		data = append(data, field.BytesPadBigEndian(elem.Y().GetValue(), keySize)...)
		return data
	}
}

// TODO: currently implementing this on UmbralCurveElement - as opposed to CurveElement - because pyUmbral has a very specific way of serializing
func (key *UmbralCurveElement) toBytes(compressed bool) []byte {
	return toUmbralBytes(&key.CurveElement, true, key.ElemParams.GetTargetField().LengthInBytes)
}

func (key *UmbralCurveElement) MulInt(mi *field.ModInt) *UmbralCurveElement {
	if mi == nil {
		return key
	}
	return &UmbralCurveElement{*key.MulScalar(mi.GetValue())}
}

func (key *UmbralCurveElement) Add(in *UmbralCurveElement) *UmbralCurveElement {
	if in == nil {
		return key
	}
	return &UmbralCurveElement{*key.CurveElement.Add(&in.CurveElement)}
}

// UmbralFieldElement

func GenPrivateKey(cxt *Context) *UmbralFieldElement {
	randoKey := field.GetRandomInt(cxt.targetField.FieldOrder)
	e := cxt.targetField.NewElement(randoKey)
	return &UmbralFieldElement{*e}
}

func MakePrivateKey(cxt *Context, mi *field.ModInt) *UmbralFieldElement {
	e := cxt.targetField.NewElement(mi.GetValue())
	return &UmbralFieldElement{*e}
}

func (key *UmbralFieldElement) GetPublicKey(cxt *Context) *UmbralCurveElement {
	calcPublicKey := cxt.curveField.GetGen().MulScalar(key.GetValue())
	return &UmbralCurveElement{*calcPublicKey}
}

// UmbralCurveElement

func (pk *UmbralCurveElement) Mul(sk *UmbralFieldElement) *UmbralCurveElement {
	return &UmbralCurveElement{*pk.MulScalar(sk.GetValue())}
}
