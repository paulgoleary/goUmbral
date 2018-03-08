package umbral

import (
	"goUmbral/field"
	"math/big"
)

type UmbralPrivateKey struct {
	field.ModInt
}

type UmbralPublicKey struct {
	field.CurveElement
}

// TODO: currently implementing this on UmbralPublicKey - as opposed to CurveElement - because pyUmbral has a very specific way of serializing
func (key *UmbralPublicKey) toBytes(compressed bool) []byte {

	keySize := key.ElemParams.GetTargetField().LengthInBytes

	if compressed {
		yBit := big.NewInt(0).And(key.Y().GetValue(), field.ONE)
		yBit = yBit.Add(yBit, field.TWO)
		return append(yBit.Bytes(), field.BytesPadBigEndian(key.X().GetValue(), keySize)...)
	} else {
		data := make([]byte, 1)
		data[0] = 0x04
		data = append(data, field.BytesPadBigEndian(key.X().GetValue(), keySize)...)
		data = append(data, field.BytesPadBigEndian(key.Y().GetValue(), keySize)...)
		return data
	}
}

// UmbralPrivateKey

func GenPrivateKey(curveField *field.CurveField) *UmbralPrivateKey {
	randoKey := field.GetRandomInt(curveField.FieldOrder)
	return &UmbralPrivateKey{*field.CopyFrom(randoKey, true, curveField.FieldOrder)}
}

func (key *UmbralPrivateKey) GetPublicKey(curveField *field.CurveField) *UmbralPublicKey {
	calcPublicKey := curveField.GetGen().MulScalar(key.GetValue())
	return &UmbralPublicKey{ *calcPublicKey }
}

// UmbralPublicKey

