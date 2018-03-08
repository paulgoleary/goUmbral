package umbral

import "goUmbral/field"

type UmbralPrivateKey struct {
	field.ZElement
}

type UmbralPublicKey struct {
	field.CurveElement
}

func (key *UmbralPublicKey) toBytes() []byte {
	return nil
}

// UmbralPrivateKey

func GenPrivateKey(curveField *field.CurveField) *UmbralPrivateKey {
	randoKey := field.GetRandomInt(curveField.GetTargetField().FieldOrder)
	randoElement := curveField.GetTargetField().NewElement(randoKey)
	return &UmbralPrivateKey{*randoElement}
}

func (key *UmbralPrivateKey) GetPublicKey(curveField *field.CurveField) *UmbralPublicKey {
	calcPublicKey := curveField.GetGen().MulScalar(key.GetValue())
	return &UmbralPublicKey{ *calcPublicKey }
}

// UmbralPublicKey

