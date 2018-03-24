package field

import (
	"fmt"
	"math/big"
)

type ZField struct {
	BaseField
	TwoInverse *ModInt
}

type ZElement struct {
	ElemField *ZField
	*ModInt
}

func (elem *ZElement) String() string {
	return fmt.Sprintf("ZElement: %s | %s", elem.v.String(), elem.ElemField.FieldOrder.String())
}

// ZField

func MakeZField(fieldOrder *big.Int) *ZField {
	zField := new(ZField)
	zField.FieldOrder = fieldOrder
	zField.LengthInBytes = fieldOrder.BitLen() / 8 // TODO: generalize ???
	zField.TwoInverse = zField.NewElement(TWO).Invert()
	zField.TwoInverse.Freeze()
	return zField
}

func (zfield *ZField) NewOneElement() *ZElement {
	return zfield.NewElement(ONE)
}

func (zfield *ZField) NewZeroElement() *ZElement {
	return zfield.NewElement(ZERO)
}

func (zfield *ZField) NewElement(elemValue *big.Int) *ZElement {
	return &ZElement{zfield, CopyFrom(elemValue, true, zfield.FieldOrder)}
}

func (zfield *ZField) NewRandomElement() *ZElement {
	randInt := GetRandomInt(zfield.FieldOrder)
	return &ZElement{zfield, CopyFrom(randInt, true, zfield.FieldOrder)}
}
