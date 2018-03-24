package umbral

import (
	"goUmbral/crypto"
	"goUmbral/field"
	"math/big"
)

type Context struct {
	curveField   *field.CurveField
	targetField  *field.ZField
	minValSha512 *big.Int
	U            *field.CurveElement
	symKeySize   int
}

func (cxt *Context) GetGen() *field.CurveElement {
	return cxt.curveField.GetGen()
}

func (cxt *Context) GetOrder() *big.Int {
	return cxt.curveField.FieldOrder
}

func (cxt *Context) MulGen(x *field.ModInt) *UmbralCurveElement {
	return &UmbralCurveElement{*cxt.GetGen().MulScalar(x.GetValue())}
}

func (cxt *Context) MulU(x *field.ModInt) *UmbralCurveElement {
	return &UmbralCurveElement{*cxt.U.MulScalar(x.GetValue())}
}

func getMinValSha512(curve *field.CurveField) *big.Int {
	maxInt512 := big.NewInt(0).Lsh(big.NewInt(1), 512)
	return big.NewInt(0).Mod(maxInt512, curve.FieldOrder)
}

const SECRET_BOX_KEY_SIZE = 32

func MakeDefaultContext() *Context {
	curveField := crypto.MakeSecp256k1()
	targetField := field.MakeZField(curveField.FieldOrder)
	uX, _ := big.NewInt(0).SetString("68282748765985831108782504644936740559294230795844544892333042179975631922610", 10)
	uY, _ := big.NewInt(0).SetString("27576123183859453704384360727380224739834659634660871190236925621255961659778", 10)
	U := curveField.MakeElement(uX, uY) // TODO: I cheat here and just construct U directly with values cribbed from pyUmbral
	return &Context{curveField, targetField, getMinValSha512(curveField), U, SECRET_BOX_KEY_SIZE}
}
