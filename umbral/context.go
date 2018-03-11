package umbral

import (
	"goUmbral/field"
	"goUmbral/crypto"
	"math/big"
)

type Context struct {
	curveField *field.CurveField
	targetField *field.ZField
	minValSha512 *big.Int
}

func getMinValSha512(curve *field.CurveField) *big.Int {
	maxInt512 := big.NewInt(0).Lsh(big.NewInt(1), 512)
	return big.NewInt(0).Mod(maxInt512, curve.FieldOrder)
}

func MakeDefaultContext() *Context {
	curveField := crypto.MakeSecp256k1()
	targetField := field.MakeZField(curveField.FieldOrder)
	return &Context{curveField, targetField, getMinValSha512(curveField)}
}