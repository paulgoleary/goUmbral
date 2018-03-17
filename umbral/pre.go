package umbral

import (
	"goUmbral/field"
	"crypto/sha512"
	"math/big"
	"fmt"
	"hash"
	"golang.org/x/crypto/hkdf"
	"log"
)

type Capsule struct {
	E	*UmbralCurveElement
	V 	*UmbralCurveElement
	s 	*field.ZElement
}

// TODO: not complete implementation of Capsule or serialization
func (c *Capsule) toBytes() []byte {
	return append(
		append(c.E.toBytes(true), c.V.toBytes(true)...),
		field.BytesPadBigEndian(c.s.GetValue(), c.s.ElemField.LengthInBytes)...)
}

func (c *Capsule) verify(cxt *Context) bool {
	items := []([]byte){c.E.toBytes(true), c.V.toBytes(true)}
	h := hashToModInt(cxt, items)

	l := cxt.curveField.GetGen().MulScalar(c.s.GetValue())
	r := c.E.MulScalar(h.GetValue()).Add(&c.V.CurveElement)
	return l.IsValEqual(&r.PointLike)
}

// TODO: parameterize a/o get from somewhere else?
const SECRET_BOX_KEY_SIZE = 32

func Encrypt( cxt *Context, pubKey *UmbralCurveElement, plainText []byte ) ([]byte, *Capsule) {

	key, capsule := encapsulate(cxt, pubKey, SECRET_BOX_KEY_SIZE)

	capsuleBytes := capsule.toBytes()

	dem := MakeDEM(key)
	cypher := dem.encrypt(plainText, capsuleBytes)

	return cypher, capsule
}

func Decrypt( cxt *Context, capsule *Capsule, privKey *UmbralFieldElement, cipherText []byte ) []byte {

	key := decapsulate(cxt, privKey, capsule, SECRET_BOX_KEY_SIZE)
	dem := MakeDEM(key)

	capsuleBytes := capsule.toBytes()

	return dem.decrypt(cipherText, capsuleBytes)
}

func hornerPolyEval(poly []*field.ModInt, x *field.ModInt) *field.ModInt {
	result := poly[0]
	for i := 1; i < len(poly); i++ {
		result = result.Mul(x).Add(poly[i])
	}
	return result
}

type KFrag struct {
	id *field.ModInt
	rk *field.ModInt
	xComp *UmbralCurveElement
	u1 *UmbralCurveElement
	z1 *field.ModInt
	z2 *field.ModInt
}

func SplitReKey(cxt *Context, privA *UmbralFieldElement, pubB *UmbralCurveElement, threshold int, numSplits int) []KFrag {

	pubA := privA.GetPublicKey(cxt)

	x := GenPrivateKey(cxt)
	xComp := x.GetPublicKey(cxt) // gen^x

	dhB := pubB.Mul(x) // pk_b^x

	// hash of:
	// . gen^x - where x is ephemeral
	// . gen^b - public key of b
	// . pk_b^x - so gen^(bx)
	d := hashToModInt(cxt, [][]byte {
		xComp.toBytes(true),
		pubB.toBytes(true),
		dhB.toBytes(true)})

	coeff0 := privA.Mul(d.Invert())

	coeffs := make([]*field.ModInt, threshold - 1)
	for i := range coeffs {
		coeffs[i] = field.MakeModIntRandom(cxt.GetOrder())
	}
	coeffs = append(coeffs, coeff0)

	kFrags := make([]KFrag, numSplits)
	for i := range kFrags {
		id := field.MakeModIntRandom(cxt.GetOrder())
		rk := hornerPolyEval(coeffs, id)

		u1 := cxt.MulU(rk) // U^rk

		y := field.MakeModIntRandom(cxt.GetOrder())

		z1 := hashToModInt(cxt, [][]byte {
			cxt.MulGen(y).toBytes(true), // gen^y
			field.BytesPadBigEndian(id.GetValue(), cxt.curveField.LengthInBytes), // TODO: ugly :/
			pubA.toBytes(true),
			pubB.toBytes(true),
			u1.toBytes(true),
			xComp.toBytes(true),
		})
		z2 :=y.Sub(privA.Mul(z1))

		kFrags[i] = KFrag { id, rk, xComp, u1, z1, z2 }
	}

	return kFrags
}

func kdf(keyPoint *field.CurveElement, keySize int) []byte {

	// TODO: awkward?
	pointKey := UmbralCurveElement{*keyPoint}
	keyMaster := hkdf.New(sha512.New, pointKey.toBytes(true), nil, nil)

	derivedKey := make([]byte, keySize)
	keyMaster.Read(derivedKey)

	return derivedKey
}

func encapsulate( cxt *Context, pubKey *UmbralCurveElement, keyLength int ) ([]byte, *Capsule) {

	skR := GenPrivateKey(cxt)
	pkR := skR.GetPublicKey(cxt)

	skU := GenPrivateKey(cxt)
	pkU := skU.GetPublicKey(cxt)

	items := []([]byte){pkR.toBytes(true), pkU.toBytes(true)}
	h := hashToModInt(cxt, items)

	s := skU.Add(skR.Mul(h))
	sElem := cxt.targetField.NewElement(s.GetValue())

	sharedKey := pubKey.MulScalar(skR.Add(skU.ModInt).GetValue())

	symmetricKey := kdf(sharedKey, keyLength)

	return symmetricKey, &Capsule{pkR, pkU, sElem}
}

func decapsulate(cxt *Context, privKey *UmbralFieldElement, capsule *Capsule, keyLength int) []byte {

	sharedKey := capsule.E.Add(&capsule.V.CurveElement).MulScalar(privKey.GetValue())
	key := kdf(sharedKey, keyLength)

	if !capsule.verify(cxt) {
		log.Panicf("Capsule validation failed.") // TODO: not sure this should be a panic
	}

	return key
}

func traceHash(h hash.Hash) {
	testDigest := h.Sum(nil)
	println(fmt.Sprintf("b'%x'", testDigest))
}

func hashToModInt(cxt *Context, items []([]byte)) *field.ModInt {

	createAndInitHash := func() hash.Hash {
		hasher := sha512.New()
		for _, item := range items {
			hasher.Write(item)
		}
		return hasher
	}

	i := int64(0)
	h := big.NewInt(0)
	for h.Cmp(cxt.minValSha512) < 0 {
		hasher := createAndInitHash()

		iBigEndianPadded := field.BytesPadBigEndian(big.NewInt(i), cxt.targetField.LengthInBytes)

		hasher.Write(iBigEndianPadded)
		hashDigest := hasher.Sum(nil)
		h = big.NewInt(0).SetBytes(hashDigest) // SetBytes assumes big-endian
		i += 1
	}

	res := field.CopyFrom(h.Mod(h, cxt.targetField.FieldOrder), true, cxt.targetField.FieldOrder)
	return res
}