package umbral

import (
	"goUmbral/field"
	"crypto/sha512"
	"math/big"
	"fmt"
	"hash"
	"golang.org/x/crypto/hkdf"
)

type Capsule struct {
	E	*UmbralPublicKey
	V 	*UmbralPublicKey
	s 	*field.ZElement
}

// TODO: not complete implementation of Capsule or serialization
func (c *Capsule) toBytes() []byte {
	return append(
		append(c.E.toBytes(true), c.V.toBytes(true)...),
		field.BytesPadBigEndian(c.s.GetValue(), c.s.ElemField.LengthInBytes)...)
}

// TODO: parameterize a/o get from somewhere else?
const SECRET_BOX_KEY_SIZE = 32

func Encrypt( curve *field.CurveField, pubKey *UmbralPublicKey, plainText []byte ) ([]byte, *Capsule) {

	// key, capsule = _encapsulate(alice_pubkey.point_key, SecretBox.KEY_SIZE)
	key, capsule := encapsulate(curve, pubKey, SECRET_BOX_KEY_SIZE)

	capsuleBytes := capsule.toBytes()
	println(capsuleBytes)

	return key, capsule // TODO: this is *wrong* but let's just compile for now ...
}

// TODO: ok - make this part of a params object
func getMinValSha512(curve *field.CurveField) *big.Int {
	maxInt512 := big.NewInt(0).Lsh(big.NewInt(1), 512)
	return big.NewInt(0).Mod(maxInt512, curve.FieldOrder)
}

func kdf(keyPoint *field.CurveElement, keySize int) []byte {

	// TODO: awkward?
	pointKey := UmbralPublicKey{*keyPoint}
	keyMaster := hkdf.New(sha512.New, pointKey.toBytes(true), nil, nil)

	derivedKey := make([]byte, keySize)
	keyMaster.Read(derivedKey)

	return derivedKey
}

func encapsulate( curve *field.CurveField, pubKey *UmbralPublicKey, keyLength int ) ([]byte, *Capsule) {

	skR := GenPrivateKey(curve)
	pkR := skR.GetPublicKey(curve)

	skU := GenPrivateKey(curve)
	pkU := skU.GetPublicKey(curve)

	items := []([]byte){pkR.toBytes(true), pkU.toBytes(true)}
	h := hashToModInt(curve, items)

	// s = priv_u + (priv_r * h)
	s := skU.Add(skR.Mul(h))
	sElem := curve.GetTargetField().NewElement(s.GetValue())

	// shared_key = (priv_r + priv_u) * alice_pub_key
	sharedKey := pubKey.MulScalar(skR.Add(skU.ModInt).GetValue())
	// sharedKey := pubKey.Pow(skR.Add(&skU.ModInt)) - equivalent but returns PointElement ...

	symmetricKey := kdf(sharedKey, keyLength)

	return symmetricKey, &Capsule{pkR, pkU, sElem}
}

func traceHash(h hash.Hash) {
	testDigest := h.Sum(nil)
	println(fmt.Sprintf("b'%x'", testDigest))
}

func hashToModInt(curve *field.CurveField, items []([]byte)) *field.ModInt {

	createAndInitHash := func() hash.Hash {
		hasher := sha512.New()
		for _, item := range items {
			hasher.Write(item)
		}
		return hasher
	}

	minValSha512 := getMinValSha512(curve)

	i := int64(0)
	h := big.NewInt(0)
	for h.Cmp(minValSha512) < 0 {
		hasher := createAndInitHash()

		iBigEndianPadded := field.BytesPadBigEndian(big.NewInt(i), curve.GetTargetField().LengthInBytes)

		hasher.Write(iBigEndianPadded)
		hashDigest := hasher.Sum(nil)
		h = big.NewInt(0).SetBytes(hashDigest) // SetBytes assumes big-endian
		i += 1
	}

	res := field.CopyFrom(h.Mod(h, curve.FieldOrder), true, curve.FieldOrder)
	return res
}