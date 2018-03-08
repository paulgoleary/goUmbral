package umbral

import (
	"goUmbral/field"
	"crypto/sha512"
	"math/big"
	"fmt"
	"hash"
)

type Capsule struct {}

// TODO: parameterize a/o get from somewhere else!
const SECRET_BOX_KEY_SIZE = 32

func Encrypt( curve *field.CurveField, pubKey *UmbralPublicKey, plainText []byte ) ([]byte, *Capsule) {

	// key, capsule = _encapsulate(alice_pubkey.point_key, SecretBox.KEY_SIZE)
	key, capsule := encapsulate(curve, pubKey, SECRET_BOX_KEY_SIZE)

	return key, capsule // TODO: this is *wrong* but let's just compile for now ...
}

// TODO: ok - make this part of a params object
func getMinValSha512(curve *field.CurveField) *big.Int {
	maxInt512 := big.NewInt(0).Lsh(big.NewInt(1), 512)
	return big.NewInt(0).Mod(maxInt512, curve.FieldOrder)
}

func encapsulate( curve *field.CurveField, pubKey *UmbralPublicKey, keyLength int ) ([]byte, *Capsule) {

	skR := GenPrivateKey(curve)
	pkR := skR.GetPublicKey(curve)

	skU := GenPrivateKey(curve)
	pkU := skU.GetPublicKey(curve)

	items := []([]byte){pkR.toBytes(), pkU.toBytes()}
	h := hashToModInt(curve, items)
	field.Trace(h)

	return nil, nil
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

		iBytes := big.NewInt(i).Bytes()
		iBigEndianPadded := append(make([]byte, curve.GetTargetField().LengthInBytes - len(iBytes)), iBytes...)

		hasher.Write(iBigEndianPadded)
		hashDigest := hasher.Sum(nil)
		h = big.NewInt(0).SetBytes(hashDigest) // SetBytes assumes big-endian
		i += 1
	}

	// TODO: both getMinValSha512 and this computation use the order of elliptical curve - not the base field ...?
	res := field.CopyFrom(h.Mod(h, curve.FieldOrder), true, curve.FieldOrder)
	return res
}