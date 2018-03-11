package field

import (
	"math/big"
	"fmt"
	"crypto/rand"
	"log"
	"time"
)

func NAF(nIn *big.Int, k int) []int8 {

	nCopy := new(big.Int).Set(nIn) // copy nIn so we don't step on it
	nIn = nil // make *sure* we don't step on it ...

	wnaf := make([]int8, nCopy.BitLen() + 1)
	pow2wB := 1 << (uint)(k)
	pow2wBI := big.NewInt((int64)(pow2wB))
	// int i = 0;

	i := 0
	length := 0
	for nCopy.Sign() > 0 {
		if (nCopy.Bit(0)) != 0 {
			remainder := big.Int{}
			remainder.SetBytes(nCopy.Bytes()).Mod(nCopy, pow2wBI) // copy n
			if remainder.Bit(k - 1) != 0 {
				wnaf[i] = (int8)(remainder.Int64() - (int64)(pow2wB))
			} else {
				wnaf[i] = (int8)(remainder.Int64())
			}

			nCopy = nCopy.Sub(nCopy, big.NewInt((int64)(wnaf[i])))
			length = i
		} else {
			wnaf[i] = 0;
		}

		nCopy.Rsh(nCopy, 1)
		i++
	}

	length++
	wnafShort := wnaf[:length]
	return wnafShort
}

func Trace(strs ...fmt.Stringer) {
	for _, s := range strs {
		println(s.String())
	}
	println()
}

func GetRandomInt(order *big.Int) *big.Int {
	randInt, err := rand.Int(rand.Reader, order)
	if err != nil {
		log.Fatal(err)
	}
	return randInt
}

func GetRandomBytes(len int) []byte {
	rando := make([]byte, len)
	_, err := rand.Read(rando)
	if err != nil {
		log.Panicf("Failed making random bytes: %v")
	}
	return rando
}

func BytesPadBigEndian(i *big.Int, l int) []byte {
	iBytes := i.Bytes() // always big-endian...
	return append(make([]byte, l - len(iBytes)), iBytes...)
}

func TimeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("%s took %s", name, elapsed)
}
