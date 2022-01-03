package security_tools

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"math"
)

type Hkdf struct {
	Algorithm string
}

func (h *Hkdf) Extract(ikm []byte, salt []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, 32)
	}

	mac := hmac.New(h.getHashFunction(), salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func (h *Hkdf) Expand(prk []byte, info []byte, length int) []byte {
	mac := hmac.New(h.getHashFunction(), prk)
	hashSize := h.getHashSize()
	if hashSize == 0 {
		return nil
	}

	ceil := int(math.Ceil(float64(length) / (float64(hashSize))))
	if ceil > 255 {
		return nil
	}


	rawResult := make([]byte, 0)
	t := make([]byte, 0)
	for i := 1; i <= ceil; i++ {
		var subBytes []byte
		subBytes = append(subBytes, t...)
		subBytes = append(subBytes, info...)
		subBytes = append(subBytes, byte(i))
		mac.Write(subBytes)
		t = mac.Sum(nil)
		mac.Reset()

		var combineBytes []byte
		combineBytes = append(combineBytes, rawResult...)
		combineBytes = append(combineBytes, t...)

		rawResult = combineBytes
	}

	return rawResult[:length]

}

func (h *Hkdf) getHashFunction() func() hash.Hash {
	switch h.Algorithm {
	case "hmacsha1":
		return sha1.New
	case "hmacsha256":
		return sha256.New
	case "hmacsha512":
		return sha512.New
	default:
		return sha256.New
	}
}

func (h *Hkdf) getHashSize() int {
	switch h.Algorithm {
	case "hmacsha1":
		return 20
	case "hmacsha256":
		return 32
	case "hmacsha512":
		return 64
	default:
		return 32
	}
}
