package security_tools

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// Hash = SHA-256
// IKM = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
// salt = 0x000102030405060708090a0b0c (13 octets)
// info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
// L = 42
// PRK = 0x077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5 (32 octets)
// OKM = 0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865 (42 octets)
func TestHkdfCase1(t *testing.T) {
	h := &Hkdf{
		Algorithm: "hmacsha256",
	}

	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")

	prk := h.Extract(ikm, salt)

	if hex.EncodeToString(prk) != "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5" {
		t.Errorf("extract failed")
	}

	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")

	okm := h.Expand(prk, info, 42)

	if hex.EncodeToString(okm) != "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" {
		t.Errorf("expand failed")
	}
}

// Hash = SHA-256
// IKM = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f (80 octets)
// salt = 0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf (80 octets)
// info = 0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff (80 octets)
// L = 82
// PRK = 0x06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244 (32 octets)
// OKM = 0xb11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87 (82 octets)
func TestHkdfCase2(t *testing.T) {
	h := &Hkdf{
		Algorithm: "hmacsha256",
	}

	ikm, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
	salt, _ := hex.DecodeString("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")

	prk := h.Extract(ikm, salt)

	if hex.EncodeToString(prk) != "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244" {
		t.Errorf("extract failed")
	}

	info, _ := hex.DecodeString("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

	okm := h.Expand(prk, info, 82)

	expectedOkm := "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
	actualOkm := hex.EncodeToString(okm)
	if actualOkm != expectedOkm {
		t.Errorf("expand failed")
		fmt.Printf("expected: %s\n", expectedOkm)
		fmt.Printf("actural:  %s\n",hex.EncodeToString(okm))
	}
}


//Hash = SHA-256
//IKM = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
//salt = (0 octets)
//info = (0 octets)
//L = 42
//PRK = 0x19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04 (32 octets)
//OKM = 0x8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8 (42 octets)
func TestHkdfCase3(t *testing.T) {
	h := &Hkdf{
		Algorithm: "hmacsha256",
	}

	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("")

	prk := h.Extract(ikm, salt)

	if hex.EncodeToString(prk) != "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04" {
		t.Errorf("extract failed")
	}

	info, _ := hex.DecodeString("")

	okm := h.Expand(prk, info, 42)

	expectedOkm := "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
	actualOkm := hex.EncodeToString(okm)
	if actualOkm != expectedOkm {
		t.Errorf("expand failed")
		fmt.Printf("expected: %s\n", expectedOkm)
		fmt.Printf("actural:  %s\n",hex.EncodeToString(okm))
	}
}

//Hash = SHA-1
//IKM = 0x0b0b0b0b0b0b0b0b0b0b0b (11 octets)
//salt = 0x000102030405060708090a0b0c (13 octets)
//info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
//L = 42
//PRK = 0x9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243 (20 octets)
//OKM = 0x085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896 (42 octets)

func TestHkdfCase4(t *testing.T) {
	h := &Hkdf{
		Algorithm: "hmacsha1",
	}

	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")

	prk := h.Extract(ikm, salt)

	if hex.EncodeToString(prk) != "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243" {
		t.Errorf("extract failed")
	}

	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")

	okm := h.Expand(prk, info, 42)

	expectedOkm := "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896"
	actualOkm := hex.EncodeToString(okm)
	if actualOkm != expectedOkm {
		t.Errorf("expand failed")
		fmt.Printf("expected: %s\n", expectedOkm)
		fmt.Printf("actural:  %s\n",hex.EncodeToString(okm))
	}
}

//Hash = SHA-1
//IKM = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f (80 octets)
//salt = 0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf (80 octets)
//info = 0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff (80 octets)
//L = 82
//PRK = 0x8adae09a2a307059478d309b26c4115a224cfaf6 (20 octets)
//OKM = 0x0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4 (82 octets)
func TestHkdfCase5(t *testing.T) {
	h := &Hkdf{
		Algorithm: "hmacsha1",
	}

	ikm, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
	salt, _ := hex.DecodeString("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")

	prk := h.Extract(ikm, salt)

	if hex.EncodeToString(prk) != "8adae09a2a307059478d309b26c4115a224cfaf6" {
		t.Errorf("extract failed")
	}

	info, _ := hex.DecodeString("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

	okm := h.Expand(prk, info, 82)

	expectedOkm := "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4"
	actualOkm := hex.EncodeToString(okm)
	if actualOkm != expectedOkm {
		t.Errorf("expand failed")
		fmt.Printf("expected: %s\n", expectedOkm)
		fmt.Printf("actural:  %s\n",hex.EncodeToString(okm))
	}
}


//Hash = SHA-1
//IKM = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
//salt = (0 octets)
//info = (0 octets)
//L = 42
//PRK = 0xda8c8a73c7fa77288ec6f5e7c297786aa0d32d01 (20 octets)
//OKM = 0x0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918 (42 octets)
func TestHkdfCase6(t *testing.T) {
	h := &Hkdf{
		Algorithm: "hmacsha1",
	}

	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("")

	prk := h.Extract(ikm, salt)

	if hex.EncodeToString(prk) != "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01" {
		t.Errorf("extract failed")
	}

	info, _ := hex.DecodeString("")

	okm := h.Expand(prk, info, 42)

	expectedOkm := "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918"
	actualOkm := hex.EncodeToString(okm)
	if actualOkm != expectedOkm {
		t.Errorf("expand failed")
		fmt.Printf("expected: %s\n", expectedOkm)
		fmt.Printf("actural:  %s\n",hex.EncodeToString(okm))
	}
}

//Hash = SHA-1
//IKM = 0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c (22 octets)
//salt = not provided (defaults to HashLen zero octets)
//info = (0 octets)
//L = 42
//PRK = 0x2adccada18779e7c2077ad2eb19d3f3e731385dd (20 octets)
//OKM = 0x2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48 (42 octets)
func TestHkdfCase7(t *testing.T) {
	h := &Hkdf{
		Algorithm: "hmacsha1",
	}

	ikm, _ := hex.DecodeString("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
	salt, _ := hex.DecodeString("")

	prk := h.Extract(ikm, salt)

	if hex.EncodeToString(prk) != "2adccada18779e7c2077ad2eb19d3f3e731385dd" {
		t.Errorf("extract failed")
	}

	info, _ := hex.DecodeString("")

	okm := h.Expand(prk, info, 42)

	expectedOkm := "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48"
	actualOkm := hex.EncodeToString(okm)
	if actualOkm != expectedOkm {
		t.Errorf("expand failed")
		fmt.Printf("expected: %s\n", expectedOkm)
		fmt.Printf("actural:  %s\n",hex.EncodeToString(okm))
	}
}