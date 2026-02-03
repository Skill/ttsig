package signer

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"net/url"
	"strconv"

	"github.com/Skill/ttsig/crypto"
)

// ------------------------------------------------------------
// PKCS7 padding
// ------------------------------------------------------------
func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

// ------------------------------------------------------------
// encrypt_enc_pb (matches Python exactly)
// ------------------------------------------------------------
func encryptEncPB(data []byte, l int) []byte {
	out := make([]byte, len(data))
	copy(out, data)

	x := out[:8]
	for i := 8; i < l; i++ {
		out[i] ^= x[i%8]
	}

	// reverse
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}

	return out
}

// ------------------------------------------------------------
// SM3 helpers (using your real SM3 implementation)
// ------------------------------------------------------------

func GetBodyHash(stub string) []byte {
	h := crypto.New()

	if stub == "" {
		data := make([]byte, 16)
		out := h.Hash(data)
		return out[:6]
	}

	data, _ := hex.DecodeString(stub)
	out := h.Hash(data)
	return out[:6]
}

func GetQueryHash(query string) []byte {
	h := crypto.New()

	if query == "" {
		data := make([]byte, 16)
		out := h.Hash(data)
		// fmt.Printf("[GO] get_queryhash input (no query): %x\n", data)
		// fmt.Printf("[GO] get_queryhash full hash: %x\n", out)
		// fmt.Printf("[GO] get_queryhash sliced: %x\n", out[:6])
		return out[:6]
	}

	data := []byte(query)
	out := h.Hash(data)
	// fmt.Printf("[GO] get_queryhash input: %x\n", data)
	// fmt.Printf("[GO] get_queryhash full hash: %x\n", out)
	// fmt.Printf("[GO] get_queryhash sliced: %x\n", out[:6])
	return out[:6]
}

// ------------------------------------------------------------
// AES-CBC with MD5(key), MD5(iv)
// ------------------------------------------------------------
func aesCBCEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext = pkcs7Pad(plaintext, aes.BlockSize)

	out := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(out, plaintext)
	// fmt.Println("[aesCBCEncrypt] Return Value:")
	// fmt.Println("out")
	return out, nil
}

// ------------------------------------------------------------
// Encrypt() — main Argus encoder
// ------------------------------------------------------------
func Encrypt(x map[int]any) (string, error) {
	// fmt.Println("ARGUS BEAN:")
	// fmt.Println(x)
	// Build ProtoBuf (your implementation has no constructor!)
	pb := &ProtoBuf{Fields: []*ProtoField{}}

	keys := []int{
		1, 2, 3, 4, 5, 6, 7, 8, 9,
		10, 12, 13, 14, 16, 20, 21, 25,
	}

	for _, k := range keys {
		v := x[k]

		switch t := v.(type) {
		case int:
			pb.PutVarint(k, uint64(t))
		case int64:
			pb.PutVarint(k, uint64(t))
		case uint64:
			pb.PutVarint(k, t)
		case string:
			pb.PutUtf8(k, t)
		case []byte:
			pb.PutBytes(k, t)
		case map[int]any:
			sub := &ProtoBuf{Fields: []*ProtoField{}}

			// ⚠️ nested maps ALSO need ordered keys if used
			subKeys := []int{ /* explicit order if present */ }
			for _, kk := range subKeys {
				vv := t[kk]
				switch tv := vv.(type) {
				case int:
					sub.PutVarint(kk, uint64(tv))
				case int64:
					sub.PutVarint(kk, uint64(tv))
				case uint64:
					sub.PutVarint(kk, tv)
				case string:
					sub.PutUtf8(kk, tv)
				case []byte:
					sub.PutBytes(kk, tv)
				}
			}

			subBytes, _ := sub.ToBytes()
			pb.PutBytes(k, subBytes)
		}
	}

	// The unpadded protobuf string
	raw, _ := pb.ToBytes()

	//Padded protobuf string
	protobuf := pkcs7Pad(raw, aes.BlockSize)
	n := len(protobuf)

	// fmt.Printf("Protobuf: %x\n", protobuf)

	// Fixed sign key
	signKey := []byte{
		0xac, 0x1a, 0xda, 0xae, 0x95, 0xa7, 0xaf, 0x94,
		0xa5, 0x11, 0x4a, 0xb3, 0xb3, 0xa9, 0x7d, 0xd8,
		0x00, 0x50, 0xaa, 0x0a, 0x39, 0x31, 0x4c, 0x40,
		0x52, 0x8c, 0xae, 0xc9, 0x52, 0x56, 0xc2, 0x8c,
	}

	sm3Output := []byte{
		0xfc, 0x78, 0xe0, 0xa9, 0x65, 0x7a, 0x0c, 0x74,
		0x8c, 0xe5, 0x15, 0x59, 0x90, 0x3c, 0xcf, 0x03,
		0x51, 0x0e, 0x51, 0xd3, 0xcf, 0xf2, 0x32, 0xd7,
		0x13, 0x43, 0xe8, 0x8a, 0x32, 0x1c, 0x53, 0x04,
	}

	// Build SIMON key list (<QQ>, <QQ>)
	keyList := [4]uint64{
		binary.LittleEndian.Uint64(sm3Output[0:8]),
		binary.LittleEndian.Uint64(sm3Output[8:16]),
		binary.LittleEndian.Uint64(sm3Output[16:24]),
		binary.LittleEndian.Uint64(sm3Output[24:32]),
	}
	// fmt.Println("[GO][ARGUS] SIMON KEY LIST")
	// fmt.Println(keyList)

	encPB := make([]byte, n)

	for i := 0; i < n/16; i++ {
		pt0 := binary.LittleEndian.Uint64(protobuf[i*16 : i*16+8])
		pt1 := binary.LittleEndian.Uint64(protobuf[i*16+8 : i*16+16])

		ct := crypto.SimonEnc([2]uint64{pt0, pt1}, keyList, 0)

		binary.LittleEndian.PutUint64(encPB[i*16:], ct[0])
		binary.LittleEndian.PutUint64(encPB[i*16+8:], ct[1])
	}

	// fmt.Printf("ENC_PB Hex: %x\n", encPB)

	// prefix + encrypt_enc_pb + wrap with header/footer
	buf := append([]byte{0xf2, 0xf7, 0xfc, 0xff, 0xf2, 0xf7, 0xfc, 0xff}, encPB...)
	buf = encryptEncPB(buf, n+8)

	buf = append([]byte{0xa6, 0x6e, 0xad, 0x9f, 0x77, 0x01, 0xd0, 0x0c, 0x18}, buf...)
	buf = append(buf, []byte("ao")...)

	// fmt.Printf("Wrapped ENC_PB Buffer: %x\n", buf)

	// AES-CBC
	key := md5.Sum(signKey[:16])
	iv := md5.Sum(signKey[16:])
	// fmt.Printf("[GO] AES Sign Key (Hex): len=%d, hex=%x\n", len(key), key)
	// fmt.Printf("[GO] AES IV (Hex): len=%d, hex=%x\n", len(iv), iv)

	ciphertext, err := aesCBCEncrypt(key[:], iv[:], buf)
	if err != nil {
		return "", err
	}
	// fmt.Printf("[GO] AES Ciphertext: %x\n", ciphertext)

	final := append([]byte{0xf2, 0x81}, ciphertext...)

	return base64.StdEncoding.EncodeToString(final), nil
}

// ------------------------------------------------------------
// GetSign — identical to Python Argus.get_sign()
// ------------------------------------------------------------
func GetSign(
	queryhash string,
	data string,
	timestamp int64,
	aid int,
	licenseID int,
	platform int,
	secDeviceID string,
	sdkVersion string,
	sdkVersionInt int,
) (string, error) {

	params, _ := url.ParseQuery(queryhash)

	deviceID := params["device_id"][0]
	versionName := "39.6.3"

	x := map[int]any{
		1:  uint64(0x20200929) << 1,
		2:  2,
		3:  rand.Int31(),
		4:  strconv.Itoa(aid),
		5:  deviceID,
		6:  strconv.Itoa(licenseID),
		7:  versionName,
		8:  sdkVersion,
		9:  sdkVersionInt,
		10: make([]byte, 8),
		12: uint64(timestamp) << 1,
		13: GetBodyHash(data),
		14: GetQueryHash(queryhash),
		16: secDeviceID,
		20: "none",
		21: 738,
		25: 2,
	}

	return Encrypt(x)
}
