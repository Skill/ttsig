package signer

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

type Gorgon struct {
	Unix    int64
	Params  string
	Data    string
	Cookies string
}

// -----------------------------
// Python: hashlib.md5(...).hexdigest()
// -----------------------------
func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// -----------------------------
// Python: get_base_string()
// -----------------------------
func (g *Gorgon) getBaseString() string {
	base := md5Hex(g.Params)

	if g.Data != "" {
		base += md5Hex(g.Data)
	} else {
		base += strings.Repeat("0", 32)
	}

	if g.Cookies != "" {
		base += md5Hex(g.Cookies)
	} else {
		base += strings.Repeat("0", 32)
	}

	return base
}

// -----------------------------
// Python: reverse()
// -----------------------------
func reverseByte(b byte) byte {
	hi := b >> 4
	lo := b & 0x0F
	return (lo << 4) | hi
}

// -----------------------------
// Python: rbit_algorithm()
// -----------------------------
func rbit(num byte) byte {
	var out byte
	for i := 0; i < 8; i++ {
		out <<= 1
		out |= (num >> i) & 1
	}
	return out
}

// -----------------------------
// Python: encrypt()
// -----------------------------
func (g *Gorgon) encrypt(base string) map[string]string {
	length := 0x14

	key := []byte{
		0xDF, 0x77, 0xB9, 0x40, 0xB9,
		0x9B, 0x84, 0x83, 0xD1, 0xB9,
		0xCB, 0xD1, 0xF7, 0xC2, 0xB9,
		0x85, 0xC3, 0xD0, 0xFB, 0xC3,
	}

	paramList := make([]byte, 0, length)

	// Python:
	// for i in range(0, 12, 4):
	for i := 0; i < 12; i += 4 {
		// temp = data[8*i : 8*(i+1)]
		temp := base[8*i : 8*(i+1)]

		for j := 0; j < 4; j++ {
			h, _ := strconv.ParseUint(temp[j*2:(j+1)*2], 16, 8)
			paramList = append(paramList, byte(h))
		}
	}

	// param_list.extend([0x0, 0x6, 0xB, 0x1C])
	paramList = append(paramList, 0x0, 0x6, 0x0B, 0x1C)

	// H = int(hex(int(self.unix)), 16)
	H := uint32(g.Unix)
	paramList = append(paramList,
		byte((H>>24)&0xFF),
		byte((H>>16)&0xFF),
		byte((H>>8)&0xFF),
		byte(H&0xFF),
	)

	// eor_result_list = [A ^ B]
	eor := make([]byte, length)
	for i := 0; i < length; i++ {
		eor[i] = paramList[i] ^ key[i]
	}

	// main transform loop
	for i := 0; i < length; i++ {
		C := reverseByte(eor[i])
		D := eor[(i+1)%length]
		E := C ^ D
		F := rbit(E)
		H := byte(((^uint32(F)) ^ uint32(length)) & 0xFF)
		eor[i] = H
	}

	var result strings.Builder
	for _, b := range eor {
		result.WriteString(fmt.Sprintf("%02x", b))
	}

	return map[string]string{
		"x-ss-req-ticket": fmt.Sprintf("%d", g.Unix*1000),
		"x-khronos":       fmt.Sprintf("%d", g.Unix),
		"x-gorgon":        "0404b0d30000" + result.String(),
	}
}

// -----------------------------
// Python: get_value()
// -----------------------------
func (g *Gorgon) GetValue() map[string]string {
	base := g.getBaseString()
	return g.encrypt(base)
}
