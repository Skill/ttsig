// SM3 is a hashing function developed by the State Cryptograph Administration in China.
// Further reading: https://en.wikipedia.org/wiki/SM3_(hash_function)

package crypto

type SM3 struct {
	iv [8]uint32
	tj [64]uint32
}

//	func New() *SM3 {
//		return &SM3{
//			iv: [8]uint32{
//				1937774191, 1226093241, 388252375, 3666478592,
//				2842636476, 372324522, 3817729613, 2969243214,
//			},
//			tj: [64]uint32{
//				2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042},
//		}
//	}
func New() *SM3 {
	s := &SM3{
		iv: [8]uint32{
			1937774191, 1226093241, 388252375, 3666478592,
			2842636476, 372324522, 3817729613, 2969243214,
		},
	}

	// TJ schedule: 0..15 = 0x79cc4519, 16..63 = 0x7a879d8a
	for i := 0; i < 64; i++ {
		if i < 16 {
			s.tj[i] = 2043430169
		} else {
			s.tj[i] = 2055708042
		}
	}

	return s
}

func (s *SM3) rotateLeft(x uint32, k int) uint32 {
	k = k % 32
	return ((x << k) & 0xFFFFFFFF) | ((x & 0xFFFFFFFF) >> (32 - k))
}

func (s *SM3) ffj(x, y, z uint32, j int) uint32 {
	if j < 16 {
		return x ^ y ^ z
	}
	return (x & y) | (x & z) | (y & z)
}

func (s *SM3) ggj(x, y, z uint32, j int) uint32 {
	if j < 16 {
		return x ^ y ^ z
	}
	return (x & y) | ((^x) & z)
}

func (s *SM3) p0(x uint32) uint32 {
	return x ^ s.rotateLeft(x, 9) ^ s.rotateLeft(x, 17)
}

func (s *SM3) p1(x uint32) uint32 {
	return x ^ s.rotateLeft(x, 15) ^ s.rotateLeft(x, 23)
}

func (s *SM3) cf(Vi [8]uint32, Bi []byte) [8]uint32 {
	var W [68]uint32
	var W1 [64]uint32

	// 1) W[0..15]
	for i := 0; i < 16; i++ {
		W[i] = uint32(Bi[i*4])<<24 |
			uint32(Bi[i*4+1])<<16 |
			uint32(Bi[i*4+2])<<8 |
			uint32(Bi[i*4+3])
	}

	// 2) W[16..67]
	for j := 16; j < 68; j++ {
		W[j] = s.p1(W[j-16]^W[j-9]^s.rotateLeft(W[j-3], 15)) ^
			s.rotateLeft(W[j-13], 7) ^
			W[j-6]
	}

	// 3) W1[0..63]
	for j := 0; j < 64; j++ {
		W1[j] = W[j] ^ W[j+4]
	}

	// 4) Registers
	A, B, C, D := Vi[0], Vi[1], Vi[2], Vi[3]
	E, F, G, H := Vi[4], Vi[5], Vi[6], Vi[7]

	// 5) Compression (j=0..63)
	for j := 0; j < 64; j++ {
		SS1 := s.rotateLeft((s.rotateLeft(A, 12)+E+s.rotateLeft(s.tj[j], j))&0xFFFFFFFF, 7)
		SS2 := SS1 ^ s.rotateLeft(A, 12)

		TT1 := (s.ffj(A, B, C, j) + D + SS2 + W1[j]) & 0xFFFFFFFF
		TT2 := (s.ggj(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF

		// Round debug: print the exact rounds that will expose tj tail issues

		D = C
		C = s.rotateLeft(B, 9)
		B = A
		A = TT1
		H = G
		G = s.rotateLeft(F, 19)
		F = E
		E = s.p0(TT2)

		if j == 0 || j == 1 || j == 2 || j == 15 || j == 16 || j == 60 || j == 61 || j == 62 || j == 63 {

		}
	}

	// 6) XOR with Vi
	return [8]uint32{
		A ^ Vi[0],
		B ^ Vi[1],
		C ^ Vi[2],
		D ^ Vi[3],
		E ^ Vi[4],
		F ^ Vi[5],
		G ^ Vi[6],
		H ^ Vi[7],
	}
}

// sm3Hash computes SM3(msg) and returns the 32-byte digest.
// This matches Python SM3.sm3_hash exactly.
func (s *SM3) sm3Hash(msg []byte) []byte {
	// Copy original message
	m := make([]byte, len(msg))
	copy(m, msg)

	// Original length in bits
	bitLen := uint64(len(m)) * 8

	// Append 0x80
	m = append(m, 0x80)

	// Pad with zeros until len(m) % 64 == 56
	for (len(m) % 64) != 56 {
		m = append(m, 0x00)
	}

	// Append 64-bit big-endian bit length
	var blk [8]byte
	for i := 0; i < 8; i++ {
		blk[7-i] = byte(bitLen >> (8 * i))
	}
	m = append(m, blk[:]...)

	blockCount := len(m) / 64

	// Process blocks
	V := s.iv
	for i := 0; i < blockCount; i++ {
		block := m[i*64 : (i+1)*64]

		V = s.cf(V, block)

	}

	// Output as big-endian 32-byte digest
	out := make([]byte, 32)
	for i := 0; i < 8; i++ {
		out[i*4+0] = byte(V[i] >> 24)
		out[i*4+1] = byte(V[i] >> 16)
		out[i*4+2] = byte(V[i] >> 8)
		out[i*4+3] = byte(V[i])
	}

	return out
}

func (s *SM3) Hash(msg []byte) []byte {
	return s.sm3Hash(msg)
}
