// simon.go
package crypto

import "math/bits"

// getBit returns the bit at position pos (0 or 1) from val.
func getBit(val uint64, pos uint) uint64 {
	return (val >> pos) & 1
}

// rotateLeft is a 64-bit left rotation.
func rotateLeft(v uint64, n uint) uint64 {
	return bits.RotateLeft64(v, int(n))
}

// rotateRight is a 64-bit right rotation.
func rotateRight(v uint64, n uint) uint64 {
	return bits.RotateLeft64(v, -int(n))
}

// keyExpansion mutates the key slice in place.
// key must have length at least 72.
func keyExpansion(key []uint64) {
	const z uint64 = 0x3DC94C3A046D678B

	for i := 4; i < 72; i++ {
		tmp := rotateRight(key[i-1], 3)
		tmp ^= key[i-3]
		tmp ^= rotateRight(tmp, 1)

		bit := getBit(z, uint((i-4)%62))

		// c_ulonglong(~key[i-4]).value in Python == ^key[i-4] in Go (on uint64)
		key[i] = ^key[i-4] ^ tmp ^ bit ^ 3
	}
}

// SimonDec is the Go equivalent of simon_dec.
// ct: [2]uint64 ciphertext block
// k:  [4]uint64 key words
// c:  mode flag (0 or 1) as in the Python version
func SimonDec(ct [2]uint64, k [4]uint64, c int) [2]uint64 {
	var key [72]uint64
	key[0] = k[0]
	key[1] = k[1]
	key[2] = k[2]
	key[3] = k[3]

	keyExpansion(key[:])

	x := ct[0]
	y := ct[1]

	for i := 72 - 1; i >= 0; i-- {
		tmp := x

		var f uint64
		if c == 1 {
			f = rotateLeft(x, 1)
		} else {
			f = rotateLeft(x, 1) & rotateLeft(x, 8)
		}

		x = y ^ f ^ rotateLeft(x, 2) ^ key[i]
		y = tmp
	}

	return [2]uint64{x, y}
}

// SimonEnc is the Go equivalent of simon_enc.
// pt: [2]uint64 plaintext block
// k:  [4]uint64 key words
// c:  mode flag (0 or 1) as in the Python version
func SimonEnc(pt [2]uint64, k [4]uint64, c int) [2]uint64 {
	var key [72]uint64
	key[0] = k[0]
	key[1] = k[1]
	key[2] = k[2]
	key[3] = k[3]

	keyExpansion(key[:])

	x := pt[0]
	y := pt[1]

	for i := 0; i < 72; i++ {
		tmp := y

		var f uint64
		if c == 1 {
			f = rotateLeft(y, 1)
		} else {
			f = rotateLeft(y, 1) & rotateLeft(y, 8)
		}

		y = x ^ f ^ rotateLeft(y, 2) ^ key[i]
		x = tmp
	}

	return [2]uint64{x, y}
}
