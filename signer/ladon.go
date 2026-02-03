package signer

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/bits"
	"strconv"
)

// ------------------------------------------------------------
// Helpers: md5, typed access, rotation, validation
// ------------------------------------------------------------

// md5Bytes is equivalent to Python's md5bytes(data) -> hexdigest string.
func md5Bytes(data []byte) string {
	sum := md5.Sum(data)
	return fmt.Sprintf("%x", sum) // lower-case hex like hashlib.md5().hexdigest()
}

// getTypeData implements get_type_data for "uint64_t".
func getTypeData(buf []byte, index int, dataType string) (uint64, error) {
	if dataType != "uint64_t" {
		return 0, fmt.Errorf("invalid data type: %s", dataType)
	}
	offset := index * 8
	if offset+8 > len(buf) {
		return 0, fmt.Errorf("getTypeData: index out of range")
	}
	return binary.LittleEndian.Uint64(buf[offset : offset+8]), nil
}

// setTypeData implements set_type_data for "uint64_t".
func setTypeData(buf []byte, index int, data uint64, dataType string) error {
	if dataType != "uint64_t" {
		return fmt.Errorf("invalid data type: %s", dataType)
	}
	offset := index * 8
	if offset+8 > len(buf) {
		return fmt.Errorf("setTypeData: index out of range")
	}
	binary.LittleEndian.PutUint64(buf[offset:offset+8], data)
	return nil
}

// validate(num) in Python masks to 64 bits. In Go uint64 already wraps, but we keep it for clarity.
func validate(num uint64) uint64 {
	return num & 0xFFFFFFFFFFFFFFFF
}

// ror64 is equivalent to __ROR__(ctypes.c_ulonglong, count).
func ror64(value uint64, count int) uint64 {
	// bits.RotateLeft64 with a negative count is a right rotation.
	return bits.RotateLeft64(value, -count)
}

// ------------------------------------------------------------
// Core block function: encrypt_ladon_input
// ------------------------------------------------------------

// encryptLadonInput is equivalent to encrypt_ladon_input(hash_table, input_data).
// hashTable is expected to contain at least (0x22) 8-byte entries (i.e. 0x22*8 bytes).
// inputBlock must be exactly 16 bytes.
func encryptLadonInput(hashTable []byte, inputBlock []byte) ([]byte, error) {
	if len(inputBlock) != 16 {
		return nil, fmt.Errorf("encryptLadonInput: input block must be 16 bytes")
	}

	data0 := binary.LittleEndian.Uint64(inputBlock[0:8])
	data1 := binary.LittleEndian.Uint64(inputBlock[8:16])

	for i := 0; i < 0x22; i++ {
		hash, err := getTypeData(hashTable, i, "uint64_t")
		if err != nil {
			return nil, err
		}

		// data1 = validate(hash ^ (data0 + ((data1 >> 8) | (data1 << (64 - 8)))))
		data1 = validate(hash ^ (data0 + ((data1 >> 8) | (data1 << (64 - 8)))))

		// data0 = validate(data1 ^ ((data0 >> 0x3D) | (data0 << (64 - 0x3D))))
		data0 = validate(data1 ^ ((data0 >> 0x3D) | (data0 << (64 - 0x3D))))
	}

	out := make([]byte, 16)
	binary.LittleEndian.PutUint64(out[0:8], data0)
	binary.LittleEndian.PutUint64(out[8:16], data1)
	return out, nil
}

// ------------------------------------------------------------
// Main encrypt_ladon (MD5-based key schedule + PKCS7 + block loop)
// ------------------------------------------------------------

// encryptLadon is equivalent to encrypt_ladon(md5hex: bytes, data: bytes, size: int) in Python.
// NOTE: md5Hex here must be the same bytes as Python's `md5bytes(keygen).encode()`
// i.e. 32 ASCII hex characters, not raw 16-byte MD5.
func encryptLadon(md5Hex []byte, data []byte) ([]byte, error) {
	size := len(data)

	// hash_table = bytearray(272 + 16)
	hashTable := make([]byte, 272+16)

	// hash_table[:32] = md5hex
	copy(hashTable[:32], md5Hex)

	// temp = [first four uint64s of hash_table]
	temp := make([]uint64, 0, 4+0x22)
	for i := 0; i < 4; i++ {
		v, err := getTypeData(hashTable, i, "uint64_t")
		if err != nil {
			return nil, err
		}
		temp = append(temp, v)
	}

	bufferB0 := temp[0]
	bufferB8 := temp[1]
	temp = temp[2:] // pop first two

	// for i in range(0, 0x22)
	for i := 0; i < 0x22; i++ {
		x9 := bufferB0
		x8 := bufferB8

		// x8 = validate(__ROR__(x8, 8))
		x8 = validate(ror64(x8, 8))

		// x8 = validate(x8 + x9)
		x8 = validate(x8 + x9)

		// x8 = validate(x8 ^ i)
		x8 = validate(x8 ^ uint64(i))

		// temp.append(x8)
		temp = append(temp, x8)

		// x8 = validate(x8 ^ __ROR__(x9, 61))
		x8 = validate(x8 ^ ror64(x9, 61))

		// set_type_data(hash_table, i + 1, x8, "uint64_t")
		if err := setTypeData(hashTable, i+1, x8, "uint64_t"); err != nil {
			return nil, err
		}

		// buffer_b0 = x8
		bufferB0 = x8

		// buffer_b8 = temp[0]; temp.pop(0)
		bufferB8 = temp[0]
		temp = temp[1:]
	}

	// padding_size(size)
	paddingSize := func(size int) int {
		mod := size % 16
		if mod > 0 {
			return size + (16 - mod)
		}
		return size
	}

	// pkcs7_padding_pad_buffer
	pkcs7Pad := func(buf []byte, dataLen int, bufferSize int, modulus int) (int, error) {
		padByte := modulus - (dataLen % modulus)
		if dataLen+padByte > bufferSize {
			// Python returns -pad_byte, but the caller does not use it for error handling;
			// in Go we'll just surface an error.
			return 0, fmt.Errorf("pkcs7Pad: data too large for buffer")
		}
		for i := 0; i < padByte; i++ {
			buf[dataLen+i] = byte(padByte)
		}
		return padByte, nil
	}

	newSize := paddingSize(size)

	// input = bytearray(new_size); input[:size] = data; pkcs7_pad(...)
	input := make([]byte, newSize)
	copy(input[:size], data)
	if _, err := pkcs7Pad(input, size, newSize, 16); err != nil {
		return nil, err
	}

	// output[i*16:(i+1)*16] = encrypt_ladon_input(...)
	output := make([]byte, newSize)
	for i := 0; i < newSize/16; i++ {
		block := input[i*16 : (i+1)*16]
		enc, err := encryptLadonInput(hashTable, block)
		if err != nil {
			return nil, err
		}
		copy(output[i*16:], enc)
	}

	return output, nil
}

// ------------------------------------------------------------
// Top-level ladon_encrypt API
// ------------------------------------------------------------

// LadonEncryptWithRandom is equivalent to:
// ladon_encrypt(khronos, lc_id, aid, random_bytes=given)
func LadonEncryptWithRandom(khronos, lcID, aid int64, randomBytes []byte) (string, error) {

	// data = f"{khronos}-{lc_id}-{aid}"
	data := fmt.Sprintf("%d-%d-%d", khronos, lcID, aid)

	// keygen = random_bytes + str(aid).encode()
	keygen := make([]byte, 0, len(randomBytes)+16)
	keygen = append(keygen, randomBytes...)
	keygen = append(keygen, []byte(strconv.FormatInt(aid, 10))...)

	// md5hex = md5bytes(keygen)  (this is hex string)
	md5hex := md5Bytes(keygen)

	// encrypt_ladon(md5hex.encode(), data.encode(), size)
	cipher, err := encryptLadon([]byte(md5hex), []byte(data))
	if err != nil {
		return "", err
	}

	// output = random_bytes + cipher, then base64
	out := make([]byte, len(cipher)+4)
	copy(out[:4], randomBytes)
	copy(out[4:], cipher)

	return base64.StdEncoding.EncodeToString(out), nil
}

// LadonEncrypt is equivalent to Python ladon_encrypt(khronos, lc_id, aid)
// using urandom(4) internally.
func LadonEncrypt(khronos, lcID, aid int64) (string, error) {
	randBytes := make([]byte, 4)
	if _, err := rand.Read(randBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return LadonEncryptWithRandom(khronos, lcID, aid, randBytes)
}

// Ladon type with an Encrypt method, mirroring the Python class Ladon.encrypt.
type Ladon struct{}

// Encrypt mirrors Ladon.encrypt(x_khronos, lc_id, aid) -> str.
func (Ladon) Encrypt(xKhronos, lcID, aid int64) (string, error) {
	return LadonEncrypt(xKhronos, lcID, aid)
}
