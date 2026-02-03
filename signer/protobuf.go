package signer

import (
	"encoding/binary"
	"fmt"
)

// ------------------------------------------------------------
// ProtoError (Go idiomatic error type)
// ------------------------------------------------------------

type ProtoError struct {
	Msg string
}

func (e *ProtoError) Error() string {
	return fmt.Sprintf("%q", e.Msg) // repr()-style quoting
}

// ------------------------------------------------------------
// Field Types
// ------------------------------------------------------------

type ProtoFieldType int

const (
	TypeVarint     ProtoFieldType = 0
	TypeInt64      ProtoFieldType = 1
	TypeString     ProtoFieldType = 2
	TypeGroupStart ProtoFieldType = 3
	TypeGroupEnd   ProtoFieldType = 4
	TypeInt32      ProtoFieldType = 5
	TypeError1     ProtoFieldType = 6
	TypeError2     ProtoFieldType = 7
)

func (t ProtoFieldType) String() string {
	switch t {
	case TypeVarint:
		return "VARINT"
	case TypeInt64:
		return "INT64"
	case TypeString:
		return "STRING"
	case TypeGroupStart:
		return "GROUPSTART"
	case TypeGroupEnd:
		return "GROUPEND"
	case TypeInt32:
		return "INT32"
	case TypeError1:
		return "ERROR1"
	case TypeError2:
		return "ERROR2"
	}
	return fmt.Sprintf("UNKNOWN(%d)", int(t))
}

// ------------------------------------------------------------
// ProtoField
// ------------------------------------------------------------

type ProtoField struct {
	Idx      int
	Type     ProtoFieldType
	IntVal   uint64
	BytesVal []byte
}

func (pf *ProtoField) IsAscii() bool {
	for _, b := range pf.BytesVal {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

func (pf *ProtoField) String() string {
	switch pf.Type {
	case TypeInt32, TypeInt64, TypeVarint:
		return fmt.Sprintf("%d(%s): %d", pf.Idx, pf.Type, pf.IntVal)

	case TypeString:
		if pf.IsAscii() {
			return fmt.Sprintf(`%d(%s): "%s"`, pf.Idx, pf.Type, string(pf.BytesVal))
		}
		return fmt.Sprintf(`%d(%s): h"%x"`, pf.Idx, pf.Type, pf.BytesVal)

	default:
		return fmt.Sprintf("%d(%s): %v", pf.Idx, pf.Type, pf.IntVal)
	}
}

// ------------------------------------------------------------
// ProtoReader
// ------------------------------------------------------------

type ProtoReader struct {
	data []byte
	pos  int
}

func NewProtoReader(b []byte) *ProtoReader {
	return &ProtoReader{data: b}
}

func (r *ProtoReader) remain(n int) bool {
	return r.pos+n <= len(r.data)
}

func (r *ProtoReader) readByte() byte {
	if !r.remain(1) {
		panic("readByte: EOF")
	}
	b := r.data[r.pos]
	r.pos++
	return b
}

func (r *ProtoReader) read(n int) []byte {
	if !r.remain(n) {
		panic("read: EOF")
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b
}

func (r *ProtoReader) ReadInt32() uint32 {
	return binary.LittleEndian.Uint32(r.read(4))
}

func (r *ProtoReader) ReadInt64() uint64 {
	return binary.LittleEndian.Uint64(r.read(8))
}

func (r *ProtoReader) ReadVarint() uint64 {
	var v uint64
	var shift uint

	for {
		b := r.readByte()
		v |= uint64(b&0x7F) << shift
		if b < 0x80 {
			break
		}
		shift += 7
	}

	return v
}

func (r *ProtoReader) ReadString() []byte {
	l := r.ReadVarint()
	return r.read(int(l))
}

// ------------------------------------------------------------
// ProtoWriter
// ------------------------------------------------------------

type ProtoWriter struct {
	data []byte
}

func NewProtoWriter() *ProtoWriter {
	return &ProtoWriter{data: make([]byte, 0)}
}

func (w *ProtoWriter) writeByte(b byte) {
	w.data = append(w.data, b)
}

func (w *ProtoWriter) write(bs []byte) {
	w.data = append(w.data, bs...)
}

func (w *ProtoWriter) WriteInt32(v uint32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	w.write(buf[:])
}

func (w *ProtoWriter) WriteInt64(v uint64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	w.write(buf[:])
}

func (w *ProtoWriter) WriteVarint(v uint64) {
	v &= 0xFFFFFFFF // match Python masking
	for v > 0x80 {
		w.writeByte(byte(v&0x7F) | 0x80)
		v >>= 7
	}
	w.writeByte(byte(v & 0x7F))
}

func (w *ProtoWriter) WriteString(b []byte) {
	w.WriteVarint(uint64(len(b)))
	w.write(b)
}

func (w *ProtoWriter) Bytes() []byte {
	return append([]byte(nil), w.data...)
}

// ------------------------------------------------------------
// ProtoBuf (main container)
// ------------------------------------------------------------

type ProtoBuf struct {
	Fields []*ProtoField
}

func NewProtoBufFromBytes(data []byte) (*ProtoBuf, error) {
	pb := &ProtoBuf{Fields: make([]*ProtoField, 0)}
	if len(data) > 0 {
		if err := pb.parseBytes(data); err != nil {
			return nil, err
		}
	}
	return pb, nil
}

func (pb *ProtoBuf) parseBytes(data []byte) error {
	r := NewProtoReader(data)

	for r.remain(1) {
		key := r.ReadVarint()
		ftype := ProtoFieldType(key & 7)
		idx := int(key >> 3)
		fmt.Printf("[Go] Parsing field idx=%d type=%s\n", idx, ftype)

		if idx == 0 {
			break
		}

		switch ftype {
		case TypeInt32:
			val := uint64(r.ReadInt32())
			// fmt.Printf("[Go] Parsed INT32 val=%d\n", val)
			pb.Put(&ProtoField{Idx: idx, Type: ftype, IntVal: val})
		case TypeInt64:
			val := r.ReadInt64()
			// fmt.Printf("[Go] Parsed INT64 val=%d\n", val)
			pb.Put(&ProtoField{Idx: idx, Type: ftype, IntVal: val})
		case TypeVarint:
			val := r.ReadVarint()
			// fmt.Printf("[Go] Parsed VARINT val=%d\n", val)
			pb.Put(&ProtoField{Idx: idx, Type: ftype, IntVal: val})
		case TypeString:
			val := r.ReadString()
			// fmt.Printf("[Go] Parsed STRING val=%x\n", val)
			pb.Put(&ProtoField{Idx: idx, Type: ftype, BytesVal: val})
		default:
			return &ProtoError{Msg: "unexpected protobuf field type"}
		}
	}

	return nil
}

// ------------------------------------------------------------
// ProtoBuf → bytes
// ------------------------------------------------------------

func (pb *ProtoBuf) ToBytes() ([]byte, error) {
	w := NewProtoWriter()

	for _, f := range pb.Fields {
		key := (uint64(f.Idx) << 3) | uint64(f.Type)
		// fmt.Printf("[Go] Writing field idx=%d type=%s key=%d\n", f.Idx, f.Type, key)
		w.WriteVarint(key)

		switch f.Type {
		case TypeInt32:
			// fmt.Printf("[Go] Write INT32 val=%d\n", f.IntVal)
			w.WriteInt32(uint32(f.IntVal))
		case TypeInt64:
			// fmt.Printf("[Go] Write INT64 val=%d\n", f.IntVal)
			w.WriteInt64(f.IntVal)
		case TypeVarint:
			// fmt.Printf("[Go] Write VARINT val=%d\n", f.IntVal)
			w.WriteVarint(f.IntVal)
		case TypeString:
			// fmt.Printf("[Go] Write STRING val=%x\n", f.BytesVal)
			w.WriteString(f.BytesVal)
		default:
			return nil, &ProtoError{Msg: "unexpected field type in encoder"}
		}
	}

	return w.Bytes(), nil
}

// ------------------------------------------------------------
// Field getters / setters
// ------------------------------------------------------------

func (pb *ProtoBuf) Put(f *ProtoField) {
	pb.Fields = append(pb.Fields, f)
}

func (pb *ProtoBuf) Get(idx int) *ProtoField {
	for _, f := range pb.Fields {
		if f.Idx == idx {
			return f
		}
	}
	return nil
}

func (pb *ProtoBuf) GetInt(idx int) (uint64, error) {
	f := pb.Get(idx)
	if f == nil {
		return 0, nil
	}
	switch f.Type {
	case TypeInt32, TypeInt64, TypeVarint:
		return f.IntVal, nil
	}
	return 0, &ProtoError{Msg: "field is not integer"}
}

func (pb *ProtoBuf) GetBytes(idx int) ([]byte, error) {
	f := pb.Get(idx)
	if f == nil {
		return nil, nil
	}
	if f.Type != TypeString {
		return nil, &ProtoError{Msg: "field is not string"}
	}
	return f.BytesVal, nil
}

func (pb *ProtoBuf) GetUtf8(idx int) (string, error) {
	bs, err := pb.GetBytes(idx)
	if err != nil {
		return "", err
	}
	if bs == nil {
		return "", nil
	}
	return string(bs), nil
}

// ------------------------------------------------------------
// Writing helpers
// ------------------------------------------------------------

func (pb *ProtoBuf) PutInt32(idx int, v uint32) {
	pb.Put(&ProtoField{Idx: idx, Type: TypeInt32, IntVal: uint64(v)})
}

func (pb *ProtoBuf) PutInt64(idx int, v uint64) {
	pb.Put(&ProtoField{Idx: idx, Type: TypeInt64, IntVal: v})
}

func (pb *ProtoBuf) PutVarint(idx int, v uint64) {
	pb.Put(&ProtoField{Idx: idx, Type: TypeVarint, IntVal: v})
}

func (pb *ProtoBuf) PutBytes(idx int, b []byte) {
	pb.Put(&ProtoField{Idx: idx, Type: TypeString, BytesVal: b})
}

func (pb *ProtoBuf) PutUtf8(idx int, s string) {
	pb.Put(&ProtoField{Idx: idx, Type: TypeString, BytesVal: []byte(s)})
}
