package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
)

const (
	h0 uint32 = 0x67452301
	h1 uint32 = 0xEFCDAB89
	h2 uint32 = 0x98BADCFE
	h3 uint32 = 0x10325476
	h4 uint32 = 0xC3D2E1F0
)

func getSHA1hash(s string) []byte {
	message := []byte(s)
	digest := make([]byte, 20)
	message = append(message, 1<<7)
	for len(message)%64 != 56 {
		message = append(message, 0)
	}
	message = append(message, P64(uint64(len(s))*8)...)
	h := [5]uint32{h0, h1, h2, h3, h4}
	for i := 0; i != len(message); i += 64 {
		bloc := message[i : i+64]
		w := make([]uint32, 80)
		for i := 0; i <= 15; i++ {
			w[i] = binary.BigEndian.Uint32(bloc[i*4 : 4*i+4])
		}
		for i := 16; i < 80; i++ {
			w[i] = bits.RotateLeft32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1)
		}
		a := h[0]
		b := h[1]
		c := h[2]
		d := h[3]
		e := h[4]

		for i := 0; i <= 79; i++ {
			var f, k uint32
			if i <= 19 {
				f = (b & c) | ((^b) & d)
				k = 0x5A827999
			} else if i <= 39 {
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			} else if i <= 59 {
				f = (b & c) | (b & d) | (c & d)
				k = 0x8F1BBCDC
			} else {
				f = b ^ c ^ d
				k = 0xCA62C1D6
			}
			temp := bits.RotateLeft32(a, 5) + f + e + k + w[i]
			e = d
			d = c
			c = bits.RotateLeft32(b, 30)
			b = a
			a = temp
		}
		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
		h[4] += e
	}
	binary.BigEndian.PutUint32(digest[0:4], h[0])
	binary.BigEndian.PutUint32(digest[4:8], h[1])
	binary.BigEndian.PutUint32(digest[8:12], h[2])
	binary.BigEndian.PutUint32(digest[12:16], h[3])
	binary.BigEndian.PutUint32(digest[16:20], h[4])
	return digest
}
func P64(n uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, n)
	return b
}

func main() {
	s := "В чащах юга жил бы цитрус? Да, но фальшивый экземпляр!"
	fmt.Println(hex.EncodeToString(getSHA1hash(s)))
}
