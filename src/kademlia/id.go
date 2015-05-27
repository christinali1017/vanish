package kademlia

// Contains definitions for the 160-bit identifiers used throughout kademlia.

import (
	"crypto/md5"
	"encoding/hex"
	"math/rand"
)

// IDs are 160-bit ints. We're going to use byte arrays with a number of
// methods.
const IDBytes = 20
const IDBits = IDBytes * 8

type ID [IDBytes]byte

func (id ID) AsString() string {
	return hex.EncodeToString(id[0:IDBytes])
}

func (id ID) Xor(other ID) (ret ID) {
	for i := 0; i < IDBytes; i++ {
		ret[i] = id[i] ^ other[i]
	}
	return
}

// Return -1, 0, or 1, with the same meaning as strcmp, etc.
func (id ID) Compare(other ID) int {
	for i := 0; i < IDBytes; i++ {
		difference := int(id[i]) - int(other[i])
		switch {
		case difference == 0:
			return 0
		case difference < 0:
			return -1
		case difference > 0:
			return 1
		}
	}
	return 0
}

func (id ID) Equals(other ID) bool {
	return id.Compare(other) == 0
}

func (id ID) Less(other ID) bool {
	return id.Compare(other) < 0
}

// Return the number of consecutive zeroes in an ID
func (id ID) PrefixLen() int {
    for i := 0; i < IDBytes; i++ {
        for j := 7; j >= 0; j-- {
            if (id[i]>>uint8(j))&0x1 != 0 {
                return (8 * i) + (7 - j)
            }
        }
    }
    return IDBytes * 8 
}

// Generate a new ID from nothing.
func NewRandomID() (ret ID) {
	for i := 0; i < IDBytes; i++ {
		ret[i] = uint8(rand.Intn(256))
	}
	return
}

// Generate an ID identical to another.
func CopyID(id ID) (ret ID) {
	for i := 0; i < IDBytes; i++ {
		ret[i] = id[i]
	}
	return
}

// Generate a ID matching a given string.
func IDFromString(idstr string) (ret ID, err error) {
	bytes, err := hex.DecodeString(idstr)
	if err != nil {
		return
	}

	for i := 0; i < IDBytes && i < len(bytes); i++ {
		ret[i] = bytes[i]
	}
	return
}

func Checksum(data []byte) [16]byte {
	return md5.Sum(data)
}
