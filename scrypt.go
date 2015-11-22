package main

import (
	"golang.org/x/crypto/scrypt"
)

// TODO: Rename to ScryptParams
type ScryptData struct {
	N      int
	r      int
	p      int
	keyLen int
}

// The recommended parameters for interactive logins as of 2009.
// TODO: Update with more up-to-date parameters.
var DefaultScryptData = ScryptData{
	N:      16384,
	r:      8,
	p:      1,
	keyLen: 32,
}

func (s *ScryptData) CalculateHash(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, s.N, s.r, s.p, s.keyLen)
}
