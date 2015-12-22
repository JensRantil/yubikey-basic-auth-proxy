package main

import (
	"golang.org/x/crypto/scrypt"
)

// TODO: Rename to ScryptParams
type ScryptData struct {
	N      int
	R      int
	P      int
	KeyLen int
}

// The recommended parameters for interactive logins as of 2009.
// TODO: Update with more up-to-date parameters.
var DefaultScryptData = ScryptData{
	N:      16384,
	R:      8,
	P:      1,
	KeyLen: 32,
}

func (s *ScryptData) CalculateHash(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, s.N, s.R, s.P, s.KeyLen)
}
