package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
)

type ScryptEntry struct {
	params ScryptData
	hash   []byte
	salt   []byte
}

func (s *ScryptEntry) Test(password string) (bool, error) {
	hash, err := s.params.CalculateHash([]byte(password), s.salt)
	if err != nil {
		return false, err
	}
	return bytes.Equal(hash, s.hash), nil
}

type UserEntry struct {
	username     string
	yubikey      string
	passwordHash ScryptEntry
}

const SALT_LENGTH = 32

func NewUserEntry(username, password, yubikey string, scryptData ScryptData) (*UserEntry, error) {
	if len(yubikey) != 12 {
		return nil, errors.New("Yubikey identifier must be 12 characters long.")
	}

	// Generating salt
	salt := make([]byte, SALT_LENGTH)
	if n, err := rand.Reader.Read(salt); n < 32 || err != nil {
		return nil, errors.New("Could not generate salt.")
	}

	var hash []byte
	if hash, err := scryptData.CalculateHash([]byte(password), salt); err != nil {
		return nil, err
	} else {
		hash = hash
	}

	u := UserEntry{
		passwordHash: ScryptEntry{
			params: scryptData,
			hash:   hash,
			salt:   salt,
		},
		username: username,
		yubikey:  yubikey,
	}

	return &u, nil
}

type ACLConfig struct {
	version int // Used to support other configuration versions in the future.
	entries []UserEntry
}

func NewACLConfigFromReader(reader io.Reader) (*ACLConfig, error) {
	config := new(ACLConfig)
	decoder := json.NewDecoder(reader)

	return config, decoder.Decode(config)
}

func (a *ACLConfig) WriteTo(writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	return encoder.Encode(a)
}
