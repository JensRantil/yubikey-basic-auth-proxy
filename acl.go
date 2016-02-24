package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
)

type ScryptEntry struct {
	Params ScryptData
	Hash   []byte
	Salt   []byte
}

func (s *ScryptEntry) Test(password string) (bool, error) {
	hash, err := s.Params.CalculateHash([]byte(password), s.Salt)
	if err != nil {
		return false, err
	}
	return bytes.Equal(hash, s.Hash), nil
}

type UserEntry struct {
	Username     string
	Yubikey      string
	PasswordHash ScryptEntry
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
	if _hash, err := scryptData.CalculateHash([]byte(password), salt); err != nil {
		return nil, err
	} else {
		hash = _hash
	}

	u := UserEntry{
		PasswordHash: ScryptEntry{
			Params: scryptData,
			Hash:   hash,
			Salt:   salt,
		},
		Username: username,
		Yubikey:  yubikey,
	}

	return &u, nil
}

type ACLConfig struct {
	Version int // Used to support other configuration versions in the future.
	Entries []UserEntry
}

func NewACLConfig() *ACLConfig {
	return &ACLConfig{
		Version: 1,
		Entries: make([]UserEntry, 0),
	}
}

func NewACLConfigFromReader(reader io.Reader) (*ACLConfig, error) {
	config := new(ACLConfig)
	decoder := json.NewDecoder(reader)

	return config, decoder.Decode(config)
}

func (a *ACLConfig) EncodeTo(writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	return encoder.Encode(a)
}
