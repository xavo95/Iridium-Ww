package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"hash/crc32"
)

func RsaParsePrivKey(privKeyPem []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privKeyPem)
	if block == nil {
		return nil, errors.New("invalid rsa private key")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func RsaDecrypt(encData []byte, privKey *rsa.PrivateKey) (decData []byte, err error) {
	return rsa.DecryptPKCS1v15(rand.Reader, privKey, encData)
}

func crc32Hash(data []byte) uint32 {
	Hash32 := crc32.NewIEEE()
	Hash32.Write(data)
	return Hash32.Sum32()
}
