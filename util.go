package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log"
)

func removeMagic(data []byte) []byte {
	cut := data[7]
	data = data[10+2:]           // Removes token + four byte magic
	data = data[0 : len(data)-4] // Removes four byte magic at the end
	if len(data) < int(cut) {
		return data
	}
	data = data[cut:]
	return data
}

func removeHeaderForParse(data []byte) []byte {
	cut := data[8]
	data = removeMagic(data)
	if len(data) < int(cut) {
		x2 := hex.Dump(data)
		x := base64.StdEncoding.EncodeToString(data)
		log.Printf(x)
		log.Printf(x2)
		return data
	}
	return data[cut:]
}

func xorDecrypt(data []byte, key []byte) {
	for i := 0; i < len(data); i++ {
		data[i] = data[i] ^ key[i%len(key)]
	}
}

func delKcpH(buffer *readStream) {
	for {
		if len(buffer.data) < 24 {
			return
		}
		peekBytes := buffer.data[:4]
		b4 := binary.LittleEndian.Uint32(peekBytes)
		if b4 == convId {
			buffer.data = buffer.data[24:]
		} else {
			break
		}
	}
	return
}

func createXorPad(seed uint64) []byte {
	first := New()
	first.Seed(int64(seed))
	// generator := New()
	// generator.Seed(first.Generate())
	// generator.Generate()
	xorPad := make([]byte, 4096)

	for i := 0; i < 4096; i += 8 {
		value := first.Generate()
		binary.BigEndian.PutUint64(xorPad[i:i+8], uint64(value))
	}
	return xorPad
}

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
