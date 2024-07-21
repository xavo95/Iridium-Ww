package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"hash/crc32"
)

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

func delKcpHD(data []byte) []byte {
	for {
		if len(data) < 24 {
			return data
		}
		peekBytes := data[:4]
		b4 := binary.LittleEndian.Uint32(peekBytes)
		if b4 == convId {
			data = data[24:]
		} else {
			break
		}
	}
	return data
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

func addBuffer(data []byte, buffer *readStream) {
	md5s := getMD5String(data)
	if buffer.md5List == nil {
		buffer.md5List = make(map[string]string)
	}
	if buffer.md5List[md5s] == "" {
		buffer.add(data)
		buffer.md5List[md5s] = "114514"
		if len(buffer.md5List) > 50 {
			buffer.evictOldest()
		}
	}
}

func (db *readStream) evictOldest() {
	for k := range db.md5List {
		delete(db.md5List, k)
		break
	}
}

func getMD5String(b []byte) (result string) {
	res := md5.Sum(b)
	// result=fmt.Sprintf("%x",res)
	result = hex.EncodeToString(res[:])
	return
}

func crc32Hash(data []byte) uint32 {
	Hash32 := crc32.NewIEEE()
	Hash32.Write(data)
	return Hash32.Sum32()
}
