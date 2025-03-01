package main

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math"
)

// ww游戏协议编解码

/*
							《Wuthering Waves》KCP协议(带*为aes加密数据)
0			1			2		 3 		    4											8(字节)
+---------------------------------------------------------------------------------------+
|		PackLen			|	0    |	msgType |					seqNo					|
+---------------------------------------------------------------------------------------+
|		 rpcId 			|		cmdId		|					crc32					|
+---------------------------------------------------------------------------------------+
|										payload*										|
+---------------------------------------------------------------------------------------+
*/

type PackMsg struct {
	PackLen   uint16
	MsgType   int
	Seq       uint32
	RpcId     uint16
	CmdId     uint16
	Crc32     uint32
	ProtoLen  uint16
	ProtoData []byte
	MsgData   []byte
}

const (
	PacketMaxLen = math.MaxUint16
)

var recursionsNum = 0

func DecodeLoop(key string, kcpMsgList *[]*PackMsg, aesEcb *AES) {
	data := getData(key)
	if recursionsNum >= 300 {
		log.Printf("recursionsNum:%v\n", recursionsNum)
		delData(key, uint16(len(data)))
		return
	}
	if len(data) < 14 {
		return
	}
	i := 0
	msgLen := binary.LittleEndian.Uint16(data[i:])
	if msgLen > PacketMaxLen {
		log.Println("packet len too long")
		delData(key, uint16(len(data)))
		return
	}
	if uint16(len(data)) < msgLen+3 {
		return
	}
	recursionsNum++
	packetLen := msgLen + 3
	i += 3
	msgType := data[i] & 0x0f
	isCompressed := data[i] & 0xf0
	i += 1
	seqNo := binary.LittleEndian.Uint32(data[i:])
	i += 4
	var rpcId uint16
	if msgType != 4 {
		rpcId = binary.LittleEndian.Uint16(data[i:])
		i += 2
	}
	if len(data) < i+6 {
		return
	}
	cmdId := binary.LittleEndian.Uint16(data[i:])
	i += 2
	receivedCrc32 := binary.LittleEndian.Uint32(data[i:])
	i += 4
	var decompressedSize uint32
	if (isCompressed & 0x10) == 0x10 {
		decompressedSize = binary.LittleEndian.Uint32(data[i:])
		i += 4
	}
	detaLength := packetLen - uint16(i)
	msgBytes := data[i:packetLen]
	computedCrc := crc32Hash(msgBytes)
	if computedCrc != receivedCrc32 {
		fmt.Printf("CRC error: expected: %d, got: %d", computedCrc, receivedCrc32)
		delData(key, uint16(len(data)))
		return
	}
	var protoData []byte
	if aesEcb != nil &&
		detaLength != 0 &&
		cmdId != ProtoKeyResponse &&
		cmdId != ProtoKeyRequest {
		protoData = aesEcb.DecryptECB(msgBytes, PKCS7Unpadding)
		aesEcb.KeyXor(seqNo, protoData)
	} else {
		protoData = msgBytes
	}
	if (isCompressed & 0x10) == 0x10 {
		b := bytes.NewBuffer(protoData)
		z, err := zlib.NewReader(b)
		if err != nil {
			delData(key, uint16(len(data)))
			return
		}
		defer z.Close()
		p, err := io.ReadAll(z)
		if err != nil {
			delData(key, uint16(len(data)))
			return
		}
		protoData = p
		detaLength = uint16(decompressedSize)
	}
	kcpMsg := &PackMsg{
		PackLen:   packetLen,
		MsgType:   int(msgType),
		Seq:       seqNo,
		RpcId:     rpcId,
		CmdId:     cmdId,
		Crc32:     receivedCrc32,
		ProtoLen:  detaLength,
		ProtoData: protoData,
	}
	*kcpMsgList = append(*kcpMsgList, kcpMsg)
	delData(key, packetLen)
	recursionsNum = 0
	if uint16(len(data)) > 14 {
		DecodeLoop(key, kcpMsgList, aesEcb)
	}
}
