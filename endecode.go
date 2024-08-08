package main

import (
	"encoding/binary"
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
	PacketMaxLen = math.MaxUint16 // 最大应用层包长度
)

func DecodeLoop(data []byte, kcpMsgList *[]*PackMsg, aesEcb *AES) []byte {
	// 长度太短
	if len(data) < 14 {
		log.Println("packet len less than 14 byte")
		return data
	}
	i := 0
	// 检查长度
	msgLen := binary.LittleEndian.Uint16(data[i:])
	if msgLen > PacketMaxLen {
		log.Println("packet len too long")
		return make([]byte, 0)
	}
	if uint16(len(data)) < msgLen+3 {
		// log.Println("packet len not enough")
		return data
	}
	packetLen := msgLen + 3
	i += 3
	// 消息类型
	msgType := data[i]
	i += 1
	seqNo := binary.LittleEndian.Uint32(data[i:])
	i += 4
	var rpcId uint16
	if msgType != 4 {
		rpcId = binary.LittleEndian.Uint16(data[i:])
		i += 2
	}
	// 二次验证数据长度
	if len(data) < i+6 {
		log.Printf("packet len less than %v byte\n", i+6)
		return data
	}
	// 协议号
	cmdId := binary.LittleEndian.Uint16(data[i:])
	i += 2
	receivedCrc32 := binary.LittleEndian.Uint32(data[i:])
	i += 4
	detaLength := packetLen - uint16(i)
	// 数据
	msgBytes := data[i:packetLen]
	// crc32 验证
	if crc32Hash(msgBytes) != receivedCrc32 {
		log.Printf("kcp msg crc32 checksum error")
		return data[packetLen:] // 丢弃数据
	}
	// proto数据
	var protoData []byte
	if aesEcb != nil &&
		detaLength != 0 &&
		cmdId != ProtoKeyResponse &&
		cmdId != ProtoKeyRequest {
		protoData = aesEcb.DecryptECB(msgBytes, PKCS7Unpadding)
		// TODO 此处需要对 data 进行一次处理,由于某些原因我无法公开
	} else {
		protoData = msgBytes
	}
	// 返回数据
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
	// 有不止一个包 递归解析
	data = data[packetLen:]
	if uint16(len(data)) > 14 {
		DecodeLoop(data, kcpMsgList, aesEcb)
	}
	return data
}
