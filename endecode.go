package main

import (
	"encoding/base64"
	"encoding/binary"
	"log"
)

type PackMsg struct {
	PackLen   uint16
	MsgType   int
	Seq       uint32
	RpcId     uint16
	CmdId     uint16
	Crc32     uint32
	ProtoLen  uint16
	ProtoData []byte
}

func DecodeLoop(buffer *readStream, kcpMsgList *[]*PackMsg) {
	delKcpH(buffer)
	lenBytes := buffer.read(2)
	if lenBytes == nil {
		// log.Println("Read LenBytes error")
		return
	}
	lenth := binary.LittleEndian.Uint16(lenBytes)
	if lenth > 2000 {
		buffer.get()
		return
	}
	if uint16(len(buffer.data)) < lenth+3 {
		log.Printf("packet len len:%v\n", lenth+3)
		return
	}
	buffer.del(3)
	msgTypeBytes := buffer.next(1)
	msgType := msgTypeBytes[0]

	seqNoBytes := buffer.next(4)
	seqNo := binary.LittleEndian.Uint32(seqNoBytes)
	var rpcId uint16
	if msgType != 4 {
		rpcIdBytes := buffer.next(2)
		rpcId = binary.LittleEndian.Uint16(rpcIdBytes)
	}
	cmdIdBytes := buffer.next(2)
	cmdId := binary.LittleEndian.Uint16(cmdIdBytes)

	crc32Bytes := buffer.next(4)
	receivedCrc32 := binary.LittleEndian.Uint32(crc32Bytes)
	var detaLength uint16
	if msgType != 4 {
		detaLength = lenth - 13
	} else {
		detaLength = lenth - 11
	}
	msgBytes := buffer.next(int(detaLength))
	cmdName := GetProtoNameById(cmdId)
	kcpMsg := &PackMsg{
		PackLen:   lenth,
		MsgType:   int(msgType),
		Seq:       seqNo,
		RpcId:     rpcId,
		CmdId:     cmdId,
		Crc32:     receivedCrc32,
		ProtoLen:  detaLength,
		ProtoData: msgBytes,
	}
	*kcpMsgList = append(*kcpMsgList, kcpMsg)
	log.Printf("cmdName:%s", cmdName)
	log.Printf("lenth:%v,msgType:%v,seqNo:%v,rpcId:%v,cmdId:%v,receivedCrc32:%v,detaLength:%v,msg:%s", lenth, msgType, seqNo, rpcId, cmdId, receivedCrc32, detaLength, base64.StdEncoding.EncodeToString(msgBytes))
	// 有不止一个包 递归解析
	if uint16(len(buffer.data)) > lenth+3 {
		DecodeLoop(buffer, kcpMsgList)
	}
}
