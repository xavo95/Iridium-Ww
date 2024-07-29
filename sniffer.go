package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/xtaci/kcp-go"
)

type Packet struct {
	Time       int64       `json:"time"`
	FromServer bool        `json:"fromServer"`
	PacketId   uint16      `json:"packetId"`
	PacketName string      `json:"packetName"`
	Object     interface{} `json:"object"`
	Raw        []byte      `json:"raw"`
}

type UniCmdItem struct {
	PacketId   uint16      `json:"packetId"`
	PacketName string      `json:"packetName"`
	Object     interface{} `json:"object"`
	Raw        []byte      `json:"raw"`
}

var ProtoKeyResponse uint16
var ProtoKeyRequest uint16

var privateKey *rsa.PrivateKey
var aesEcb *AES
var sessionKey []byte

var captureHandler *pcap.Handle
var kcpMap map[string]*kcp.KCP
var packetFilter = make(map[string]bool)
var pcapFile *os.File
var err error

func openPcap(fileName string) {
	readKeys()
	var err error
	captureHandler, err = pcap.OpenOffline(fileName)
	if err != nil {
		log.Println("Could not open pacp file", err)
		return
	}
	startSniffer()
}

func openCapture() {
	readKeys()
	var err error
	captureHandler, err = pcap.OpenLive(config.DeviceName, 1500, true, -1)

	if err != nil {
		log.Println("Could not open capture", err)
		return
	}

	if config.AutoSavePcapFiles {
		pcapFile, err = os.Create(time.Now().Format("06-01-02 15.04.05") + ".pcapng")
		if err != nil {
			log.Println("Could not create pcapng file", err)
		}
		defer pcapFile.Close()
	}

	startSniffer()
}

func closeHandle() {
	if captureHandler != nil {
		captureHandler.Close()
		captureHandler = nil
	}
	if pcapFile != nil {
		pcapFile.Close()
		pcapFile = nil
	}
}

func readKeys() {
	keyBytes, err := os.ReadFile("./data/privateKey.pem")
	if err != nil {
		log.Fatal("Could not load initial key @ ./data/privateKey.pem #1", err)
	}
	privateKey, _ = RsaParsePrivKey(keyBytes)
	ProtoKeyResponse = packetNameMap["ProtoKeyResponse"]
	ProtoKeyRequest = packetNameMap["ProtoKeyRequest"]
}

func startSniffer() {
	defer captureHandler.Close()

	err := captureHandler.SetBPFFilter("udp portrange 13100-13120")
	if err != nil {
		log.Println("Could not set the filter of capture")
		return
	}

	packetSource := gopacket.NewPacketSource(captureHandler, captureHandler.LinkType())
	packetSource.NoCopy = true

	kcpMap = make(map[string]*kcp.KCP)
	cbuffer = &readStream{md5List: make(map[string]string)}
	sbuffer = &readStream{md5List: make(map[string]string)}

	var pcapWriter *pcapgo.NgWriter
	if pcapFile != nil {
		pcapWriter, err = pcapgo.NewNgWriter(pcapFile, captureHandler.LinkType())
		if err != nil {
			log.Println("Could not create pcapng writer", err)
		}
	}

	for packet := range packetSource.Packets() {
		if pcapWriter != nil {
			err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				log.Println("Could not write packet to pcap file", err)
			}
		}

		capTime := packet.Metadata().Timestamp
		data := packet.ApplicationLayer().Payload()
		udp := packet.TransportLayer().(*layers.UDP)
		fromServer := config.MinPort <= udp.SrcPort && udp.SrcPort <= config.MaxPort

		if len(data) < 24 {
			handleSpecialPacket(data, fromServer, capTime)
			continue
		}

		handleKcp(data, fromServer, capTime)
	}
}

type readStream struct {
	data    []byte
	md5List map[string]string
}

func (db *readStream) add(newData []byte) {
	db.data = append(db.data, newData...)
}

func (db *readStream) read(length int) []byte {
	if len(db.data) < length {
		return nil
	}
	return db.data[:length]
}

func (db *readStream) del(length int) {
	if len(db.data) < length || length <= 0 {
		return
	}
	db.data = db.data[length:]
}

func (db *readStream) next(length uint16) []byte {
	if uint16(len(db.data)) < length {
		return nil
	}
	readData := db.data[:length]
	db.data = db.data[length:]
	return readData
}

func (db *readStream) get() []byte {
	length := len(db.data)
	readData := db.data[:length]
	db.data = db.data[length:]
	return readData
}

var convId uint32
var cbuffer *readStream
var sbuffer *readStream

func handleKcp(data []byte, fromServer bool, capTime time.Time) {
	// data := reformData(buffer)
	conv := binary.LittleEndian.Uint32(data[:4])
	convId = conv
	data = delKcpHD(data)
	if fromServer {
		addBuffer(data, sbuffer)
	} else {
		addBuffer(data, cbuffer)
	}

	handleProtoPacket(fromServer, capTime)

	// key := strconv.Itoa(int(conv))
	// if fromServer {
	// 	key += "svr"
	// } else {
	// 	key += "cli"
	// }
	//
	// if _, ok := kcpMap[key]; !ok {
	// 	kcpInstance := kcp.NewKCP(conv, func(buf []byte, size int) {})
	// 	kcpInstance.WndSize(1024, 1024)
	// 	kcpMap[key] = kcpInstance
	// }
	// kcpInstance := kcpMap[key]
	// _ = kcpInstance.Input(data, true, true)
	//
	// size := kcpInstance.PeekSize()
	// for size > 0 {
	// 	kcpBytes := make([]byte, size)
	// 	kcpInstance.Recv(kcpBytes)
	// 	buffer.add(kcpBytes)
	// 	handleProtoPacket(buffer, fromServer, capTime)
	// 	size = kcpInstance.PeekSize()
	// }
	// kcpInstance.Update()
}

func handleSpecialPacket(data []byte, fromServer bool, timestamp time.Time) {
	aesEcb = nil
}

func handleProtoPacket(fromServer bool, timestamp time.Time) {
	// buffer.add(data)
	msgList := make([]*PackMsg, 0)
	DecodeLoop(cbuffer, &msgList)
	DecodeLoop(sbuffer, &msgList)

	for _, msg := range msgList {
		var data []byte
		if msg.CmdId != ProtoKeyResponse && msg.CmdId != ProtoKeyRequest {
			if aesEcb != nil && msg.ProtoLen != 0 {
				data = aesEcb.DecryptECB(msg.ProtoData, PKCS7Unpadding)
				if err != nil {
					log.Printf("AesECBDecrypt error:%s\n", err.Error())
				}
				// TODO 此处需要对 data 进行一次处理,由于某些原因我无法公开
			}
		}
		if data == nil {
			data = msg.ProtoData
		}
		var objectJson interface{}
		packetId := msg.CmdId
		if packetId == ProtoKeyResponse {
			objectJson = handleProtoKeyResponsePacket(data, packetId, objectJson)
		} else {
			// protoData := removeHeaderForParse(msg.ProtoData)
			objectJson = parseProtoToInterface(packetId, data)
		}

		if msg.CmdId == 104 {
			aeskey := sessionKey
			log.Printf("key:%s", hex.EncodeToString(aeskey))
			log.Printf("protoMsg:%s", base64.StdEncoding.EncodeToString(msg.ProtoData))
			log.Printf("msg:%s,decryptMsg:%s", base64.StdEncoding.EncodeToString(msg.MsgData), base64.StdEncoding.EncodeToString(data))
		}

		buildPacketToSend(data, fromServer, timestamp, packetId, objectJson)
	}
}

func handleProtoKeyResponsePacket(data []byte, packetId uint16, objectJson interface{}) interface{} {
	// data = removeMagic(data)
	dMsg, err := parseProto(packetId, data)
	if err != nil {
		log.Println("Could not parse ProtoKeyResponse proto", err)
		closeHandle()
	}
	oj, err := dMsg.MarshalJSON()
	if err != nil {
		log.Println("Could not parse ProtoKeyResponse proto", err)
		closeHandle()
	}
	err = json.Unmarshal(oj, &objectJson)
	if err != nil {
		log.Println("Could not parse ProtoKeyResponse proto", err)
		closeHandle()
	}
	x := objectJson.(map[string]interface{})
	key, _ := base64.StdEncoding.DecodeString(x["key"].(string))
	sessionKey, err = RsaDecrypt(key, privateKey)
	if err != nil {
		log.Printf("DecryptPKCS1v15 Key error:%s\n", err)
	}
	aesEcb, err = NewAES(sessionKey)
	if err != nil {
		log.Printf("%s", err)
	}

	return objectJson
}

func buildPacketToSend(data []byte, fromSever bool, timestamp time.Time, packetId uint16, objectJson interface{}) {
	packet := &Packet{
		Time:       timestamp.UnixMilli(),
		FromServer: fromSever,
		PacketId:   packetId,
		PacketName: GetProtoNameById(packetId),
		Object:     objectJson,
		Raw:        data,
	}

	jsonResult, err := json.Marshal(packet)
	if err != nil {
		log.Println("Json marshal error", err)
	}
	logPacket(packet)

	if packetFilter[GetProtoNameById(packetId)] {
		return
	}
	sendStreamMsg(string(jsonResult))
}

func logPacket(packet *Packet) {
	from := "[Client]"
	if packet.FromServer {
		from = "[Server]"
	}
	forward := ""
	if strings.Contains(packet.PacketName, "ScRsp") {
		forward = "<--"
	} else if strings.Contains(packet.PacketName, "CsReq") {
		forward = "-->"
	} else if strings.Contains(packet.PacketName, "Notify") && packet.FromServer {
		forward = "<-i"
	} else if strings.Contains(packet.PacketName, "Notify") {
		forward = "i->"
	}

	log.Println(color.GreenString(from),
		"\t",
		color.CyanString(forward),
		"\t",
		color.RedString(packet.PacketName),
		color.YellowString("#"+strconv.Itoa(int(packet.PacketId))),
		"\t",
		len(packet.Raw),
	)
}
