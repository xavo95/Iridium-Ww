package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
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

var ProtoKeyResponse uint16
var ProtoKeyRequest uint16

var privateKey *rsa.PrivateKey
var aesEcb *AES
var sessionKey []byte

var captureHandler *pcap.Handle
var kcpMap map[string]*kcp.KCP
var packetFilter = make(map[string]bool)
var pcapFile *os.File

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

func handleKcp(data []byte, fromServer bool, capTime time.Time) {
	conv := binary.LittleEndian.Uint32(data[:4])
	key := strconv.Itoa(int(conv))
	if fromServer {
		key += "svr"
	} else {
		key += "cli"
	}

	if _, ok := kcpMap[key]; !ok {
		kcpInstance := kcp.NewKCP(conv, func(buf []byte, size int) {})
		kcpInstance.WndSize(1024, 1024)
		kcpMap[key] = kcpInstance
	}
	kcpInstance := kcpMap[key]
	_ = kcpInstance.Input(data, true, true)

	size := kcpInstance.PeekSize()
	for size > 0 {
		kcpBytes := make([]byte, size)
		kcpInstance.Recv(kcpBytes)
		addDataMap(key, kcpBytes)
		size = kcpInstance.PeekSize()
	}
	handleProtoPacket(key, fromServer, capTime)
	kcpInstance.Update()
}

func handleSpecialPacket(data []byte, fromServer bool, timestamp time.Time) {
	if len(data) < 1 {
		return
	}
	switch data[0] {
	case 237:
		buildPacketToSend(data, fromServer, timestamp, 0, "Hamdshanke pls.")
		break
	case 238:
		aesEcb = nil
		buildPacketToSend(data, fromServer, timestamp, 0, "Hamdshanke estamblished.")
		break
	default:
		buildPacketToSend(data, fromServer, timestamp, 0, "Hamdshanke error.")
	}
}

func handleProtoPacket(key string, fromServer bool, timestamp time.Time) {
	msgList := make([]*PackMsg, 0)
	DecodeLoop(key, &msgList, aesEcb)
	for _, msg := range msgList {
		var objectJson interface{}
		packetId := msg.CmdId
		if packetId == ProtoKeyResponse {
			objectJson = handleProtoKeyResponsePacket(msg.ProtoData, packetId, objectJson)
		} else {
			objectJson = parseProtoToInterface(packetId, msg.ProtoData)
		}

		buildPacketToSend(msg.ProtoData, fromServer, timestamp, packetId, objectJson)
	}
}

func handleProtoKeyResponsePacket(data []byte, packetId uint16, objectJson interface{}) interface{} {
	dMsg, err := parseProto(packetId, data)
	if err != nil {
		log.Printf("Could not parse ProtoKeyResponse proto Error:%s\n", err)
		closeHandle()
	}
	oj, err := dMsg.MarshalJSON()
	if err != nil {
		log.Printf("Could not parse ProtoKeyResponse proto Error:%s\n", err)
		closeHandle()
	}
	err = json.Unmarshal(oj, &objectJson)
	if err != nil {
		log.Printf("Could not parse ProtoKeyResponse proto Error:%s\n", err)
		closeHandle()
	}
	req := objectJson.(map[string]interface{})
	var key []byte
	if reqKey := req["key"]; reqKey != nil {
		key, _ = base64.StdEncoding.DecodeString(reqKey.(string))
	} else if reqKey2 := req["Key"]; reqKey2 != nil {
		key, _ = base64.StdEncoding.DecodeString(reqKey2.(string))
	}
	if len(key) == 0 {
		log.Printf("ProtoKeyResponse Get Key Error:%s\n", err)
		return objectJson
	}
	sessionKey, err = RsaDecryptPrivKey(key, privateKey)
	if err != nil {
		log.Printf("DecryptPKCS1v15 Key Error:%s\n", err)
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
	if strings.Contains(packet.PacketName, "Response") {
		forward = "<--"
	} else if strings.Contains(packet.PacketName, "Request") {
		forward = "-->"
	} else if strings.Contains(packet.PacketName, "Notify") && packet.FromServer {
		forward = "<-i"
	} else if strings.Contains(packet.PacketName, "Push") {
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
