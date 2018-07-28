package mndplib

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	mndpMNDP          = 0
	mndpMACAddr       = 1
	mndpIdentity      = 5
	mndpVersion       = 7
	mndpPlatform      = 8
	mndpUptime        = 10
	mndpSoftwareID    = 11
	mndpBoard         = 12
	mndpUnpack        = 14
	mndpIPv6Addr      = 15
	mndpInterfaceName = 16
)

// MNDPResponse is a struct with all relevant fields from a response
type MNDPResponse struct {
	Src        string
	MACAddr    string
	Identity   string
	Version    string
	Platform   string
	Uptime     string
	SoftwareID string
	Board      string
	Unpack     string
	IPv6Addr   string
	Interface  string
}

type mndpTLV struct {
	typeTag uint16
	length  uint16
	value   []byte
}

// IsResponse tells if a MNDPMessage is a response
func (msg *MNDPMessage) IsResponse() bool {
	if len(msg.tlvs) > 2 {
		return true
	}
	return false
}

// Unpack turns a MNDP message into a MNDPResponse
func (msg *MNDPMessage) Unpack() MNDPResponse {
	return MNDPResponse{
		msg.src,
		strings.Split(msg.tlvs[0].String(), " ")[1],
		strings.Split(msg.tlvs[1].String(), " ")[1],
		strings.Split(msg.tlvs[2].String(), " ")[1],
		strings.Split(msg.tlvs[3].String(), " ")[1],
		strings.Split(msg.tlvs[4].String(), " ")[1],
		strings.Split(msg.tlvs[5].String(), " ")[1],
		strings.Split(msg.tlvs[6].String(), " ")[1],
		strings.Split(msg.tlvs[7].String(), " ")[1],
		strings.Split(msg.tlvs[8].String(), " ")[1],
		strings.Split(msg.tlvs[9].String(), " ")[1],
	}
}

// MNDPMessage ...
type MNDPMessage struct {
	src     string
	typeTag uint16
	seqNo   uint16
	tlvs    []mndpTLV
}

func (tlv mndpTLV) String() string {
	typeTag := "?"
	value := "?"
	switch tlv.typeTag {
	case mndpMACAddr:
		typeTag = "MACAddr"
		value = net.HardwareAddr(tlv.value).String()
	case mndpIdentity:
		typeTag = "Identity"
		value = string(tlv.value)
	case mndpVersion:
		typeTag = "Version"
		value = string(tlv.value)
	case mndpPlatform:
		typeTag = "Platform"
		value = string(tlv.value)
	case mndpUptime:
		typeTag = "Uptime"
		value = (time.Duration(binary.LittleEndian.Uint32(tlv.value)) * time.Second).String()
	case mndpSoftwareID:
		typeTag = "Software-ID"
		value = string(tlv.value)
	case mndpBoard:
		typeTag = "Board"
		value = string(tlv.value)
	case mndpUnpack:
		typeTag = "Unpack"
		value = fmt.Sprint(tlv.value[0])
	case mndpIPv6Addr:
		typeTag = "IPv6Addr"
		value = net.IP(tlv.value).String()
	case mndpInterfaceName:
		typeTag = "Interface"
		value = string(tlv.value)
	}
	return fmt.Sprintf("%s: %s", typeTag, value)
}

func getTlvsString(tlvs []mndpTLV) string {
	count := len(tlvs)
	if count < 1 {
		return ""
	}
	if count == 1 {
		return tlvs[0].String()
	}

	result := tlvs[0].String()
	separator := "; "
	for _, tlv := range tlvs[1:] {
		result = result + separator + tlv.String()
	}
	return result
}

func (msg MNDPMessage) String() string {
	if msg.typeTag == mndpMNDP && msg.seqNo == 0 {
		return fmt.Sprintf("!!MNDP[%d] (%s):\n  [%s]", msg.seqNo, msg.src, "REFRESH REQUEST")
	}
	return fmt.Sprintf("!!MNDP[%d] (%s):\n  [%s]", msg.seqNo, msg.src, getTlvsString(msg.tlvs))
}

func readMndpTLV(r io.Reader) *mndpTLV {
	var record mndpTLV
	err := binary.Read(r, binary.BigEndian, &record.typeTag)
	if err == io.EOF {
		return nil
	} else if err != nil {
		return nil
	}

	err = binary.Read(r, binary.BigEndian, &record.length)
	if err == io.EOF {
		return nil
	} else if err != nil {
		return nil
	}

	var buff [maxPacketSize]byte

	c, err := r.Read(buff[:record.length])
	if err != nil {
		return nil
	}
	if uint16(c) != record.length {
		return nil
	}

	record.value = buff[:record.length]

	return &record
}

func readMndp(r io.Reader) *MNDPMessage {
	var record MNDPMessage
	err := binary.Read(r, binary.BigEndian, &record.typeTag)
	if err == io.EOF {
		return nil
	} else if err != nil {
		return nil
	}

	err = binary.Read(r, binary.BigEndian, &record.seqNo)
	if err == io.EOF {
		return nil
	} else if err != nil {
		return nil
	}

	for {
		tlv := readMndpTLV(r)
		if tlv == nil {
			break
		}
		record.tlvs = append(record.tlvs, *tlv)
	}

	return &record
}
