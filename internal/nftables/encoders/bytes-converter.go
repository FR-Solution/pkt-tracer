//nolint:mnd
package encoders

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	baseDec = 10
	baseHex = 16
)

type RawBytes []byte

func (b RawBytes) Uint64() uint64 {
	return new(big.Int).SetBytes(b).Uint64()
}

func (b RawBytes) ReverseByte() RawBytes {
	for i := 0; i < len(b)/2; i++ {
		b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
	}
	return b
}

func (b RawBytes) LittleEndian() RawBytes {
	//set bytes as big endian by default and then reverse it
	return RawBytes(new(big.Int).SetBytes(b).Bytes()).ReverseByte()
}

func (b RawBytes) String() string {
	if utf8.Valid(b) && func() bool {
		for _, v := range bytes.TrimRight(b, "\x00") {
			if !unicode.IsGraphic(rune(v)) {
				return false
			}
		}
		return true
	}() {
		return string(bytes.TrimRight(b, "\x00"))
	}
	return new(big.Int).SetBytes(b).String()
}

func (b RawBytes) Text(base int) string {
	return new(big.Int).SetBytes(b).Text(base)
}

func (b RawBytes) Ip() (ip net.IP) {
	l := len(b)
	if l == 4 {
		ip = make(net.IP, l)
	} else if l == 6 {
		ip = make(net.IP, l)
	}
	if ip == nil {
		return
	}
	binary.BigEndian.PutUint32(ip, uint32(b.Uint64())) //nolint:gosec
	return
}

func (b RawBytes) CIDR() (ipnet *net.IPNet) {
	const nBits = 32
	l := len(b)
	if l == 1 {
		mask := l * 8
		ipnet = &net.IPNet{
			IP:   net.IPv4(b[0], 0, 0, 0),
			Mask: net.CIDRMask(mask, nBits),
		}
	}
	return ipnet
}

// MarshalJSON json Marshaler
func (b RawBytes) MarshalJSON() ([]byte, error) {
	if utf8.Valid(b) && func() bool {
		for _, v := range bytes.TrimRight(b, "\x00") {
			if !unicode.IsGraphic(rune(v)) {
				return false
			}
		}
		return true
	}() {
		return json.Marshal(string(b))
	}

	intSlice := new(big.Int).SetBytes(b)
	return intSlice.MarshalJSON()
}

func BytesToCtStateString(b []byte) string {
	return CtState(RawBytes(b).LittleEndian().Uint64()).String() //nolint:gosec
}

func BytesToCtDirString(b []byte) string {
	return CtDir(uint32(b[0])).String()
}

func BytesToCtStatusString(b []byte) string {
	return CtStatus(RawBytes(b).LittleEndian().Uint64()).String() //nolint:gosec
}

func BytesToNfProtoString(b []byte) string {
	switch uint32(b[0]) {
	case unix.NFPROTO_IPV4:
		return "ipv4"
	case unix.NFPROTO_IPV6:
		return "ipv6"
	}
	return "unknown" //nolint:goconst
}

func BytesToCtEventString(b []byte) string {
	return CtEvents(RawBytes(b).LittleEndian().Uint64()).String() //nolint:gosec
}

func BytesToDecimalString(b []byte) string {
	return RawBytes(b).Text(10)
}

func BytesToHexString(b []byte) string {
	return fmt.Sprintf("0x%s", RawBytes(b).Text(baseHex))
}

func LEBytesToIntString(b []byte) string {
	return strconv.FormatUint(RawBytes(b).LittleEndian().Uint64(), baseDec)
}

func BytesToString(b []byte) string {
	return string(bytes.TrimRight(b, "\x00"))
}

func BytesToTimeString(b []byte) string {
	return (time.Duration(RawBytes(b).LittleEndian().Uint64()) * time.Millisecond).String() //nolint:gosec
}

func BytesToInvalidType(b []byte) string {
	return fmt.Sprintf("0x%x [invalid type]", RawBytes(b).LittleEndian().Uint64())
}

func BytesToAddrString(b []byte) string {
	if len(b) >= 4 {
		return RawBytes(b).Ip().String()
	} else if len(b) == 1 {
		return RawBytes(b).CIDR().String()
	}
	return ""
}

func BytesToProtoString(b []byte) string {
	return ProtoType(int(RawBytes(b).Uint64())).String() //nolint:gosec
}

func BytesToDscp(b []byte) string {
	var dscp string
	switch (RawBytes(b).Uint64() >> 2) & 0x3 {
	case 0x00:
		dscp = "cs0"
	case 0x08:
		dscp = "cs1"
	case 0x10:
		dscp = "cs2"
	case 0x18:
		dscp = "cs3"
	case 0x20:
		dscp = "cs4"
	case 0x28:
		dscp = "cs5"
	case 0x30:
		dscp = "cs6"
	case 0x38:
		dscp = "cs7"
	case 0x01:
		dscp = "lephb"
	case 0x0a:
		dscp = "af11"
	case 0x0c:
		dscp = "af12"
	case 0x0e:
		dscp = "af13"
	case 0x12:
		dscp = "af21"
	case 0x14:
		dscp = "af22"
	case 0x16:
		dscp = "af23"
	case 0x1a:
		dscp = "af31"
	case 0x1c:
		dscp = "af32"
	case 0x1e:
		dscp = "af33"
	case 0x22:
		dscp = "af41"
	case 0x24:
		dscp = "af42"
	case 0x26:
		dscp = "af43"
	case 0x2c:
		dscp = "va"
	case 0x2e:
		dscp = "ef"
	}
	return dscp
}

func BytesToEcn(b []byte) string {
	var ecn string
	switch RawBytes(b).Uint64() & 0x3 {
	case 0:
		ecn = "not-ect" //nolint:misspell
	case 1:
		ecn = "ect1"
	case 2:
		ecn = "ect0"
	case 3:
		ecn = "ce"
	}
	return ecn
}

func BytesToIcmpType(b []byte) string {
	return IcmpType(RawBytes(b).Uint64()).String() //nolint:gosec
}

func BytesToIcmpCode(b []byte) string {
	return IcmpCode(RawBytes(b).Uint64()).String() //nolint:gosec
}

func BytesToIcmp6Type(b []byte) string {
	return Icmp6Type(RawBytes(b).Uint64()).String() //nolint:gosec
}

func BytesToIcmp6Code(b []byte) string {
	return Icmp6Code(RawBytes(b).Uint64()).String() //nolint:gosec
}

func BytesToTcpFlags(b []byte) string {
	var flags []string
	fl := TcpFlagType(RawBytes(b).Uint64()) //nolint:gosec
	if fl&TCP_FLAG_FIN != 0 {
		flags = append(flags, TCP_FLAG_FIN.String())
	}
	if fl&TCP_FLAG_SYN != 0 {
		flags = append(flags, TCP_FLAG_SYN.String())
	}
	if fl&TCP_FLAG_RST != 0 {
		flags = append(flags, TCP_FLAG_RST.String())
	}
	if fl&TCP_FLAG_PSH != 0 {
		flags = append(flags, TCP_FLAG_PSH.String())
	}
	if fl&TCP_FLAG_ACK != 0 {
		flags = append(flags, TCP_FLAG_ACK.String())
	}
	if fl&TCP_FLAG_URG != 0 {
		flags = append(flags, TCP_FLAG_URG.String())
	}
	if fl&TCP_FLAG_ECN != 0 {
		flags = append(flags, TCP_FLAG_ECN.String())
	}
	if fl&TCP_FLAG_CWR != 0 {
		flags = append(flags, TCP_FLAG_CWR.String())
	}

	return strings.Join(flags, ",")
}

func BytesToIPVer(b []byte) string {
	return fmt.Sprintf("%d", (RawBytes(b).Uint64()>>4)&0xf)
}
