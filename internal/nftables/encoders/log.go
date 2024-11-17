package encoders

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	nfte "github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type (
	LogFlags nfte.LogFlags
	LogLevel nfte.LogLevel
)

func (l LogFlags) String() []string {
	var flags []string
	if l == LogFlags(nfte.LogFlagsMask) {
		flags = append(flags, "all")
		return flags
	}
	if l == LogFlags(nfte.LogFlagsTCPSeq) {
		flags = append(flags, "tcp sequence")
	}
	if l == LogFlags(nfte.LogFlagsTCPOpt) {
		flags = append(flags, "tcp options")
	}
	if l == LogFlags(nfte.LogFlagsIPOpt) {
		flags = append(flags, "ip options")
	}
	if l == LogFlags(nfte.LogFlagsUID) {
		flags = append(flags, "skuid")
	}
	if l == LogFlags(nfte.LogFlagsNFLog) {
		flags = append(flags, "nflog")
	}
	if l == LogFlags(nfte.LogFlagsMACDecode) {
		flags = append(flags, "mac-decode")
	}
	return flags
}

func (l LogLevel) String() string {
	switch nfte.LogLevel(l) {
	case nfte.LogLevelEmerg:
		return "emerg"
	case nfte.LogLevelAlert:
		return "alert"
	case nfte.LogLevelCrit:
		return "crit"
	case nfte.LogLevelErr:
		return "err"
	case nfte.LogLevelWarning:
		return "warn"
	case nfte.LogLevelNotice:
		return "notice"
	case nfte.LogLevelInfo:
		return "info"
	case nfte.LogLevelDebug:
		return "debug"
	case nfte.LogLevelAudit:
		return "audit"
	}
	return "unknown"
}

type ExprLog struct {
	*nfte.Log
}

func newLogEncoder(expr *nfte.Log) *ExprLog {
	return &ExprLog{Log: expr}
}

func (expr *ExprLog) String() (string, error) {
	sb := strings.Builder{}
	sb.WriteString("log")
	if expr.Key&(1<<unix.NFTA_LOG_PREFIX) != 0 {
		sb.WriteString(fmt.Sprintf(" prefix \"%s\"", string(bytes.TrimRight(expr.Data, "\x00"))))
	}
	if expr.Key&(1<<unix.NFTA_LOG_GROUP) != 0 {
		sb.WriteString(fmt.Sprintf(" group %d", expr.Group))
	}
	if expr.Key&(1<<unix.NFTA_LOG_SNAPLEN) != 0 {
		sb.WriteString(fmt.Sprintf(" snaplen %d", expr.Snaplen))
	}
	if expr.Key&(1<<unix.NFTA_LOG_QTHRESHOLD) != 0 {
		sb.WriteString(fmt.Sprintf(" queue-threshold %d", expr.QThreshold))
	}
	if expr.Key&(1<<unix.NFTA_LOG_LEVEL) != 0 {
		sb.WriteString(fmt.Sprintf(" level %s", LogLevel(expr.Level)))
	}
	flags := LogFlags(expr.Flags).String()
	if len(flags) > 0 {
		sb.WriteString(fmt.Sprintf(" flags %s", strings.Join(flags, ", ")))
	}

	return sb.String(), nil
}

func (expr *ExprLog) MarshalJSON() ([]byte, error) {
	var fl any
	flags := LogFlags(expr.Flags).String()
	if len(flags) > 1 {
		fl = flags
	} else if len(flags) == 1 {
		fl = flags[0]
	}
	log := &struct {
		Prefix     string `json:"prefix,omitempty"`
		Group      uint16 `json:"group,omitempty"`
		Snaplen    uint32 `json:"snaplen,omitempty"`
		QThreshold uint16 `json:"queue-threshold,omitempty"`
		Level      string `json:"level,omitempty"`
		Flags      any    `json:"flags,omitempty"`
	}{
		Flags: fl,
	}

	if expr.Key&(1<<unix.NFTA_LOG_PREFIX) != 0 {
		log.Prefix = string(bytes.TrimRight(expr.Data, "\x00"))
	}
	if expr.Key&(1<<unix.NFTA_LOG_GROUP) != 0 {
		log.Group = expr.Group
	}
	if expr.Key&(1<<unix.NFTA_LOG_SNAPLEN) != 0 {
		log.Snaplen = expr.Snaplen
	}
	if expr.Key&(1<<unix.NFTA_LOG_QTHRESHOLD) != 0 {
		log.QThreshold = expr.QThreshold
	}
	if expr.Key&(1<<unix.NFTA_LOG_LEVEL) != 0 {
		log.Level = LogLevel(expr.Level).String()
	}
	if expr.Key == 0 {
		log = nil
	}
	lg := map[string]interface{}{
		"log": log,
	}
	return json.Marshal(lg)
}
