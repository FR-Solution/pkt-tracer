package encoders

import (
	"encoding/json"
	"fmt"
	"strings"

	nfte "github.com/google/nftables/expr"
)

type (
	LimitType nfte.LimitType
	LimitTime nfte.LimitTime
	rate      uint64
)

func (r rate) Rate() (val uint64, unit string) {
	return getRate(uint64(r))
}

func getRate(bytes uint64) (val uint64, unit string) {
	dataUnit := [...]string{"bytes", "kbytes", "mbytes"}
	if bytes == 0 {
		return 0, dataUnit[0]
	}
	i := 0
	for i = range dataUnit {
		if bytes%1024 != 0 {
			break
		}
		bytes /= 1024
	}
	return bytes, dataUnit[i]
}

func (l LimitTime) String() string {
	switch nfte.LimitTime(l) {
	case nfte.LimitTimeSecond:
		return "second"
	case nfte.LimitTimeMinute:
		return "minute"
	case nfte.LimitTimeHour:
		return "hour"
	case nfte.LimitTimeDay:
		return "day"
	case nfte.LimitTimeWeek:
		return "week"
	}
	return "error"
}

type ExprLimit struct {
	*nfte.Limit
}

func newLimitEncoder(expr *nfte.Limit) *ExprLimit {
	return &ExprLimit{Limit: expr}
}

func (expr *ExprLimit) String() (string, error) {
	switch expr.Type {
	case nfte.LimitTypePkts:
		return fmt.Sprintf("limit rate %s %d/%s burst %d packets",
			map[bool]string{true: "over", false: ""}[expr.Over],
			expr.Rate, LimitTime(expr.Unit), expr.Burst), nil
	case nfte.LimitTypePktBytes:
		sb := strings.Builder{}
		rateVal, rateUnit := rate(expr.Rate).Rate()
		sb.WriteString(fmt.Sprintf("limit rate %s %d/%s/%s",
			map[bool]string{true: "over", false: ""}[expr.Over],
			rateVal, rateUnit, LimitTime(expr.Unit)))
		if expr.Burst != 0 {
			burst, burstUnit := rate(uint64(expr.Burst)).Rate()
			sb.WriteString(fmt.Sprintf(" burst %d %s", burst, burstUnit))
		}
		return sb.String(), nil
	}
	return "", nil
}

func (expr *ExprLimit) MarshalJSON() ([]byte, error) {
	var (
		rateVal, burst      uint64
		rateUnit, burstUnit string
	)
	if expr.Type == nfte.LimitTypePktBytes {
		rateVal, rateUnit = rate(expr.Rate).Rate()
		burst, burstUnit = rate(expr.Burst).Rate()
	}

	lm := map[string]interface{}{
		"limit": struct {
			Rate      uint64 `json:"rate"`
			Burst     uint64 `json:"burst"`
			Per       string `json:"per,omitempty"`
			Inv       bool   `json:"inv,omitempty"`
			RateUnit  string `json:"rate_unit,omitempty"`
			BurstUnit string `json:"burst_unit,omitempty"`
		}{
			Rate:      rateVal,
			Burst:     burst,
			Per:       LimitTime(expr.Unit).String(),
			Inv:       expr.Over,
			RateUnit:  rateUnit,
			BurstUnit: burstUnit,
		},
	}

	return json.Marshal(lm)
}
