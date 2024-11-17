package encoders

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	nfte "github.com/google/nftables/expr"
)

type QueueFlag nfte.QueueFlag

func (fl QueueFlag) List() (flags []string) {
	if fl&QueueFlag(nfte.QueueFlagBypass) != 0 {
		flags = append(flags, "bypass")
	}
	if fl&QueueFlag(nfte.QueueFlagFanout) != 0 {
		flags = append(flags, "fanout")
	}
	return flags
}

type ExprQueue struct {
	*nfte.Queue
}

func newQueueEncoder(expr *nfte.Queue) *ExprQueue {
	return &ExprQueue{Queue: expr}
}

func (expr *ExprQueue) String() (string, error) {
	sb := strings.Builder{}
	total := expr.Total
	exp := strconv.Itoa(int(expr.Num))
	if total > 1 {
		total += expr.Num - 1
		exp = fmt.Sprintf("%s-%d", exp, total)
	}
	sb.WriteString("queue")
	flags := QueueFlag(expr.Flag).List()
	if len(flags) > 0 {
		sb.WriteString(fmt.Sprintf(" flags %s", strings.Join(QueueFlag(expr.Flag).List(), ",")))
	}
	sb.WriteString(fmt.Sprintf(" to %s", exp))
	return sb.String(), nil
}

func (expr *ExprQueue) MarshalJSON() ([]byte, error) {
	var flag any
	flags := QueueFlag(expr.Flag).List()
	if len(flags) > 1 {
		flag = flags
	} else if len(flags) == 1 {
		flag = flags[0]
	}
	que := map[string]interface{}{
		"queue": struct {
			Num   uint16 `json:"num,omitempty"`
			Flags any    `json:"flags,omitempty"`
		}{
			Num:   expr.Num,
			Flags: flag,
		},
	}

	return json.Marshal(que)
}
