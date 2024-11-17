package trace

import (
	"encoding/json"
	"fmt"
	"time"
)

type (
	TraceModel struct {
		// trace id
		TrId uint32 `json:"trace_id"`
		// nftables table name
		Table string `json:"table"`
		// nftables chain name
		Chain string `json:"chain"`
		// nftables jump to a target name
		JumpTarget string `json:"jt,omitempty"`
		// nftables rule number
		RuleHandle uint64 `json:"handle"`
		// protocols family
		Family string `json:"family"`
		// input network interface
		Iifname string `json:"iif,omitempty"`
		// output network interface
		Oifname string `json:"oif,omitempty"`
		// source mac address
		SMacAddr string `json:"hw-src,omitempty"`
		// destination mac address
		DMacAddr string `json:"hw-dst,omitempty"`
		// source ip address
		SAddr string `json:"ip-src,omitempty"`
		// destination ip address
		DAddr string `json:"ip-dst,omitempty"`
		// source port
		SPort uint32 `json:"sport,omitempty"`
		// destination port
		DPort uint32 `json:"dport,omitempty"`
		// name of the security group for src ip
		SSgName string `json:"sg-src,omitempty"`
		// name of the security group for dst ip
		DSgName string `json:"sg-dst,omitempty"`
		// name of the network for src ip
		SSgNet string `json:"net-src,omitempty"`
		// name of the network for dst ip
		DSgNet string `json:"net-dst,omitempty"`
		// length packet
		Length uint32 `json:"len"`
		// ip protocol (tcp/udp/icmp/...)
		IpProto string `json:"proto"`
		// verdict for the rule
		Verdict string `json:"verdict"`
		// rule expression as string
		Rule string `json:"rule"`
		// user agent id
		UserAgent string `json:"agent,omitempty"`
	}

	FetchTraceModel struct {
		// trace id
		TrId uint32 `json:"trace_id"`
		// table id
		TableId uint64 `json:"-"`
		// nftables table name
		Table string `json:"table_name"`
		// nftables chain name
		Chain string `json:"chain_name"`
		// nftables jump to a target name
		JumpTarget string `json:"jt,omitempty"`
		// nftables rule number
		RuleHandle uint64 `json:"handle"`
		// rule expression
		Rule string `json:"rule"`
		// verdict for the rule
		Verdict string `json:"verdict"`
		// input network interface
		Iifname string `json:"iif,omitempty"`
		// output network interface
		Oifname string `json:"oif,omitempty"`
		// protocols family
		Family string `json:"family"`
		// ip protocol (tcp/udp/icmp/...)
		IpProto string `json:"proto"`
		// length packet
		Length uint32 `json:"len"`
		// source mac address
		SMacAddr string `json:"hw-src,omitempty"`
		// destination mac address
		DMacAddr string `json:"hw-dst,omitempty"`
		// source ip address
		SAddr string `json:"ip-src,omitempty"`
		// destination ip address
		DAddr string `json:"ip-dst,omitempty"`
		// source port
		SPort uint32 `json:"sport,omitempty"`
		// destination port
		DPort uint32 `json:"dport,omitempty"`
		// name of the security group for src ip
		SSgName string `json:"sg-src,omitempty"`
		// name of the security group for dst ip
		DSgName string `json:"sg-dst,omitempty"`
		// name of the network for src ip
		SSgNet string `json:"net-src,omitempty"`
		// name of the network for dst ip
		DSgNet string `json:"net-dst,omitempty"`
		// agent identifier
		UserAgent string `json:"agent,omitempty"`
		// time stamps
		Timestamp time.Time `json:"timestamp"`
	}

	TimeRange struct {
		From time.Time
		To   time.Time
	}

	TraceScopeModel struct {
		// traces ids
		TrId []uint32
		// nftables tables names
		Table []string
		// nftables chains names
		Chain []string
		// nftables jump to a target names
		JumpTarget []string
		// nftables rules numbers
		RuleHandle []uint64
		// protocols family
		Family []string
		// input network interfaces
		Iifname []string
		// output network interfaces
		Oifname []string
		// source mac addresses
		SMacAddr []string
		// destination mac addresses
		DMacAddr []string
		// source ip addresses
		SAddr []string
		// destination ip addresses
		DAddr []string
		// source ports
		SPort []uint32
		// destination ports
		DPort []uint32
		// names of the security group for src ip
		SSgName []string
		// names of the security group for dst ip
		DSgName []string
		// names of the network for src ip
		SSgNet []string
		// names of the network for dst ip
		DSgNet []string
		// lengths of packets
		Length []uint32
		// ip protocols (tcp/udp/icmp/...)
		IpProto []string
		// verdicts of rules
		Verdict []string
		// rules expressions
		Rule []string
		// time filter
		Time *TimeRange
		// visor agents identifiers
		AgentsIds []string
		// follow mode on/off
		FollowMode bool
		// complex query filter parameter
		Query string
	}

	NftRule struct {
		// nftables chain name
		ChainName string
		// rule expression
		Rule string
	}

	NftTableModel struct {
		// nftables table name
		TableName string
		// protocols family
		TableFamily string
		// nftables table represented as string
		TableStr string
		// nftables rules items
		Rules []*NftRule
	}
	FetchNftTableModel struct {
		// nftables table id
		TableId uint64
		// nftables table represented as string
		TableStr string
		// time stamps
		Timestamp time.Time
	}
)

func (t *FetchTraceModel) JsonString() string {
	b, _ := json.Marshal(t)
	return string(b)
}

func (t *FetchTraceModel) FiveTuple() string {
	return fmt.Sprintf("src=%-25s dst=%-25s proto=%-8s",
		fmt.Sprintf("%s:%d", t.SAddr, t.SPort),
		fmt.Sprintf("%s:%d", t.DAddr, t.DPort),
		t.IpProto)
}
