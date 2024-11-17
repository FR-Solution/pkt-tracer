package encoders

import "golang.org/x/sys/unix"

const (
	BitsPerByte     byte = 8
	BitsPerHalfByte byte = BitsPerByte / 2
)

type (
	ProtoType   int
	IcmpType    int
	Icmp6Type   int
	IcmpCode    int
	Icmp6Code   int
	TcpFlagType int
)

func (p ProtoType) String() string {
	switch p {
	case unix.IPPROTO_IP:
		return "ip"
	case unix.IPPROTO_IPV6:
		return "ip6"
	case unix.IPPROTO_ICMP:
		return "icmp"
	case unix.IPPROTO_ICMPV6:
		return "icmp6"
	case unix.IPPROTO_IGMP:
		return "igmp"
	case unix.IPPROTO_EGP:
		return "egp"
	case unix.IPPROTO_PUP:
		return "pup"
	case unix.IPPROTO_TCP:
		return "tcp"
	case unix.IPPROTO_UDP:
		return "udp"
	}
	return "unknown"
}

// ICMP_TYPE
const (
	ICMP_ECHOREPLY      IcmpType = 0
	ICMP_DEST_UNREACH   IcmpType = 3
	ICMP_SOURCE_QUENCH  IcmpType = 4
	ICMP_REDIRECT       IcmpType = 5
	ICMP_ECHO           IcmpType = 8
	ICMP_ROUTERADVERT   IcmpType = 9
	ICMP_ROUTERSOLICIT  IcmpType = 10
	ICMP_TIME_EXCEEDED  IcmpType = 11
	ICMP_PARAMETERPROB  IcmpType = 12
	ICMP_TIMESTAMP      IcmpType = 13
	ICMP_TIMESTAMPREPLY IcmpType = 14
	ICMP_INFO_REQUEST   IcmpType = 15
	ICMP_INFO_REPLY     IcmpType = 16
	ICMP_ADDRESS        IcmpType = 17
	ICMP_ADDRESSREPLY   IcmpType = 18
)

func (i IcmpType) String() string {
	switch i {
	case ICMP_ECHOREPLY:
		return "echo-reply"
	case ICMP_DEST_UNREACH:
		return "destination-unreachable"
	case ICMP_SOURCE_QUENCH:
		return "source-quench"
	case ICMP_REDIRECT:
		return "redirect"
	case ICMP_ECHO:
		return "echo-request"
	case ICMP_ROUTERADVERT:
		return "router-advertisement"
	case ICMP_ROUTERSOLICIT:
		return "router-solicitation"
	case ICMP_TIME_EXCEEDED:
		return "time-exceeded"
	case ICMP_PARAMETERPROB:
		return "parameter-problem"
	case ICMP_TIMESTAMP:
		return "timestamp-request"
	case ICMP_TIMESTAMPREPLY:
		return "timestamp-reply"
	case ICMP_INFO_REQUEST:
		return "info-request"
	case ICMP_INFO_REPLY:
		return "info-reply"
	case ICMP_ADDRESS:
		return "address-mask-request"
	case ICMP_ADDRESSREPLY:
		return "address-mask-reply"
	}
	return "unknown"
}

// ICMP_CODE
const (
	ICMP_NET_UNREACH  IcmpCode = 0
	ICMP_HOST_UNREACH IcmpCode = 1
	ICMP_PROT_UNREACH IcmpCode = 2
	ICMP_PORT_UNREACH IcmpCode = 3
	ICMP_NET_ANO      IcmpCode = 9
	ICMP_HOST_ANO     IcmpCode = 10
	ICMP_PKT_FILTERED IcmpCode = 13
	ICMP_FRAG_NEEDED  IcmpCode = 4
)

func (i IcmpCode) String() string {
	switch i {
	case ICMP_NET_UNREACH:
		return "net-unreachable"
	case ICMP_HOST_UNREACH:
		return "host-unreachable"
	case ICMP_PROT_UNREACH:
		return "prot-unreachable"
	case ICMP_PORT_UNREACH:
		return "port-unreachable"
	case ICMP_NET_ANO:
		return "net-prohibited"
	case ICMP_HOST_ANO:
		return "host-prohibited"
	case ICMP_PKT_FILTERED:
		return "admin-prohibited"
	case ICMP_FRAG_NEEDED:
		return "frag-needed"
	}
	return "unknown"
}

// ICMP6_TYPE
const (
	ICMP6_DST_UNREACH        Icmp6Type = 1
	ICMP6_PACKET_TOO_BIG     Icmp6Type = 2
	ICMP6_TIME_EXCEEDED      Icmp6Type = 3
	ICMP6_PARAM_PROB         Icmp6Type = 4
	ICMP6_ECHO_REQUEST       Icmp6Type = 128
	ICMP6_ECHO_REPLY         Icmp6Type = 129
	MLD_LISTENER_QUERY       Icmp6Type = 130
	MLD_LISTENER_REPORT      Icmp6Type = 131
	MLD_LISTENER_REDUCTION   Icmp6Type = 132
	ND_NEIGHBOR_SOLICIT      Icmp6Type = 133
	ND_NEIGHBOR_ADVERT       Icmp6Type = 134
	ND_REDIRECT              Icmp6Type = 137
	ICMP6_ROUTER_RENUMBERING Icmp6Type = 138
	IND_NEIGHBOR_SOLICIT     Icmp6Type = 141
	IND_NEIGHBOR_ADVERT      Icmp6Type = 142
	ICMPV6_MLD2_REPORT       Icmp6Type = 143
)

func (i Icmp6Type) String() string {
	switch i {
	case ICMP6_DST_UNREACH:
		return "destination-unreachable"
	case ICMP6_PACKET_TOO_BIG:
		return "packet-too-big"
	case ICMP6_TIME_EXCEEDED:
		return "time-exceeded"
	case ICMP6_PARAM_PROB:
		return "parameter-problem"
	case ICMP6_ECHO_REQUEST:
		return "echo-request"
	case ICMP6_ECHO_REPLY:
		return "echo-reply"
	case MLD_LISTENER_QUERY:
		return "mld-listener-query"
	case MLD_LISTENER_REPORT:
		return "mld-listener-report"
	case MLD_LISTENER_REDUCTION:
		return "mld-listener-reduction"
	case ND_NEIGHBOR_SOLICIT:
		return "nd-neighbor-solicit"
	case ND_NEIGHBOR_ADVERT:
		return "nd-neighbor-advert"
	case ND_REDIRECT:
		return "nd-redirect"
	case ICMP6_ROUTER_RENUMBERING:
		return "router-renumbering"
	case IND_NEIGHBOR_SOLICIT:
		return "ind-neighbor-solicit"
	case IND_NEIGHBOR_ADVERT:
		return "ind-neighbor-advert"
	case ICMPV6_MLD2_REPORT:
		return "mld2-listener-report"
	}
	return "unknown"
}

// ICMP6_CODE
const (
	ICMPV6_NOROUTE        Icmp6Code = 0
	ICMPV6_ADM_PROHIBITED Icmp6Code = 1
	ICMPV6_ADDR_UNREACH   Icmp6Code = 3
	ICMPV6_PORT_UNREACH   Icmp6Code = 4
	ICMPV6_POLICY_FAIL    Icmp6Code = 5
	ICMPV6_REJECT_ROUTE   Icmp6Code = 6
)

func (i Icmp6Code) String() string {
	switch i {
	case ICMPV6_NOROUTE:
		return ""
	case ICMPV6_ADM_PROHIBITED:
		return ""
	case ICMPV6_ADDR_UNREACH:
		return ""
	case ICMPV6_PORT_UNREACH:
		return ""
	case ICMPV6_POLICY_FAIL:
		return ""
	case ICMPV6_REJECT_ROUTE:
		return ""
	}
	return "unknown"
}

// TCP_FLAG_TYPE
const (
	TCP_FLAG_FIN TcpFlagType = 1 << iota
	TCP_FLAG_SYN
	TCP_FLAG_RST
	TCP_FLAG_PSH
	TCP_FLAG_ACK
	TCP_FLAG_URG
	TCP_FLAG_ECN
	TCP_FLAG_CWR
)

func (t TcpFlagType) String() string {
	switch t {
	case TCP_FLAG_FIN:
		return "fin"
	case TCP_FLAG_SYN:
		return "syn"
	case TCP_FLAG_RST:
		return "rst"
	case TCP_FLAG_PSH:
		return "psh"
	case TCP_FLAG_ACK:
		return "ack"
	case TCP_FLAG_URG:
		return "urg"
	case TCP_FLAG_ECN:
		return "ecn"
	case TCP_FLAG_CWR:
		return "cwr"
	}
	return "unknown"
}
