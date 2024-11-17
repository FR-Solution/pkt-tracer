package nftrace

import "golang.org/x/sys/unix"

const (
	NFTNL_TRACE_CHAIN uint = iota //  name of the chain (NLA_STRING)
	NFTNL_TRACE_FAMILY
	NFTNL_TRACE_ID      //  pseudo-id, same for each skb traced (NLA_U32
	NFTNL_TRACE_IIF     // indev ifindex (NLA_U32)
	NFTNL_TRACE_IIFTYPE // netdev->type of indev (NLA_U16)
	NFTNL_TRACE_JUMP_TARGET
	NFTNL_TRACE_OIF              // outdev ifindex (NLA_U32)
	NFTNL_TRACE_OIFTYPE          // netdev->type of outdev (NLA_U16)
	NFTNL_TRACE_MARK             // nfmark (NLA_U32)
	NFTNL_TRACE_LL_HEADER        // linklayer header (NLA_BINARY)
	NFTNL_TRACE_NETWORK_HEADER   // network header (NLA_BINARY)
	NFTNL_TRACE_TRANSPORT_HEADER // transport header (NLA_BINARY)
	NFTNL_TRACE_TABLE            // name of the table (NLA_STRING)
	NFTNL_TRACE_TYPE             // type of the event (NLA_U32: nft_trace_types)
	NFTNL_TRACE_RULE_HANDLE      // numeric handle of the rule (NLA_U64)
	NFTNL_TRACE_VERDICT          // verdict returned by hook (NLA_NESTED: nft_verdicts)
	NFTNL_TRACE_NFPROTO          // nf protocol processed (NLA_U32)
	NFTNL_TRACE_POLICY           // policy that decided fate of packet (NLA_U32)

	NFTNL_TRACE_MAX
)

const NFT_TRACETYPE_MAX = unix.NFT_TRACETYPE_RULE

const NFTA_TRACE_MAX = unix.NFTA_TRACE_PAD

const (
	NFTA_VERDICT_CHAIN_ID uint = iota + 3 // jump target chain ID (NLA_U32)

	NFTA_VERDICT_MAX uint = iota + 4
)

/* We overload the higher bits for encoding auxiliary data such as the queue
 * number or errno values. Not nice, but better than additional function
 * arguments. */
const NF_VERDICT_MASK = 0x000000ff

/**
 * enum nft_verdicts - nf_tables internal verdicts
 *
 * @NFT_CONTINUE: continue evaluation of the current rule
 * @NFT_BREAK: terminate evaluation of the current rule
 * @NFT_JUMP: push the current chain on the jump stack and jump to a chain
 * @NFT_GOTO: jump to a chain without pushing the current chain on the jump stack
 * @NFT_RETURN: return to the topmost chain on the jump stack
 *
 * The nf_tables verdicts share their numeric space with the netfilter verdicts.
 */
const (
	NFT_CONTINUE = -1
	NFT_BREAK    = -2
	NFT_JUMP     = -3
	NFT_GOTO     = -4
	NFT_RETURN   = -5
)

/* Responses from hook functions. */
const (
	NF_DROP        = 0
	NF_ACCEPT      = 1
	NF_STOLEN      = 2
	NF_QUEUE       = 3
	NF_REPEAT      = 4
	NF_STOP        = 5 /* Deprecated, for userspace nf_queue compatibility. */
	NF_MAX_VERDICT = NF_STOP
)
