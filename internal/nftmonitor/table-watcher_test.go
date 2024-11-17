package nftmonitor

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/wildberries-tech/pkt-tracer/internal/nftables/cache"
	nl "github.com/wildberries-tech/pkt-tracer/internal/nl"
	proto "github.com/wildberries-tech/pkt-tracer/pkg/api/tracehub"

	"github.com/H-BF/corlib/pkg/patterns/observer"
	nftLib "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

// Recorder provides an nftables connection that does not send to the Linux
// kernel but instead records netlink messages into the recorder. The recorded
// requests can later be obtained using Requests and compared using Diff.
type (
	ConnMock struct {
		*nftLib.Conn
	}
	Recorder struct {
		requests []netlink.Message
	}
)

// override as a proxy method only for prepare data for the mock test
func (c *ConnMock) AddSet(s *nftLib.Set, vals []nftLib.SetElement) error {
	//prepare data for the mock test
	cache.SetsHolder.InsertSet(
		cache.SetKey{
			TableName: s.Table.Name,
			SetName:   s.Name,
			SetId:     1,
		},
		&cache.SetEntry{
			Set:      *s,
			Elements: vals,
		},
	)
	return c.Conn.AddSet(s, vals)
}

// Conn opens an nftables connection that records netlink messages into the
// Recorder.
func (r *Recorder) Conn() (*ConnMock, error) {
	conn, err := nftLib.New(nftLib.WithTestDial(
		func(req []netlink.Message) ([]netlink.Message, error) {
			r.requests = append(r.requests, req...)

			acks := make([]netlink.Message, 0, len(req))
			for _, msg := range req {
				if msg.Header.Flags&netlink.Acknowledge != 0 {
					acks = append(acks, netlink.Message{
						Header: netlink.Header{
							Length:   4,
							Type:     netlink.Error,
							Sequence: msg.Header.Sequence,
							PID:      msg.Header.PID,
						},
						Data: []byte{0, 0, 0, 0},
					})
				}
			}
			return acks, nil
		}))
	if err != nil {
		return nil, err
	}

	return &ConnMock{conn}, err
}

// Requests returns the recorded netlink messages (typically nftables requests).
func (r *Recorder) Requests() []netlink.Message {
	return r.requests
}

// NewRecorder returns a ready-to-use Recorder.
func NewRecorder() *Recorder {
	return &Recorder{}
}

type mockTableCache struct {
	tableCache
}

// override stub method
func (m *mockTableCache) Refresh() error {
	return nil
}

type tableTestSuite struct {
	suite.Suite
}

func Test_NftTableWatcher(t *testing.T) {
	suite.Run(t, new(tableTestSuite))
}

func (sui *tableTestSuite) Test_TableWatcher() {
	var doneCh chan struct{}
	type args struct {
		si time.Duration
	}
	tests := []struct {
		name string
		args args
		mock func(t *testing.T) Deps
	}{
		{
			name: "Test 1",
			args: args{si: time.Second},
			mock: func(t *testing.T) Deps {
				cli := NewMockStreamCli(t)
				nlWatcher := NewMockNetlinkWatcher(t)
				nlWatcher.On("Read").Return(func() chan nl.NlData {
					out := make(chan nl.NlData)
					rec := NewRecorder()
					c, err := rec.Conn()
					if err != nil {
						t.Fatal(err)
					}
					c.FlushRuleset()
					fillRuleset(c)
					if err := c.Flush(); err != nil {
						t.Fatal(err)
					}
					go func() {
						defer close(out)
						for _, m := range rec.Requests() {
							out <- nl.NlData{
								Messages: []syscall.NetlinkMessage{
									{
										Data: m.Data,
										Header: syscall.NlMsghdr{
											Len:   m.Header.Length,
											Type:  uint16(m.Header.Type),
											Flags: uint16(m.Header.Flags),
											Seq:   m.Header.Sequence,
											Pid:   m.Header.PID,
										},
									},
								},
							}
						}
						<-doneCh
					}()
					return out
				}())
				matchTable := func(o *proto.SyncTableReq) bool {
					expectedTable := `table ip filter {
	set ipSet {
		type ipv4_addr
		flags constant,interval
		elements = { 10.34.11.179 }
	}
	chain output {
		type filter hook output priority filter; policy accept;
		ip daddr @ipSet counter packets 0 bytes 0 log accept #handle 5
	}
}`
					return assert.NotNil(t, o) &&
						assert.True(t, len(o.GetTable()) > 0) &&
						assert.Equal(t, expectedTable, o.Table[0].TableStr)
				}
				cli.On("CloseAndRecv").Return(nil, nil)
				cli.On("Send", mock.MatchedBy(matchTable)).Maybe().Return(nil)
				return Deps{
					Client:       cli,
					AgentSubject: observer.NewSubject(),
					NlWatcher:    nlWatcher,
				}
			},
		},
	}
	for _, tt := range tests {
		sui.Run(tt.name, func() {
			doneCh = make(chan struct{})
			tblWatcher := tableWatcherImpl{
				Deps:         tt.mock(sui.T()),
				syncInterval: tt.args.si,
				cache:        &mockTableCache{},
				stop:         make(chan struct{}),
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err := tblWatcher.Run(ctx)
			close(doneCh)
			sui.Require().Error(err)
			sui.Require().ErrorIs(context.DeadlineExceeded, err)
		})
	}
}

func fillRuleset(c *ConnMock) error {
	var (
		policy = nftLib.ChainPolicyAccept
	)
	filter := c.AddTable(&nftLib.Table{
		Family: nftLib.TableFamilyIPv4,
		Name:   "filter",
	})

	input := c.AddChain(&nftLib.Chain{
		Name:     "output",
		Hooknum:  nftLib.ChainHookOutput,
		Priority: nftLib.ChainPriorityFilter,
		Table:    filter,
		Type:     nftLib.ChainTypeFilter,
		Policy:   &policy,
	})

	ipSet := &nftLib.Set{
		Name:     "ipSet",
		Table:    filter,
		KeyType:  nftLib.TypeIPAddr,
		Constant: true,
		Interval: true,
	}

	if err := c.AddSet(ipSet, []nftLib.SetElement{
		{
			Key: []byte(net.ParseIP("10.34.11.179").To4()),
		},
		{
			Key:         []byte(net.ParseIP("10.34.11.180").To4()),
			IntervalEnd: true,
		},
	}); err != nil {
		return err
	}

	c.AddRule(&nftLib.Rule{
		Handle: 5,
		Table:  filter,
		Chain:  input,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16,
				Len:          4,
			},

			&expr.Lookup{
				SourceRegister: 1,
				SetName:        ipSet.Name,
				SetID:          1,
			},
			&expr.Counter{},
			&expr.Log{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})
	return nil
}
