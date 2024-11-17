package flags

import (
	"testing"
	"time"
	"unsafe"

	model "github.com/wildberries-tech/pkt-tracer/internal/models/trace"

	"github.com/google/shlex"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/suite"
)

type flagsTestSuite struct {
	suite.Suite
}

func Test_Flags(t *testing.T) {
	suite.Run(t, new(flagsTestSuite))
}

func (sui *flagsTestSuite) Test_GetFlagParamsByGroup() {
	const group = "trace"
	f := &Flags{}
	testCases := []struct {
		name     string
		group    string
		expected []FlagParams
	}{
		{
			name:  "valid group trace",
			group: group,
			expected: []FlagParams{
				{Name: "trid", Group: "trace", Usage: "set filter by trace id. Supported multiple values separated by symbol ',' and meaning logical OR operation (e.g. --trid 123,987,234)", Example: "123,987,234"},
				{Name: "table", Group: "trace", Usage: "set filter by table name. Supported multiple values separated by symbol ',' and meaning logical OR operation (e.g. --table flt,fwd,output)", Example: "flt,fwd,output"},
				{Name: "chain", Group: "trace", Usage: "set filter by chain name. Supported multiple values (see --table Flag)", Example: "chain1,chain2"},
				{Name: "jt", Group: "trace", Usage: "set filter by jump target name. Supported multiple values (see --table Flag)", Example: "target1,target2"},
				{Name: "handle", Group: "trace", Usage: "set filter by rule handle. Supported multiple values (see --trid Flag)", Example: "1,2,3,4,5"},
				{Name: "family", Group: "trace", Usage: "set filter by protocols family (ip/ip6). Supported multiple values (see --table Flag)", Example: "ip,ip6"},
				{Name: "iif", Group: "trace", Usage: "set filter by network interface name for ingress traffic. Supported multiple values (see --table Flag)", Example: "eth0,eth1"},
				{Name: "oif", Group: "trace", Usage: "set filter by network interface name for egress traffic. Supported multiple values (see --table Flag)", Example: "eth0,eth1"},
				{Name: "hw-src", Group: "trace", Usage: "set filter by source mac address. Supported multiple values (see --table Flag)", Example: "00:00:00:00:00:00,00:00:00:00:00:01"},
				{Name: "hw-dst", Group: "trace", Usage: "set filter by destination mac address. Supported multiple values (see --table Flag)", Example: "00:00:00:00:00:00,00:00:00:00:00:01"},
				{Name: "ip-src", Group: "trace", Usage: "set filter by source ip address. Supported multiple values (see --table Flag)", Example: "192.168.0.1,192.168.0.2"},
				{Name: "ip-dst", Group: "trace", Usage: "set filter by destination ip address. Supported multiple values (see --table Flag)", Example: "192.168.0.1,192.168.0.2"},
				{Name: "sport", Group: "trace", Usage: "set filter by source port. Supported multiple values (see --trid Flag)", Example: "80,443"},
				{Name: "dport", Group: "trace", Usage: "set filter by destination port. Supported multiple values (see --trid Flag)", Example: "80,443"},
				{Name: "sg-src", Group: "trace", Usage: "set filter by source security group name. Supported multiple values (see --table Flag)", Example: "sg1,sg2"},
				{Name: "sg-dst", Group: "trace", Usage: "set filter by destination security group name. Supported multiple values (see --table Flag)", Example: "sg1,sg2"},
				{Name: "net-src", Group: "trace", Usage: "set filter by source network name. Supported multiple values (see --table Flag)", Example: "192.168.0.0/32,192.168.50.0/32"},
				{Name: "net-dst", Group: "trace", Usage: "set filter by destination network name. Supported multiple values (see --table Flag)", Example: "192.168.0.0/32,192.168.50.0/32"},
				{Name: "len", Group: "trace", Usage: "set filter by network packet length. Supported multiple values (see --trid Flag)", Example: "20,80"},
				{Name: "proto", Group: "trace", Usage: "set filter by ip protocol (tcp/udp/icmp/...). Supported multiple values (see --table Flag)", Example: "tcp,udp,icmp"},
				{Name: "verdict", Group: "trace", Usage: "set filter by rule verdict (accept/drop/continue). Supported multiple values (see --table Flag)", Example: "accept,drop,continue"},
			},
		},
		{
			name:  "invalid group",
			group: "invalid",
		},
	}
	for _, tc := range testCases {
		sui.Run(tc.name, func() {
			sui.Require().Equal(tc.expected, f.GetFlagParamsByGroup(tc.group))
		})
	}
}

func (sui *flagsTestSuite) Test_NameFromTag() {
	expNames := map[uintptr]string{
		unsafe.Offsetof(Flags{}.ConfigPath):   "config",
		unsafe.Offsetof(Flags{}.JsonFormat):   "json",
		unsafe.Offsetof(Flags{}.ServerUrl):    "host",
		unsafe.Offsetof(Flags{}.LogLevel):     "log-level",
		unsafe.Offsetof(Flags{}.VerboseMode):  "verbose",
		unsafe.Offsetof(Flags{}.TimeFrom):     "time-from",
		unsafe.Offsetof(Flags{}.TimeTo):       "time-to",
		unsafe.Offsetof(Flags{}.TimeDuration): "time",
		unsafe.Offsetof(Flags{}.FollowMode):   "follow",
		unsafe.Offsetof(Flags{}.Query):        "query",
		unsafe.Offsetof(Flags{}.TrId):         "trid",
		unsafe.Offsetof(Flags{}.Table):        "table",
		unsafe.Offsetof(Flags{}.Chain):        "chain",
		unsafe.Offsetof(Flags{}.JumpTarget):   "jt",
		unsafe.Offsetof(Flags{}.RuleHandle):   "handle",
		unsafe.Offsetof(Flags{}.Family):       "family",
		unsafe.Offsetof(Flags{}.Iifname):      "iif",
		unsafe.Offsetof(Flags{}.Oifname):      "oif",
		unsafe.Offsetof(Flags{}.SMacAddr):     "hw-src",
		unsafe.Offsetof(Flags{}.DMacAddr):     "hw-dst",
		unsafe.Offsetof(Flags{}.SAddr):        "ip-src",
		unsafe.Offsetof(Flags{}.DAddr):        "ip-dst",
		unsafe.Offsetof(Flags{}.SPort):        "sport",
		unsafe.Offsetof(Flags{}.DPort):        "dport",
		unsafe.Offsetof(Flags{}.SSgName):      "sg-src",
		unsafe.Offsetof(Flags{}.DSgName):      "sg-dst",
		unsafe.Offsetof(Flags{}.SSgNet):       "net-src",
		unsafe.Offsetof(Flags{}.DSgNet):       "net-dst",
		unsafe.Offsetof(Flags{}.Length):       "len",
		unsafe.Offsetof(Flags{}.IpProto):      "proto",
		unsafe.Offsetof(Flags{}.Verdict):      "verdict",
	}
	sui.Run("name from object pointer", func() {
		f := &Flags{}
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.ConfigPath)], f.NameFromTag(&f.ConfigPath))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.JsonFormat)], f.NameFromTag(&f.JsonFormat))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.ServerUrl)], f.NameFromTag(&f.ServerUrl))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.LogLevel)], f.NameFromTag(&f.LogLevel))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.VerboseMode)], f.NameFromTag(&f.VerboseMode))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.TimeFrom)], f.NameFromTag(&f.TimeFrom))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.TimeTo)], f.NameFromTag(&f.TimeTo))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.TimeDuration)], f.NameFromTag(&f.TimeDuration))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.FollowMode)], f.NameFromTag(&f.FollowMode))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Query)], f.NameFromTag(&f.Query))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.TrId)], f.NameFromTag(&f.TrId))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Table)], f.NameFromTag(&f.Table))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Chain)], f.NameFromTag(&f.Chain))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.JumpTarget)], f.NameFromTag(&f.JumpTarget))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.RuleHandle)], f.NameFromTag(&f.RuleHandle))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Family)], f.NameFromTag(&f.Family))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Iifname)], f.NameFromTag(&f.Iifname))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Oifname)], f.NameFromTag(&f.Oifname))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.SMacAddr)], f.NameFromTag(&f.SMacAddr))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.DMacAddr)], f.NameFromTag(&f.DMacAddr))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.SAddr)], f.NameFromTag(&f.SAddr))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.DAddr)], f.NameFromTag(&f.DAddr))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.SPort)], f.NameFromTag(&f.SPort))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.DPort)], f.NameFromTag(&f.DPort))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.SSgName)], f.NameFromTag(&f.SSgName))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.DSgName)], f.NameFromTag(&f.DSgName))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.SSgNet)], f.NameFromTag(&f.SSgNet))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.DSgNet)], f.NameFromTag(&f.DSgNet))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Length)], f.NameFromTag(&f.Length))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.IpProto)], f.NameFromTag(&f.IpProto))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Verdict)], f.NameFromTag(&f.Verdict))
	})
	sui.Run("name from object", func() {
		f := Flags{}
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.ConfigPath)], f.NameFromTag(&f.ConfigPath))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.JsonFormat)], f.NameFromTag(&f.JsonFormat))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.ServerUrl)], f.NameFromTag(&f.ServerUrl))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.LogLevel)], f.NameFromTag(&f.LogLevel))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.VerboseMode)], f.NameFromTag(&f.VerboseMode))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.TimeFrom)], f.NameFromTag(&f.TimeFrom))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.TimeTo)], f.NameFromTag(&f.TimeTo))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.TimeDuration)], f.NameFromTag(&f.TimeDuration))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.FollowMode)], f.NameFromTag(&f.FollowMode))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Query)], f.NameFromTag(&f.Query))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.TrId)], f.NameFromTag(&f.TrId))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Table)], f.NameFromTag(&f.Table))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Chain)], f.NameFromTag(&f.Chain))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.JumpTarget)], f.NameFromTag(&f.JumpTarget))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.RuleHandle)], f.NameFromTag(&f.RuleHandle))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Family)], f.NameFromTag(&f.Family))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Iifname)], f.NameFromTag(&f.Iifname))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Oifname)], f.NameFromTag(&f.Oifname))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.SMacAddr)], f.NameFromTag(&f.SMacAddr))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.DMacAddr)], f.NameFromTag(&f.DMacAddr))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.SAddr)], f.NameFromTag(&f.SAddr))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.DAddr)], f.NameFromTag(&f.DAddr))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.SPort)], f.NameFromTag(&f.SPort))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.DPort)], f.NameFromTag(&f.DPort))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.SSgName)], f.NameFromTag(&f.SSgName))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.DSgName)], f.NameFromTag(&f.DSgName))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.SSgNet)], f.NameFromTag(&f.SSgNet))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.DSgNet)], f.NameFromTag(&f.DSgNet))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Length)], f.NameFromTag(&f.Length))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.IpProto)], f.NameFromTag(&f.IpProto))
		sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Verdict)], f.NameFromTag(&f.Verdict))
	})
	sui.Run("name from clone of object", func() {
		Flags{}.Clone(func(f *Flags) {
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.ConfigPath)], f.NameFromTag(&f.ConfigPath))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.JsonFormat)], f.NameFromTag(&f.JsonFormat))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.ServerUrl)], f.NameFromTag(&f.ServerUrl))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.LogLevel)], f.NameFromTag(&f.LogLevel))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.VerboseMode)], f.NameFromTag(&f.VerboseMode))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.TimeFrom)], f.NameFromTag(&f.TimeFrom))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.TimeTo)], f.NameFromTag(&f.TimeTo))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.TimeDuration)], f.NameFromTag(&f.TimeDuration))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.FollowMode)], f.NameFromTag(&f.FollowMode))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Query)], f.NameFromTag(&f.Query))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.TrId)], f.NameFromTag(&f.TrId))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Table)], f.NameFromTag(&f.Table))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Chain)], f.NameFromTag(&f.Chain))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.JumpTarget)], f.NameFromTag(&f.JumpTarget))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.RuleHandle)], f.NameFromTag(&f.RuleHandle))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Family)], f.NameFromTag(&f.Family))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Iifname)], f.NameFromTag(&f.Iifname))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Oifname)], f.NameFromTag(&f.Oifname))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.SMacAddr)], f.NameFromTag(&f.SMacAddr))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.DMacAddr)], f.NameFromTag(&f.DMacAddr))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.SAddr)], f.NameFromTag(&f.SAddr))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.DAddr)], f.NameFromTag(&f.DAddr))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.SPort)], f.NameFromTag(&f.SPort))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.DPort)], f.NameFromTag(&f.DPort))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.SSgName)], f.NameFromTag(&f.SSgName))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.DSgName)], f.NameFromTag(&f.DSgName))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.SSgNet)], f.NameFromTag(&f.SSgNet))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.DSgNet)], f.NameFromTag(&f.DSgNet))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Length)], f.NameFromTag(&f.Length))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.IpProto)], f.NameFromTag(&f.IpProto))
			sui.Require().Equal(expNames[unsafe.Offsetof(Flags{}.Verdict)], f.NameFromTag(&f.Verdict))
		})
	})
}

func (sui *flagsTestSuite) Test_GetFieldFlagParams() {
	expectedParams := map[uintptr]FlagParams{
		unsafe.Offsetof(Flags{}.ConfigPath):   {Name: "config", Key: "c", Usage: "app config file"},
		unsafe.Offsetof(Flags{}.JsonFormat):   {Name: "json", Key: "j", Usage: "enable extended output in the json format"},
		unsafe.Offsetof(Flags{}.ServerUrl):    {Name: "host", Key: "H", Usage: "trace-hub service address (format: <IP>:<port>)", Example: "tcp://127.0.0.1:9000"},
		unsafe.Offsetof(Flags{}.LogLevel):     {Name: "log-level", DefValue: "INFO", Usage: "log level: INFO|DEBUG|WARN|ERROR|PANIC|FATAL"},
		unsafe.Offsetof(Flags{}.VerboseMode):  {Name: "verbose", Key: "v", Usage: "verbose output mode"},
		unsafe.Offsetof(Flags{}.TimeFrom):     {Name: "time-from", Usage: "specifies the start time of the time interval in the format '2024-10-08T12:30:00Z'"},
		unsafe.Offsetof(Flags{}.TimeTo):       {Name: "time-to", Usage: "specifies the end time of the time interval in the format '2024-10-08T12:30:00Z'"},
		unsafe.Offsetof(Flags{}.TimeDuration): {Name: "time", Key: "t", Usage: "time offset from current time (e.g., 1s for 1 second, 1m for 1 minute, 1h for 1 hour, 1d for 1 day)", Example: "1s"},
		unsafe.Offsetof(Flags{}.FollowMode):   {Name: "follow", Key: "f", Usage: "follow or tail continuous output [Required --time Flag]"},
		unsafe.Offsetof(Flags{}.Query):        {Name: "query", Key: "q", Usage: "complex query filter like: (sport>=80 and sport<=443) and ip-dst=='93.184.215.14' and dport not in (80,443)", Example: "(sport>=80 and sport<=443) and ip-dst=='93.184.215.14' and dport in (80,443)"},
		unsafe.Offsetof(Flags{}.TrId):         {Name: "trid", Group: "trace", Usage: "set filter by trace id. Supported multiple values separated by symbol ',' and meaning logical OR operation (e.g. --trid 123,987,234)", Example: "123,987,234"},
		unsafe.Offsetof(Flags{}.Table):        {Name: "table", Group: "trace", Usage: "set filter by table name. Supported multiple values separated by symbol ',' and meaning logical OR operation (e.g. --table flt,fwd,output)", Example: "flt,fwd,output"},
		unsafe.Offsetof(Flags{}.Chain):        {Name: "chain", Group: "trace", Usage: "set filter by chain name. Supported multiple values (see --table Flag)", Example: "chain1,chain2"},
		unsafe.Offsetof(Flags{}.JumpTarget):   {Name: "jt", Group: "trace", Usage: "set filter by jump target name. Supported multiple values (see --table Flag)", Example: "target1,target2"},
		unsafe.Offsetof(Flags{}.RuleHandle):   {Name: "handle", Group: "trace", Usage: "set filter by rule handle. Supported multiple values (see --trid Flag)", Example: "1,2,3,4,5"},
		unsafe.Offsetof(Flags{}.Family):       {Name: "family", Group: "trace", Usage: "set filter by protocols family (ip/ip6). Supported multiple values (see --table Flag)", Example: "ip,ip6"},
		unsafe.Offsetof(Flags{}.Iifname):      {Name: "iif", Group: "trace", Usage: "set filter by network interface name for ingress traffic. Supported multiple values (see --table Flag)", Example: "eth0,eth1"},
		unsafe.Offsetof(Flags{}.Oifname):      {Name: "oif", Group: "trace", Usage: "set filter by network interface name for egress traffic. Supported multiple values (see --table Flag)", Example: "eth0,eth1"},
		unsafe.Offsetof(Flags{}.SMacAddr):     {Name: "hw-src", Group: "trace", Usage: "set filter by source mac address. Supported multiple values (see --table Flag)", Example: "00:00:00:00:00:00,00:00:00:00:00:01"},
		unsafe.Offsetof(Flags{}.DMacAddr):     {Name: "hw-dst", Group: "trace", Usage: "set filter by destination mac address. Supported multiple values (see --table Flag)", Example: "00:00:00:00:00:00,00:00:00:00:00:01"},
		unsafe.Offsetof(Flags{}.SAddr):        {Name: "ip-src", Group: "trace", Usage: "set filter by source ip address. Supported multiple values (see --table Flag)", Example: "192.168.0.1,192.168.0.2"},
		unsafe.Offsetof(Flags{}.DAddr):        {Name: "ip-dst", Group: "trace", Usage: "set filter by destination ip address. Supported multiple values (see --table Flag)", Example: "192.168.0.1,192.168.0.2"},
		unsafe.Offsetof(Flags{}.SPort):        {Name: "sport", Group: "trace", Usage: "set filter by source port. Supported multiple values (see --trid Flag)", Example: "80,443"},
		unsafe.Offsetof(Flags{}.DPort):        {Name: "dport", Group: "trace", Usage: "set filter by destination port. Supported multiple values (see --trid Flag)", Example: "80,443"},
		unsafe.Offsetof(Flags{}.SSgName):      {Name: "sg-src", Group: "trace", Usage: "set filter by source security group name. Supported multiple values (see --table Flag)", Example: "sg1,sg2"},
		unsafe.Offsetof(Flags{}.DSgName):      {Name: "sg-dst", Group: "trace", Usage: "set filter by destination security group name. Supported multiple values (see --table Flag)", Example: "sg1,sg2"},
		unsafe.Offsetof(Flags{}.SSgNet):       {Name: "net-src", Group: "trace", Usage: "set filter by source network name. Supported multiple values (see --table Flag)", Example: "192.168.0.0/32,192.168.50.0/32"},
		unsafe.Offsetof(Flags{}.DSgNet):       {Name: "net-dst", Group: "trace", Usage: "set filter by destination network name. Supported multiple values (see --table Flag)", Example: "192.168.0.0/32,192.168.50.0/32"},
		unsafe.Offsetof(Flags{}.Length):       {Name: "len", Group: "trace", Usage: "set filter by network packet length. Supported multiple values (see --trid Flag)", Example: "20,80"},
		unsafe.Offsetof(Flags{}.IpProto):      {Name: "proto", Group: "trace", Usage: "set filter by ip protocol (tcp/udp/icmp/...). Supported multiple values (see --table Flag)", Example: "tcp,udp,icmp"},
		unsafe.Offsetof(Flags{}.Verdict):      {Name: "verdict", Group: "trace", Usage: "set filter by rule verdict (accept/drop/continue). Supported multiple values (see --table Flag)", Example: "accept,drop,continue"},
	}
	sui.Run("name from object pointer", func() {
		f := &Flags{}
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.ConfigPath)], f.GetFieldFlagParams(&f.ConfigPath))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.JsonFormat)], f.GetFieldFlagParams(&f.JsonFormat))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.ServerUrl)], f.GetFieldFlagParams(&f.ServerUrl))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.LogLevel)], f.GetFieldFlagParams(&f.LogLevel))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.VerboseMode)], f.GetFieldFlagParams(&f.VerboseMode))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.TimeFrom)], f.GetFieldFlagParams(&f.TimeFrom))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.TimeTo)], f.GetFieldFlagParams(&f.TimeTo))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.TimeDuration)], f.GetFieldFlagParams(&f.TimeDuration))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.FollowMode)], f.GetFieldFlagParams(&f.FollowMode))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Query)], f.GetFieldFlagParams(&f.Query))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.TrId)], f.GetFieldFlagParams(&f.TrId))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Table)], f.GetFieldFlagParams(&f.Table))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Chain)], f.GetFieldFlagParams(&f.Chain))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.JumpTarget)], f.GetFieldFlagParams(&f.JumpTarget))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.RuleHandle)], f.GetFieldFlagParams(&f.RuleHandle))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Family)], f.GetFieldFlagParams(&f.Family))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Iifname)], f.GetFieldFlagParams(&f.Iifname))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Oifname)], f.GetFieldFlagParams(&f.Oifname))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.SMacAddr)], f.GetFieldFlagParams(&f.SMacAddr))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.DMacAddr)], f.GetFieldFlagParams(&f.DMacAddr))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.SAddr)], f.GetFieldFlagParams(&f.SAddr))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.DAddr)], f.GetFieldFlagParams(&f.DAddr))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.SPort)], f.GetFieldFlagParams(&f.SPort))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.DPort)], f.GetFieldFlagParams(&f.DPort))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.SSgName)], f.GetFieldFlagParams(&f.SSgName))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.DSgName)], f.GetFieldFlagParams(&f.DSgName))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.SSgNet)], f.GetFieldFlagParams(&f.SSgNet))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.DSgNet)], f.GetFieldFlagParams(&f.DSgNet))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Length)], f.GetFieldFlagParams(&f.Length))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.IpProto)], f.GetFieldFlagParams(&f.IpProto))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Verdict)], f.GetFieldFlagParams(&f.Verdict))
	})
	sui.Run("name from object", func() {
		f := Flags{}
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.ConfigPath)], f.GetFieldFlagParams(&f.ConfigPath))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.JsonFormat)], f.GetFieldFlagParams(&f.JsonFormat))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.ServerUrl)], f.GetFieldFlagParams(&f.ServerUrl))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.LogLevel)], f.GetFieldFlagParams(&f.LogLevel))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.VerboseMode)], f.GetFieldFlagParams(&f.VerboseMode))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.TimeFrom)], f.GetFieldFlagParams(&f.TimeFrom))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.TimeTo)], f.GetFieldFlagParams(&f.TimeTo))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.TimeDuration)], f.GetFieldFlagParams(&f.TimeDuration))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.FollowMode)], f.GetFieldFlagParams(&f.FollowMode))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Query)], f.GetFieldFlagParams(&f.Query))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.TrId)], f.GetFieldFlagParams(&f.TrId))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Table)], f.GetFieldFlagParams(&f.Table))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Chain)], f.GetFieldFlagParams(&f.Chain))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.JumpTarget)], f.GetFieldFlagParams(&f.JumpTarget))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.RuleHandle)], f.GetFieldFlagParams(&f.RuleHandle))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Family)], f.GetFieldFlagParams(&f.Family))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Iifname)], f.GetFieldFlagParams(&f.Iifname))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Oifname)], f.GetFieldFlagParams(&f.Oifname))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.SMacAddr)], f.GetFieldFlagParams(&f.SMacAddr))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.DMacAddr)], f.GetFieldFlagParams(&f.DMacAddr))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.SAddr)], f.GetFieldFlagParams(&f.SAddr))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.DAddr)], f.GetFieldFlagParams(&f.DAddr))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.SPort)], f.GetFieldFlagParams(&f.SPort))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.DPort)], f.GetFieldFlagParams(&f.DPort))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.SSgName)], f.GetFieldFlagParams(&f.SSgName))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.DSgName)], f.GetFieldFlagParams(&f.DSgName))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.SSgNet)], f.GetFieldFlagParams(&f.SSgNet))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.DSgNet)], f.GetFieldFlagParams(&f.DSgNet))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Length)], f.GetFieldFlagParams(&f.Length))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.IpProto)], f.GetFieldFlagParams(&f.IpProto))
		sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Verdict)], f.GetFieldFlagParams(&f.Verdict))
	})
	sui.Run("name from clone of object", func() {
		Flags{}.Clone(func(f *Flags) {
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.ConfigPath)], f.GetFieldFlagParams(&f.ConfigPath))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.JsonFormat)], f.GetFieldFlagParams(&f.JsonFormat))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.ServerUrl)], f.GetFieldFlagParams(&f.ServerUrl))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.LogLevel)], f.GetFieldFlagParams(&f.LogLevel))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.VerboseMode)], f.GetFieldFlagParams(&f.VerboseMode))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.TimeFrom)], f.GetFieldFlagParams(&f.TimeFrom))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.TimeTo)], f.GetFieldFlagParams(&f.TimeTo))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.TimeDuration)], f.GetFieldFlagParams(&f.TimeDuration))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.FollowMode)], f.GetFieldFlagParams(&f.FollowMode))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Query)], f.GetFieldFlagParams(&f.Query))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.TrId)], f.GetFieldFlagParams(&f.TrId))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Table)], f.GetFieldFlagParams(&f.Table))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Chain)], f.GetFieldFlagParams(&f.Chain))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.JumpTarget)], f.GetFieldFlagParams(&f.JumpTarget))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.RuleHandle)], f.GetFieldFlagParams(&f.RuleHandle))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Family)], f.GetFieldFlagParams(&f.Family))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Iifname)], f.GetFieldFlagParams(&f.Iifname))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Oifname)], f.GetFieldFlagParams(&f.Oifname))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.SMacAddr)], f.GetFieldFlagParams(&f.SMacAddr))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.DMacAddr)], f.GetFieldFlagParams(&f.DMacAddr))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.SAddr)], f.GetFieldFlagParams(&f.SAddr))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.DAddr)], f.GetFieldFlagParams(&f.DAddr))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.SPort)], f.GetFieldFlagParams(&f.SPort))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.DPort)], f.GetFieldFlagParams(&f.DPort))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.SSgName)], f.GetFieldFlagParams(&f.SSgName))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.DSgName)], f.GetFieldFlagParams(&f.DSgName))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.SSgNet)], f.GetFieldFlagParams(&f.SSgNet))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.DSgNet)], f.GetFieldFlagParams(&f.DSgNet))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Length)], f.GetFieldFlagParams(&f.Length))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.IpProto)], f.GetFieldFlagParams(&f.IpProto))
			sui.Require().Equal(expectedParams[unsafe.Offsetof(Flags{}.Verdict)], f.GetFieldFlagParams(&f.Verdict))
		})
	})
}

func (sui *flagsTestSuite) Test_ToTraceScopeModel() {
	dur := time.Second
	to := time.Now()
	from := to.Add(-dur)
	testCases := []struct {
		name string
		fl   Flags
		md   model.TraceScopeModel
	}{
		{
			name: "not query",
			fl: Flags{
				ConfigPath:   "path",
				JsonFormat:   true,
				ServerUrl:    "tcp://127.0.0.1:9000",
				LogLevel:     "INFO",
				VerboseMode:  true,
				TimeFrom:     &from,
				TimeTo:       &to,
				TimeDuration: nil,
				FollowMode:   false,
				Query:        "",
				TrId:         []uint{123, 987, 234},
				Table:        []string{"flt", "fwd", "output"},
				Chain:        []string{"chain1", "chain2"},
				JumpTarget:   []string{"target1", "target2"},
				RuleHandle:   []uint{1, 2, 3, 4, 5},
				Family:       []string{"ip", "ip6"},
				Iifname:      []string{"eth0", "eth1"},
				Oifname:      []string{"eth0", "eth1"},
				SMacAddr:     []string{"00:00:00:00:00:00", "00:00:00:00:00:01"},
				DMacAddr:     []string{"00:00:00:00:00:00", "00:00:00:00:00:01"},
				SAddr:        []string{"192.168.0.1", "192.168.0.2"},
				DAddr:        []string{"192.168.0.1", "192.168.0.2"},
				SPort:        []uint{80, 443},
				DPort:        []uint{80, 443},
				SSgName:      []string{"sg1", "sg2"},
				DSgName:      []string{"sg1", "sg2"},
				SSgNet:       []string{"192.168.0.0/32", "192.168.50.0/32"},
				DSgNet:       []string{"192.168.0.0/32", "192.168.50.0/32"},
				Length:       []uint{20, 80},
				IpProto:      []string{"tcp", "udp", "icmp"},
				Verdict:      []string{"accept", "drop", "continue"},
			},
			md: model.TraceScopeModel{
				TrId:       []uint32{123, 987, 234},
				Table:      []string{"flt", "fwd", "output"},
				Chain:      []string{"chain1", "chain2"},
				JumpTarget: []string{"target1", "target2"},
				RuleHandle: []uint64{1, 2, 3, 4, 5},
				Family:     []string{"ip", "ip6"},
				Iifname:    []string{"eth0", "eth1"},
				Oifname:    []string{"eth0", "eth1"},
				SMacAddr:   []string{"00:00:00:00:00:00", "00:00:00:00:00:01"},
				DMacAddr:   []string{"00:00:00:00:00:00", "00:00:00:00:00:01"},
				SAddr:      []string{"192.168.0.1", "192.168.0.2"},
				DAddr:      []string{"192.168.0.1", "192.168.0.2"},
				SPort:      []uint32{80, 443},
				DPort:      []uint32{80, 443},
				SSgName:    []string{"sg1", "sg2"},
				DSgName:    []string{"sg1", "sg2"},
				SSgNet:     []string{"192.168.0.0/32", "192.168.50.0/32"},
				DSgNet:     []string{"192.168.0.0/32", "192.168.50.0/32"},
				Length:     []uint32{20, 80},
				IpProto:    []string{"tcp", "udp", "icmp"},
				Verdict:    []string{"accept", "drop", "continue"},
				FollowMode: false,
				Query:      "",
				Time: &model.TimeRange{
					From: from,
					To:   to,
				},
			},
		},
		{
			name: "with query",
			fl: Flags{
				ConfigPath:   "path",
				JsonFormat:   true,
				ServerUrl:    "tcp://127.0.0.1:9000",
				LogLevel:     "INFO",
				VerboseMode:  true,
				TimeDuration: &dur,
				FollowMode:   true,
				Query:        "(sport>=80 and sport<=443) and ip-dst=='93.184.215.14' and dport in (80,443)",
			},
			md: model.TraceScopeModel{
				FollowMode: true,
				Query:      "sport >= 80 AND sport <= 443 AND ip_d = '93.184.215.14' AND dport IN (80,443)",
			},
		},
	}
	for _, tc := range testCases {
		sui.Run(tc.name, func() {
			md, err := tc.fl.ToTraceScopeModel()
			sui.Require().NoError(err)
			sui.Require().Equal(tc.md.FollowMode, md.FollowMode)
			sui.Require().Equal(tc.md.Query, md.Query)
		})
	}

}

func (sui *flagsTestSuite) Test_Attach() {
	expectedParams := []FlagParams{
		{Name: "config", Key: "c", Usage: "app config file"},
		{Name: "json", Key: "j", Usage: "enable extended output in the json format"},
		{Name: "host", Key: "H", Usage: "trace-hub service address (format: <IP>:<port>)", Example: "tcp://127.0.0.1:9000"},
		{Name: "log-level", DefValue: "INFO", Usage: "log level: INFO|DEBUG|WARN|ERROR|PANIC|FATAL"},
		{Name: "verbose", Key: "v", Usage: "verbose output mode"},
		{Name: "time-from", Usage: "specifies the start time of the time interval in the format '2024-10-08T12:30:00Z'"},
		{Name: "time-to", Usage: "specifies the end time of the time interval in the format '2024-10-08T12:30:00Z'"},
		{Name: "time", Key: "t", Usage: "time offset from current time (e.g., 1s for 1 second, 1m for 1 minute, 1h for 1 hour, 1d for 1 day)", Example: "1s"},
		{Name: "follow", Key: "f", Usage: "follow or tail continuous output [Required --time Flag]"},
		{Name: "query", Key: "q", Usage: "complex query filter like: (sport>=80 and sport<=443) and ip-dst=='93.184.215.14' and dport not in (80,443)", Example: "(sport>=80 and sport<=443) and ip-dst=='93.184.215.14' and dport in (80,443)"},
		{Name: "trid", Group: "trace", Usage: "set filter by trace id. Supported multiple values separated by symbol ',' and meaning logical OR operation (e.g. --trid 123,987,234)", Example: "123,987,234"},
		{Name: "table", Group: "trace", Usage: "set filter by table name. Supported multiple values separated by symbol ',' and meaning logical OR operation (e.g. --table flt,fwd,output)", Example: "flt,fwd,output"},
		{Name: "chain", Group: "trace", Usage: "set filter by chain name. Supported multiple values (see --table Flag)", Example: "chain1,chain2"},
		{Name: "jt", Group: "trace", Usage: "set filter by jump target name. Supported multiple values (see --table Flag)", Example: "target1,target2"},
		{Name: "handle", Group: "trace", Usage: "set filter by rule handle. Supported multiple values (see --trid Flag)", Example: "1,2,3,4,5"},
		{Name: "family", Group: "trace", Usage: "set filter by protocols family (ip/ip6). Supported multiple values (see --table Flag)", Example: "ip,ip6"},
		{Name: "iif", Group: "trace", Usage: "set filter by network interface name for ingress traffic. Supported multiple values (see --table Flag)", Example: "eth0,eth1"},
		{Name: "oif", Group: "trace", Usage: "set filter by network interface name for egress traffic. Supported multiple values (see --table Flag)", Example: "eth0,eth1"},
		{Name: "hw-src", Group: "trace", Usage: "set filter by source mac address. Supported multiple values (see --table Flag)", Example: "00:00:00:00:00:00,00:00:00:00:00:01"},
		{Name: "hw-dst", Group: "trace", Usage: "set filter by destination mac address. Supported multiple values (see --table Flag)", Example: "00:00:00:00:00:00,00:00:00:00:00:01"},
		{Name: "ip-src", Group: "trace", Usage: "set filter by source ip address. Supported multiple values (see --table Flag)", Example: "192.168.0.1,192.168.0.2"},
		{Name: "ip-dst", Group: "trace", Usage: "set filter by destination ip address. Supported multiple values (see --table Flag)", Example: "192.168.0.1,192.168.0.2"},
		{Name: "sport", Group: "trace", Usage: "set filter by source port. Supported multiple values (see --trid Flag)", Example: "80,443"},
		{Name: "dport", Group: "trace", Usage: "set filter by destination port. Supported multiple values (see --trid Flag)", Example: "80,443"},
		{Name: "sg-src", Group: "trace", Usage: "set filter by source security group name. Supported multiple values (see --table Flag)", Example: "sg1,sg2"},
		{Name: "sg-dst", Group: "trace", Usage: "set filter by destination security group name. Supported multiple values (see --table Flag)", Example: "sg1,sg2"},
		{Name: "net-src", Group: "trace", Usage: "set filter by source network name. Supported multiple values (see --table Flag)", Example: "192.168.0.0/32,192.168.50.0/32"},
		{Name: "net-dst", Group: "trace", Usage: "set filter by destination network name. Supported multiple values (see --table Flag)", Example: "192.168.0.0/32,192.168.50.0/32"},
		{Name: "len", Group: "trace", Usage: "set filter by network packet length. Supported multiple values (see --trid Flag)", Example: "20,80"},
		{Name: "proto", Group: "trace", Usage: "set filter by ip protocol (tcp/udp/icmp/...). Supported multiple values (see --table Flag)", Example: "tcp,udp,icmp"},
		{Name: "verdict", Group: "trace", Usage: "set filter by rule verdict (accept/drop/continue). Supported multiple values (see --table Flag)", Example: "accept,drop,continue"},
	}
	rootCmd := &cobra.Command{}
	persistentFlagMap := map[string]*pflag.FlagSet{
		"log-level": rootCmd.PersistentFlags(),
		"verbose":   rootCmd.PersistentFlags(),
	}
	fl := Flags{}

	err := fl.Attach(rootCmd,
		WithDefValues{Defvalues: map[string]any{fl.NameFromTag(&fl.LogLevel): "INFO"}},
		WithPersistentFlags{Pflags: map[string]*pflag.FlagSet{
			fl.NameFromTag(&fl.LogLevel):    rootCmd.PersistentFlags(),
			fl.NameFromTag(&fl.VerboseMode): rootCmd.PersistentFlags(),
		}})
	sui.Require().NoError(err)
	for _, p := range expectedParams {
		sui.Run(p.Name, func() {
			pf := persistentFlagMap[p.Name]
			if pf == nil {
				pf = rootCmd.Flags()
			}
			fl := pf.Lookup(p.Name)
			sui.Require().NotNil(fl)
			sui.Require().Equal(p.Name, fl.Name)
			sui.Require().Equal(p.Key, fl.Shorthand)
			sui.Require().Equal(p.Usage, fl.Usage)
		})
	}
}

func (sui *flagsTestSuite) Test_Action() {
	timeFrom, _ := time.Parse("2006-01-02T15:04:05Z", "2024-10-08T12:30:00Z")
	timeTo, _ := time.Parse("2006-01-02T15:04:05Z", "2024-10-08T12:35:00Z")
	dur := time.Second
	testCases := []struct {
		name     string
		args     string
		expFlags Flags
	}{
		{
			name: "no query",
			args: "--host tcp://10.10.0.150:9650 --log-level WARN --config test-data/config-test.yml -j --trid 123,234 --table tb1,tb2 --chain ch1,ch2 --jt tg1,tg2 --handle 1,2,3 --iif eth0,eth1 --oif eth1,eth2 --sport 80,443 --dport 80,443 --ip-src 192.168.0.50 --ip-dst 93.184.215.14 --proto tcp,udp,icmp --family ip,ip6 --sg-src HBF-TEST1 --sg-dst HBF-TEST2 --net-src NET1 --net-dst NET2 --len 20,80 --verdict accept,drop,continue --agent-id tracer1,tracer2 --time-from 2024-10-08T12:30:00Z --time-to 2024-10-08T12:35:00Z",
			expFlags: Flags{
				ConfigPath:  "test-data/config-test.yml",
				JsonFormat:  true,
				ServerUrl:   "tcp://10.10.0.150:9650",
				LogLevel:    "WARN",
				VerboseMode: false,
				TimeFrom:    &timeFrom,
				TimeTo:      &timeTo,
				TrId:        []uint{123, 234},
				Table:       []string{"tb1", "tb2"},
				Chain:       []string{"ch1", "ch2"},
				JumpTarget:  []string{"tg1", "tg2"},
				RuleHandle:  []uint{1, 2, 3},
				Family:      []string{"ip", "ip6"},
				Iifname:     []string{"eth0", "eth1"},
				Oifname:     []string{"eth1", "eth2"},
				SAddr:       []string{"192.168.0.50"},
				DAddr:       []string{"93.184.215.14"},
				SPort:       []uint{80, 443},
				DPort:       []uint{80, 443},
				SSgName:     []string{"HBF-TEST1"},
				DSgName:     []string{"HBF-TEST2"},
				SSgNet:      []string{"NET1"},
				DSgNet:      []string{"NET2"},
				Length:      []uint{20, 80},
				IpProto:     []string{"tcp", "udp", "icmp"},
				Verdict:     []string{"accept", "drop", "continue"},
				AgentsIds:   []string{"tracer1", "tracer2"},
			},
		},
		{
			name: "with query",
			args: `--host tcp://10.10.0.150:9650 -v -f -t 1s --log-level WARN --config test-data/config-test.yml -j -q "(trid > 123 or trid < 234) and trid != 200 and sport in (80,443) and dport not in (80,443) and sg-src != 'no-routed'" --agent-id tracer1,tracer2`,
			expFlags: Flags{
				ConfigPath:   "test-data/config-test.yml",
				JsonFormat:   true,
				ServerUrl:    "tcp://10.10.0.150:9650",
				LogLevel:     "DEBUG",
				VerboseMode:  true,
				FollowMode:   true,
				TimeDuration: &dur,
				AgentsIds:    []string{"tracer1", "tracer2"},
				Query:        "(trid > 123 or trid < 234) and trid != 200 and sport in (80,443) and dport not in (80,443) and sg-src != 'no-routed'",
			},
		},
	}
	for _, tc := range testCases {
		sui.Run(tc.name, func() {
			rootCmd := &cobra.Command{
				RunE: func(cmd *cobra.Command, args []string) (err error) {
					fl := Flags{}
					err = fl.Action(cmd)
					sui.Require().NoError(err)
					sui.Require().Equal(tc.expFlags, fl)
					return
				},
			}
			fl := Flags{}
			err := fl.Attach(rootCmd,
				WithDefValues{Defvalues: map[string]any{fl.NameFromTag(&fl.LogLevel): "INFO"}},
				WithPersistentFlags{Pflags: map[string]*pflag.FlagSet{
					fl.NameFromTag(&fl.LogLevel):    rootCmd.PersistentFlags(),
					fl.NameFromTag(&fl.VerboseMode): rootCmd.PersistentFlags(),
				}})
			sui.Require().NoError(err)
			splitArgs, err := shlex.Split(tc.args)
			sui.Require().NoError(err)
			rootCmd.SetArgs(splitArgs)
			err = rootCmd.Execute()
			sui.Require().NoError(err)
		})
	}
}

func (sui *flagsTestSuite) Test_ExcludeFlags() {
	testCases := []struct {
		name    string
		args    string
		isError bool
	}{
		{
			name: "valid args",
			args: "--host tcp://10.10.0.150:9650",
		},
		{
			name:    "invalid args",
			args:    "--host tcp://10.10.0.150:9650 -f",
			isError: true,
		},
	}

	for _, tc := range testCases {
		sui.Run(tc.name, func() {
			rootCmd := &cobra.Command{
				RunE: func(cmd *cobra.Command, args []string) (err error) {
					fl := Flags{}
					err = fl.Action(cmd)
					sui.Require().NoError(err)
					return
				},
			}
			fl := Flags{}
			err := fl.Attach(rootCmd,
				WithExcludeFlags{ExcludeFlags: []string{fl.NameFromTag(&fl.FollowMode)}},
				WithDefValues{Defvalues: map[string]any{fl.NameFromTag(&fl.LogLevel): "INFO"}},
				WithPersistentFlags{Pflags: map[string]*pflag.FlagSet{
					fl.NameFromTag(&fl.LogLevel):    rootCmd.PersistentFlags(),
					fl.NameFromTag(&fl.VerboseMode): rootCmd.PersistentFlags(),
				}})
			sui.Require().NoError(err)
			splitArgs, err := shlex.Split(tc.args)
			sui.Require().NoError(err)
			rootCmd.SetArgs(splitArgs)
			err = rootCmd.Execute()
			if tc.isError {
				sui.Require().Error(err)
			} else {
				sui.Require().NoError(err)
			}
		})
	}
}
