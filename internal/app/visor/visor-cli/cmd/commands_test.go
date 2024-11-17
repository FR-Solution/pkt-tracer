package cmd

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wildberries-tech/pkt-tracer/internal/app"
	. "github.com/wildberries-tech/pkt-tracer/internal/app/visor" //nolint:revive
	vf "github.com/wildberries-tech/pkt-tracer/internal/app/visor/flags"
	model "github.com/wildberries-tech/pkt-tracer/internal/models/trace"

	"github.com/google/shlex"
	"github.com/stretchr/testify/suite"
)

type cmdTestSuite struct {
	suite.Suite
}

func Test_Cmd(t *testing.T) {
	suite.Run(t, new(cmdTestSuite))
}

func (sui *cmdTestSuite) Test_RootCommands() {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	defer func() {
		os.Stdout = old
	}()
	cmd := newRootCmd()
	sui.Run("Valid Comands", func() {
		cmd.SetArgs([]string{"--version"})
		err := cmd.Execute()
		sui.Require().NoError(err)
		w.Close()
		out, _ := io.ReadAll(r)
		sui.Require().True(strings.Contains(string(out), "visor-cli version "))
		r, w, _ = os.Pipe()
		os.Stdout = w
		cmd.SetArgs([]string{"--help"})
		err = cmd.Execute()
		sui.Require().NoError(err)
		w.Close()
		out, _ = io.ReadAll(r)
		sui.Require().NotEmpty(out)
	})

}

func (sui *cmdTestSuite) Test_SingleWatcherValidFlags() {
	timeFrom, _ := time.Parse("2006-01-02T15:04:05Z", "2024-10-08T12:30:00Z")
	timeTo, _ := time.Parse("2006-01-02T15:04:05Z", "2024-10-08T12:35:00Z")

	testCase := []struct {
		name           string
		args           string
		expFollowFlag  bool
		expConfigFile  string
		expFilterFlags model.TraceScopeModel
	}{
		{
			name:          "sub01",
			args:          "--config test-data/config-test.yml",
			expConfigFile: "test-data/config-test.yml",
		},
		{
			name: "sub02",
			args: "--host 10.10.0.150:9650",
		},
		{
			name: "sub03",
			args: "--host 10.10.0.150:9650 --iif eth0",
			expFilterFlags: model.TraceScopeModel{
				Iifname: []string{"eth0"},
			},
		},
		{
			name: "sub04",
			args: "--host 10.10.0.150:9650 --iif eth0 --oif eth1",
			expFilterFlags: model.TraceScopeModel{
				Iifname: []string{"eth0"},
				Oifname: []string{"eth1"},
			},
		},
		{
			name: "sub05",
			args: "--host 10.10.0.150:9650 --iif eth0 --oif eth1 --sport 80 --dport 443",
			expFilterFlags: model.TraceScopeModel{
				Iifname: []string{"eth0"},
				Oifname: []string{"eth1"},
				SPort:   []uint32{80},
				DPort:   []uint32{443},
			},
		},
		{
			name: "sub06",
			args: "--host 10.10.0.150:9650 --iif eth0 --oif eth1 --sport 80 --dport 443 --ip-src 192.168.0.50 --ip-dst 93.184.215.14",
			expFilterFlags: model.TraceScopeModel{
				Iifname: []string{"eth0"},
				Oifname: []string{"eth1"},
				SPort:   []uint32{80},
				DPort:   []uint32{443},
				SAddr:   []string{"192.168.0.50"},
				DAddr:   []string{"93.184.215.14"},
			},
		},
		{
			name: "sub07",
			args: "--host 10.10.0.150:9650 --iif eth0 --oif eth1 --sport 80 --dport 443 --ip-src 192.168.0.50 --ip-dst 93.184.215.14 --proto tcp --family ip",
			expFilterFlags: model.TraceScopeModel{
				Iifname: []string{"eth0"},
				Oifname: []string{"eth1"},
				SPort:   []uint32{80},
				DPort:   []uint32{443},
				SAddr:   []string{"192.168.0.50"},
				DAddr:   []string{"93.184.215.14"},
				IpProto: []string{"tcp"},
				Family:  []string{"ip"},
			},
		},
		{
			name: "sub08",
			args: "--host 10.10.0.150:9650 --iif eth0 --oif eth1 --sport 80 --dport 443 --ip-src 192.168.0.50 --ip-dst 93.184.215.14 --proto tcp --family ip --sg-src HBF-TEST1 --sg-dst HBF-TEST2",
			expFilterFlags: model.TraceScopeModel{
				Iifname: []string{"eth0"},
				Oifname: []string{"eth1"},
				SPort:   []uint32{80},
				DPort:   []uint32{443},
				SAddr:   []string{"192.168.0.50"},
				DAddr:   []string{"93.184.215.14"},
				IpProto: []string{"tcp"},
				Family:  []string{"ip"},
				SSgName: []string{"HBF-TEST1"},
				DSgName: []string{"HBF-TEST2"},
			},
		},
		{
			name: "sub09",
			args: "--host 10.10.0.150:9650 --iif eth0 --oif eth1 --sport 80 --dport 443 --ip-src 192.168.0.50 --ip-dst 93.184.215.14 --proto tcp --family ip --sg-src HBF-TEST1 --sg-dst HBF-TEST2 --net-src NET1 --net-dst NET2",
			expFilterFlags: model.TraceScopeModel{
				Iifname: []string{"eth0"},
				Oifname: []string{"eth1"},
				SPort:   []uint32{80},
				DPort:   []uint32{443},
				SAddr:   []string{"192.168.0.50"},
				DAddr:   []string{"93.184.215.14"},
				IpProto: []string{"tcp"},
				Family:  []string{"ip"},
				SSgName: []string{"HBF-TEST1"},
				DSgName: []string{"HBF-TEST2"},
				SSgNet:  []string{"NET1"},
				DSgNet:  []string{"NET2"},
			},
		},
		{
			name: "sub10",
			args: "--host 10.10.0.150:9650 --iif eth0 --oif eth1 --sport 80 --dport 443 --ip-src 192.168.0.50 --ip-dst 93.184.215.14 --proto tcp --family ip --sg-src HBF-TEST1 --sg-dst HBF-TEST2 --net-src NET1 --net-dst NET2 --time-from 2024-10-08T12:30:00Z --time-to 2024-10-08T12:35:00Z",
			expFilterFlags: model.TraceScopeModel{
				Iifname: []string{"eth0"},
				Oifname: []string{"eth1"},
				SPort:   []uint32{80},
				DPort:   []uint32{443},
				SAddr:   []string{"192.168.0.50"},
				DAddr:   []string{"93.184.215.14"},
				IpProto: []string{"tcp"},
				Family:  []string{"ip"},
				SSgName: []string{"HBF-TEST1"},
				DSgName: []string{"HBF-TEST2"},
				SSgNet:  []string{"NET1"},
				DSgNet:  []string{"NET2"},
				Time: &model.TimeRange{
					From: timeFrom,
					To:   timeTo,
				},
			},
		},
	}

	for _, test := range testCase {
		sui.Run(test.name, func() {
			test := test
			cmd := newWatcherCommand()
			ctx, cancel := context.WithCancel(app.Context())
			app.SetContext(ctx)

			cmd.SetArgs(strings.Split(test.args, " "))
			cancel()
			_ = cmd.Execute()

			fl := vf.Flags{}
			err := fl.InitFromCmd(cmd)
			sui.Require().NoError(err)
			cfg, err := cmd.Flags().GetString(fl.NameFromTag(&fl.ConfigPath))
			sui.Require().NoError(err)
			sui.Require().Equal(test.expConfigFile, cfg)
			sui.Require().Equal(test.expConfigFile, fl.ConfigPath)
			md, err := fl.ToTraceScopeModel()
			sui.Require().NoError(err)
			sui.Require().EqualValues(test.expFilterFlags, md)
			cmd.ResetFlags()
		})
	}
	cmd := newWatcherCommand()
	ctx, cancel := context.WithCancel(app.Context())
	app.SetContext(ctx)
	args := "--host 10.10.0.150:9650 -f -t 5s --iif eth0 --oif eth1 --sport 80 --dport 443 --ip-src 192.168.0.50 --ip-dst 93.184.215.14 --proto tcp --family ip --sg-src HBF-TEST1 --sg-dst HBF-TEST2 --net-src NET1 --net-dst NET2"
	cmd.SetArgs(strings.Split(args, " "))
	cancel()
	_ = cmd.Execute()

	fl := vf.Flags{}
	err := fl.InitFromCmd(cmd)
	sui.Require().NoError(err)
	md, err := fl.ToTraceScopeModel()
	sui.Require().NoError(err)

	sui.Require().True(md.FollowMode)
	sui.Require().NotNil(md.Time)
	sui.Require().Equal(5*time.Second, md.Time.To.Sub(md.Time.From))
}

func (sui *cmdTestSuite) Test_QueryFlags() {
	args := `--host 10.10.0.150:9650 -q "(trid > 123 or trid < 234) and trid != 200 and sport in (80,443) and dport not in (80,443) and sg-src != 'no-routed'"`
	expectedQuery := "(trace_id > 123 OR trace_id < 234) AND trace_id != 200 AND sport IN (80,443) AND dport NOT IN (80,443) AND sgname_s != 'no-routed'"
	splitArgs, err := shlex.Split(args)
	sui.Require().NoError(err)

	cmd := newWatcherCommand()
	ctx, cancel := context.WithCancel(app.Context())
	app.SetContext(ctx)

	cmd.SetArgs(splitArgs)
	cancel()
	_ = cmd.Execute()

	fl := vf.Flags{}
	err = fl.InitFromCmd(cmd)
	sui.Require().NoError(err)
	md, err := fl.ToTraceScopeModel()
	sui.Require().NoError(err)

	sui.Require().Equal(expectedQuery, md.Query)
}

func (sui *cmdTestSuite) Test_MultipleValidFlags() {
	testCase := []struct {
		name           string
		args           string
		expFollowFlag  bool
		expConfigFile  string
		expFilterFlags model.TraceScopeModel
	}{

		{
			name: "sub01",
			args: "--host 10.10.0.150:9650 --iif eth0,eth1,eth2",
			expFilterFlags: model.TraceScopeModel{
				Iifname: []string{"eth0", "eth1", "eth2"},
			},
		},
		{
			name: "sub02",
			args: "--host 10.10.0.150:9650 --iif eth0,eth1,eth2 --oif eth3,eth4,eth5",
			expFilterFlags: model.TraceScopeModel{
				Iifname: []string{"eth0", "eth1", "eth2"},
				Oifname: []string{"eth3", "eth4", "eth5"},
			},
		},
		{
			name: "sub03",
			args: "--host 10.10.0.150:9650 --iif eth0,eth1,eth2 --oif eth3,eth4,eth5 --sport 80,81,82 --dport 443,444,445",
			expFilterFlags: model.TraceScopeModel{
				Iifname: []string{"eth0", "eth1", "eth2"},
				Oifname: []string{"eth3", "eth4", "eth5"},
				SPort:   []uint32{80, 81, 82},
				DPort:   []uint32{443, 444, 445},
			},
		},
		{
			name: "sub04",
			args: "--host 10.10.0.150:9650 --iif eth0,eth1,eth2 --oif eth3,eth4,eth5 --sport 80,81,82 --dport 443,444,445 --ip-src 192.168.0.50,192.168.0.51 --ip-dst 93.184.215.14,93.184.215.15",
			expFilterFlags: model.TraceScopeModel{
				Iifname: []string{"eth0", "eth1", "eth2"},
				Oifname: []string{"eth3", "eth4", "eth5"},
				SPort:   []uint32{80, 81, 82},
				DPort:   []uint32{443, 444, 445},
				SAddr:   []string{"192.168.0.50", "192.168.0.51"},
				DAddr:   []string{"93.184.215.14", "93.184.215.15"},
			},
		},
		{
			name: "sub05",
			args: "--host 10.10.0.150:9650 --iif eth0,eth1,eth2 --oif eth3,eth4,eth5 --sport 80,81,82 --dport 443,444,445 --ip-src 192.168.0.50,192.168.0.51 --ip-dst 93.184.215.14,93.184.215.15 --proto tcp,udp --family ip,ip6",
			expFilterFlags: model.TraceScopeModel{
				Iifname: []string{"eth0", "eth1", "eth2"},
				Oifname: []string{"eth3", "eth4", "eth5"},
				SPort:   []uint32{80, 81, 82},
				DPort:   []uint32{443, 444, 445},
				SAddr:   []string{"192.168.0.50", "192.168.0.51"},
				DAddr:   []string{"93.184.215.14", "93.184.215.15"},
				IpProto: []string{"tcp", "udp"},
				Family:  []string{"ip", "ip6"},
			},
		},
		{
			name: "sub06",
			args: "--host 10.10.0.150:9650 --iif eth0,eth1,eth2 --oif eth3,eth4,eth5 --sport 80,81,82 --dport 443,444,445 --ip-src 192.168.0.50,192.168.0.51 --ip-dst 93.184.215.14,93.184.215.15 --proto tcp,udp --family ip,ip6 --sg-src sg1,sg2,sg3 --sg-dst sg4,sg5,sg6",
			expFilterFlags: model.TraceScopeModel{
				Iifname: []string{"eth0", "eth1", "eth2"},
				Oifname: []string{"eth3", "eth4", "eth5"},
				SPort:   []uint32{80, 81, 82},
				DPort:   []uint32{443, 444, 445},
				SAddr:   []string{"192.168.0.50", "192.168.0.51"},
				DAddr:   []string{"93.184.215.14", "93.184.215.15"},
				IpProto: []string{"tcp", "udp"},
				Family:  []string{"ip", "ip6"},
				SSgName: []string{"sg1", "sg2", "sg3"},
				DSgName: []string{"sg4", "sg5", "sg6"},
			},
		},
		{
			name: "sub07",
			args: "--host 10.10.0.150:9650 --iif eth0,eth1,eth2 --oif eth3,eth4,eth5 --sport 80,81,82 --dport 443,444,445 --ip-src 192.168.0.50,192.168.0.51 --ip-dst 93.184.215.14,93.184.215.15 --proto tcp,udp --family ip,ip6 --sg-src sg1,sg2,sg3 --sg-dst sg4,sg5,sg6 --net-src net1,net2 --net-dst net3,net4",
			expFilterFlags: model.TraceScopeModel{
				Iifname: []string{"eth0", "eth1", "eth2"},
				Oifname: []string{"eth3", "eth4", "eth5"},
				SPort:   []uint32{80, 81, 82},
				DPort:   []uint32{443, 444, 445},
				SAddr:   []string{"192.168.0.50", "192.168.0.51"},
				DAddr:   []string{"93.184.215.14", "93.184.215.15"},
				IpProto: []string{"tcp", "udp"},
				Family:  []string{"ip", "ip6"},
				SSgName: []string{"sg1", "sg2", "sg3"},
				DSgName: []string{"sg4", "sg5", "sg6"},
				SSgNet:  []string{"net1", "net2"},
				DSgNet:  []string{"net3", "net4"},
			},
		},
	}

	for _, test := range testCase {
		sui.Run(test.name, func() {
			test := test
			cmd := newWatcherCommand()
			ctx, cancel := context.WithCancel(app.Context())
			app.SetContext(ctx)
			cmd.SetArgs(strings.Split(test.args, " "))
			cancel()
			err := cmd.Execute()
			sui.Require().NoError(err)
			fl := vf.Flags{}
			err = fl.InitFromCmd(cmd)
			sui.Require().NoError(err)
			cfg, err := cmd.Flags().GetString(fl.NameFromTag(&fl.ConfigPath))
			sui.Require().NoError(err)
			sui.Require().Equal(test.expConfigFile, cfg)
			sui.Require().Equal(test.expConfigFile, fl.ConfigPath)
			sui.Require().Equal(test.expFollowFlag, fl.FollowMode)
			md, err := fl.ToTraceScopeModel()
			sui.Require().NoError(err)
			sui.Require().EqualValues(test.expFilterFlags, md)
			cmd.ResetFlags()
			cancel()
		})
	}
}

func (sui *cmdTestSuite) Test_InvalidFlags() {
	const name = "invalid"
	testCase := []struct {
		name           string
		args           string
		expFollowFlag  bool
		expConfigFile  string
		expFilterFlags model.TraceScopeModel
	}{
		{
			name: name,
			args: "--host 10.10.0.150:9650 --time-from 2024-10-08T12:30:00Z",
		},
		{
			name: name,
			args: "--host 10.10.0.150:9650 --time-to 2024-10-08T12:30:00Z",
		},
		{
			name: name,
			args: "--host 10.10.0.150:9650 -f",
		},
		{
			name: name,
			args: "--host 10.10.0.150:9650 -t 5s",
		},
		{
			name: name,
			args: "",
		},
		{
			name: name,
			args: "--host 10.10.0.150:9650 --dport invalid",
		},
		{
			name: name,
			args: "--host 10.10.0.150:9650 --oif 'eth1,select * from'",
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --trid 123 -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --table 'tb1' -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --chain 'ch1' -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --jt 'jt1' -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --handle 1 -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --family 'ip' -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --iif 'eth1' -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --oif 'eth1' -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --hw-src '00:00:00:00:00:00' -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --hw-dst '00:00:00:00:00:00' -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --ip-src '192.168.0.1' -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --ip-dst '192.168.0.1' -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --sport 80 -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --dport 80 -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --sg-src 'sg1' -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --sg-dst 'sg1' -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --net-src 'net1' -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --net-src 'net2' -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --net-dst 'net2' -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --len 20 -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --proto 'udp' -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --verdict 'accept' -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
		{
			name: name,
			args: `--host 10.10.0.150:9650 --sport 80 --dport 80 --sg-src 'sg1' --sg-dst 'sg1' --net-src 'net2' --net-dst 'net2' --len 20 --proto 'udp' --verdict 'accept' -q "(trid > 123 or trid < 234) and trid != 200 and (dport == 80 or dport == 443)"`,
		},
	}

	for _, test := range testCase {
		sui.Run(test.name, func() {
			test := test
			cmd := newWatcherCommand()
			ctx, cancel := context.WithCancel(app.Context())
			app.SetContext(ctx)
			splitArgs, err := shlex.Split(test.args)
			sui.Require().NoError(err)
			cmd.SetArgs(splitArgs)
			cancel()
			err = cmd.Execute()
			sui.Require().Error(err)
			cmd.ResetFlags()
		})
	}
}

func (sui *cmdTestSuite) Test_ConfigFromCLIAndFile() {
	var err error

	args := "--host tcp://10.10.0.150:9650 --config test-data/config-test.yml"
	cmd := newWatcherCommand()
	ctx, cancel := context.WithCancel(app.Context())
	app.SetContext(ctx)
	cmd.SetArgs(strings.Split(args, " "))
	cancel()
	err = cmd.Execute()
	sui.Require().NoError(err)
	fl := vf.Flags{}
	err = fl.InitFromCmd(cmd)
	sui.Require().NoError(err)
	cfg, err := cmd.Flags().GetString(fl.NameFromTag(&fl.ConfigPath))
	sui.Require().NoError(err)
	sui.Require().Equal("test-data/config-test.yml", cfg)
	sui.Require().Equal("test-data/config-test.yml", fl.ConfigPath)

	addr, err := TrAddress.Value(ctx)
	sui.Require().NoError(err)
	sui.Require().Equal("tcp://10.10.0.150:9650", addr)

	level, err := AppLoggerLevel.Value(ctx)
	sui.Require().NoError(err)
	sui.Require().Equal("DEBUG", level)
}

func (sui *cmdTestSuite) Test_ConfigFromCLIAndDefault() {
	var err error

	args := "--host tcp://10.10.0.150:9650"
	cmd := newWatcherCommand()
	ctx, cancel := context.WithCancel(app.Context())
	app.SetContext(ctx)
	cmd.SetArgs(strings.Split(args, " "))
	cancel()
	_ = cmd.Execute()

	addr, err := TrAddress.Value(ctx)
	sui.Require().NoError(err)
	sui.Require().Equal("tcp://10.10.0.150:9650", addr)

	level, err := AppLoggerLevel.Value(ctx)
	sui.Require().NoError(err)
	sui.Require().Equal("INFO", level)
}

func (sui *cmdTestSuite) Test_ConfigFromFile() {
	var err error

	args := "--config test-data/config-test.yml"
	cmd := newWatcherCommand()
	ctx, cancel := context.WithCancel(app.Context())
	app.SetContext(ctx)
	cmd.SetArgs(strings.Split(args, " "))
	cancel()
	err = cmd.Execute()
	sui.Require().NoError(err)

	addr, err := TrAddress.Value(ctx)
	sui.Require().NoError(err)
	sui.Require().Equal("tcp://127.0.0.2:9010", addr)

	level, err := AppLoggerLevel.Value(ctx)
	sui.Require().NoError(err)
	sui.Require().Equal("DEBUG", level)
}

func (sui *cmdTestSuite) Test_Verbose() {
	var err error

	args := "--config test-data/config-test.yml --verbose"
	cmd := newWatcherCommand()
	ctx, cancel := context.WithCancel(app.Context())
	app.SetContext(ctx)
	cmd.SetArgs(strings.Split(args, " "))
	cancel()
	err = cmd.Execute()
	sui.Require().NoError(err)

	addr, err := TrAddress.Value(ctx)
	sui.Require().NoError(err)
	sui.Require().Equal("tcp://127.0.0.2:9010", addr)

	level, err := AppLoggerLevel.Value(ctx)
	sui.Require().NoError(err)
	sui.Require().Equal("DEBUG", level)
}
