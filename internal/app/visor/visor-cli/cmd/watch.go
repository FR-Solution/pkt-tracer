package cmd

import (
	"time"

	"github.com/wildberries-tech/pkt-tracer/internal/app"
	. "github.com/wildberries-tech/pkt-tracer/internal/app/visor" //nolint:revive
	vf "github.com/wildberries-tech/pkt-tracer/internal/app/visor/flags"
	vc "github.com/wildberries-tech/pkt-tracer/internal/app/visor/visor-cli"
	"github.com/wildberries-tech/pkt-tracer/internal/config"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func newWatcherCommand() *cobra.Command {
	fl := vf.Flags{}
	c := &cobra.Command{
		Use:     "watch",
		Short:   "Watch network traffic",
		Example: "visor-cli watch -H tcp://10.10.0.150:9650 -f -j --iif eth0 --oif eth0,eth1 --sport 80,8080,443 --dport 443 --ip-src 192.168.0.50 --ip-dst 93.184.215.14 --proto tcp,udp --family ip --sg-src sg1,sg2 --sg-dst sg3",
		RunE:    run,
	}
	err := fl.Attach(c,
		vf.WithDefValues{Defvalues: map[string]any{fl.NameFromTag(&fl.LogLevel): "INFO"}},
		vf.WithPersistentFlags{Pflags: map[string]*pflag.FlagSet{
			fl.NameFromTag(&fl.LogLevel):    c.PersistentFlags(),
			fl.NameFromTag(&fl.VerboseMode): c.PersistentFlags(),
		}},
	)
	if err != nil {
		panic(errors.WithMessage(err, "failed to attach flag"))
	}
	qName := fl.NameFromTag(&fl.Query)
	for _, p := range fl.GetFlagParamsByGroup("trace") {
		c.MarkFlagsMutuallyExclusive(qName, p.Name)
	}

	c.MarkFlagsRequiredTogether(fl.NameFromTag(&fl.TimeFrom), fl.NameFromTag(&fl.TimeTo))
	c.MarkFlagsMutuallyExclusive(fl.NameFromTag(&fl.TimeFrom), fl.NameFromTag(&fl.TimeDuration))
	c.MarkFlagsRequiredTogether(fl.NameFromTag(&fl.TimeDuration), fl.NameFromTag(&fl.FollowMode))
	c.MarkFlagsOneRequired(fl.NameFromTag(&fl.ConfigPath), fl.NameFromTag(&fl.ServerUrl))
	SetupContext()
	return c
}

func run(cmd *cobra.Command, args []string) (err error) {
	fl := vf.Flags{}
	err = fl.Action(cmd)
	if err != nil {
		return err
	}
	ctx := app.Context()
	err = config.InitGlobalConfig(
		config.WithAcceptEnvironment{EnvPrefix: "VC"},
		config.WithSourceFile{FileName: fl.ConfigPath},

		config.WithCmdFlag{Key: AppLoggerLevel, Flag: cmd.Flag(fl.NameFromTag(&fl.LogLevel))},
		config.WithDefValue{Key: AppLoggerLevel, Val: "INFO"},

		config.WithCmdFlag{Key: TrAddress, Flag: cmd.Flag(fl.NameFromTag(&fl.ServerUrl))},
		config.WithDefValue{Key: TrAddress, Val: "tcp://127.0.0.1:9000"},

		config.WithDefValue{Key: ServicesDefDialDuration, Val: 30 * time.Second},

		config.WithDefValue{Key: UseCompression, Val: false},
		config.WithDefValue{Key: UserAgent, Val: "visor-cli0"},
	)
	if err != nil {
		return err
	}

	if err = SetupLogger(fl.JsonFormat); err != nil {
		return err
	}
	md, err := fl.ToTraceScopeModel()
	if err != nil {
		return err
	}
	if err = vc.RunJobs(ctx, md, fl.JsonFormat); err != nil {
		select {
		case <-ctx.Done():
		default:
			return err
		}
	}
	return nil
}
