package cmd

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/wildberries-tech/pkt-tracer/internal/app"
	. "github.com/wildberries-tech/pkt-tracer/internal/app/visor" //nolint:revive
	vf "github.com/wildberries-tech/pkt-tracer/internal/app/visor/flags"
	"github.com/wildberries-tech/pkt-tracer/internal/app/visor/visor-ui/view"
	"github.com/wildberries-tech/pkt-tracer/internal/config"
	model "github.com/wildberries-tech/pkt-tracer/internal/models/trace"
	np "github.com/wildberries-tech/pkt-tracer/internal/providers/nft-provider"

	app_identity "github.com/H-BF/corlib/app/identity"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	appName       = "visor-ui"
	shortAppDesc  = "A graphical CLI for network traffic analyzer."
	longAppDesc   = `visor is a graphical CLI to view and analyze traces of the network traffic coming through nftables rules marked as 'nftrace set 1'.`
	exampleAppUse = "visor-ui -H tcp://10.10.0.150:9650 -j --iif eth0 --oif eth0,eth1 --sport 80,8080,443 --dport 443 --ip-src 192.168.0.50 --ip-dst 93.184.215.14 --proto tcp,udp --family ip --sg-src sg1,sg2 --sg-dst sg3"
)

func newRootCmd() *cobra.Command {
	fl := vf.Flags{}
	c := &cobra.Command{
		Version: fmt.Sprintf("v%s", app_identity.Version),
		Use:     appName,
		Short:   shortAppDesc,
		Long:    longAppDesc,
		Example: exampleAppUse,
		RunE:    run,
	}

	err := fl.Attach(c,
		vf.WithExcludeFlags{ExcludeFlags: []string{fl.NameFromTag(&fl.FollowMode), fl.NameFromTag(&fl.TimeFrom), fl.NameFromTag(&fl.TimeTo)}},
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

	c.MarkFlagsOneRequired(fl.NameFromTag(&fl.ConfigPath), fl.NameFromTag(&fl.ServerUrl))
	SetupContext()
	return c
}

// Execute root command.
func Execute() {
	_ = newRootCmd().Execute()
}

func run(cmd *cobra.Command, args []string) (err error) {
	const (
		timeDuration = 1 * time.Second
		syncInterval = 3 * time.Second
	)
	fl := vf.Flags{}
	err = fl.Action(cmd)
	if err != nil {
		return err
	}
	if fl.TimeDuration == nil {
		dur := time.Second
		fl.TimeDuration = &dur
	}
	fl.FollowMode = true

	ctx := app.Context()
	err = config.InitGlobalConfig(
		config.WithAcceptEnvironment{EnvPrefix: "VU"},
		config.WithSourceFile{FileName: fl.ConfigPath},

		config.WithCmdFlag{Key: AppLoggerLevel, Flag: cmd.Flag(fl.NameFromTag(&fl.LogLevel))},
		config.WithDefValue{Key: AppLoggerLevel, Val: "INFO"},

		config.WithCmdFlag{Key: TrAddress, Flag: cmd.Flag(fl.NameFromTag(&fl.ServerUrl))},
		config.WithDefValue{Key: TrAddress, Val: "tcp://127.0.0.1:9000"},

		config.WithDefValue{Key: ServicesDefDialDuration, Val: 30 * time.Second},

		config.WithDefValue{Key: UseCompression, Val: false},
		config.WithDefValue{Key: UserAgent, Val: "visor-ui0"},
	)
	if err != nil {
		return err
	}
	if err = SetupLogger(false); err != nil {
		return err
	}

	thClient, err := NewTHClient(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = thClient.CloseConn() }()

	app := view.SetupViewer(
		ctx,
		view.Deps{
			Visor:       &visorProxy{},
			TblProvider: &tblProviderDecorator{si: syncInterval},
		},
		view.Cfg{
			CmdFlags: fl,
		},
	)

	if err := app.Run(); err != nil {
		select {
		case <-ctx.Done():
		default:
			return err
		}
	}
	return nil
}

type (
	visorDecorator struct {
		Visor
	}
	visorProxy struct {
		visorDecorator
		started atomic.Bool
	}
	tblProviderDecorator struct {
		np.TableProvider
		si time.Duration
	}
)

func (v *visorDecorator) Run(ctx context.Context, flt model.TraceScopeModel) error {
	thClient, err := NewTHClient(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = thClient.CloseConn() }()
	v.Visor = NewVisor(
		Deps{
			Client:       THClient{TraceHubServiceClient: thClient.TraceHubServiceClient},
			TracePrinter: view.NewPrinter(),
		},
	)
	return v.Visor.Run(ctx, flt)
}

func (v *visorDecorator) Close() (err error) {
	if v.Visor != nil {
		err = v.Visor.Close()
	}
	return err
}

func (v *visorProxy) Run(ctx context.Context, flt model.TraceScopeModel) error {
	if !v.started.CompareAndSwap(false, true) {
		return nil
	}
	return v.visorDecorator.Run(ctx, flt)
}

func (v *visorProxy) Close() error {
	v.started.Store(false)
	return v.visorDecorator.Close()
}

func (v *visorProxy) IsStarted() bool {
	return v.started.Load()
}

func (t *tblProviderDecorator) Run(ctx context.Context) error {
	thClient, err := NewTHClient(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = thClient.CloseConn() }()
	t.TableProvider = np.NewTableProvider(
		np.Deps{
			Cli: thClient,
		},
		t.si,
	)
	return t.TableProvider.Run(ctx)
}

func (t *tblProviderDecorator) Close() (err error) {
	if t.TableProvider != nil {
		err = t.TableProvider.Close()
	}
	return err
}
