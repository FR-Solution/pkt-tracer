package view

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	thAPI "github.com/wildberries-tech/pkt-tracer/internal/api/tracehub"
	"github.com/wildberries-tech/pkt-tracer/internal/app/visor"
	vf "github.com/wildberries-tech/pkt-tracer/internal/app/visor/flags"
	ui "github.com/wildberries-tech/pkt-tracer/internal/app/visor/visor-ui/tui"
	model "github.com/wildberries-tech/pkt-tracer/internal/models/trace"

	"github.com/H-BF/corlib/pkg/parallel"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"go.uber.org/multierr"
)

var (
	viewInstanceHolder atomic.Pointer[view]
	setupViewerOnce    sync.Once
)

type (
	THClient = thAPI.Client

	logT = func(format string, a ...any)

	Visor interface {
		Run(context.Context, model.TraceScopeModel) error
		IsStarted() bool
		Close() error
	}
	TableProvider interface {
		Run(context.Context) error
		GetTableById(id uint64) (tbl string, err error)
		Close() error
	}
	//Deps - dependencies
	Deps struct {
		Visor       Visor
		TblProvider TableProvider
	}

	//Cfg - configs
	Cfg struct {
		CmdFlags vf.Flags
	}
	Viewer interface {
		Run() error
	}
	view struct {
		*ui.App
		Deps
		cfg        Cfg
		sub        observer.Subject
		ctxApp     context.Context
		primitives componentCache[ui.Primitive]
		next       ui.NextPrimitive
		log        logT
	}
)

// SetupViewer returns a visor ui app instance.
func SetupViewer(ctx context.Context, d Deps, c Cfg) Viewer {
	setupViewerOnce.Do(func() {
		viewInstanceHolder.Store(newView(ctx, d, c))
	})
	return viewInstanceHolder.Load()
}

func GetViewer() Viewer {
	return viewInstanceHolder.Load()
}

func newView(ctx context.Context, d Deps, c Cfg) *view {
	var a *view
	a = &view{
		App:    ui.NewApp(),
		Deps:   d,
		cfg:    c,
		sub:    visor.VisorSubject(),
		ctxApp: ctx,
		log: func(format string, vals ...any) {
			tracePanel := a.primitives.At(panelTraceName).(*ui.Panel)
			tracePanel.Printf(format+"\n", vals...)
		},
	}
	mainPanels := a.newMainPagePanels()
	helpPanels := a.newHelpPagePanels()
	a.primitives.AddPrimitivesFromMap(componentMap[ui.Primitive]{
		mainLayoutName:    a.mainLayout(mainPanels),
		helpLayoutName:    a.helpLayout(helpPanels),
		filtersLayoutName: a.filtersLayout(),
		panelTraceName:    mainPanels[panelTraceName],
		panelTblName:      mainPanels[panelTblName],
		modalErrName:      a.newErrWindow(),
	})
	a.next = ui.NewNextPrimitive(mainPanels[panelTraceName], mainPanels[panelTblName])
	a.Page.Add(a.primitives.GetPrimitivesByNames(mainLayoutName, helpLayoutName, filtersLayoutName, modalErrName)...)
	a.Page.SwitchToPage(mainLayoutName)
	a.bindKeys()
	a.SetInputCapture(a.keyboard).
		EnableMouse(true).
		EnablePaste(true)
	return a
}

// Run starts the application loop.
func (a *view) Run() (err error) {
	defer func() {
		if err != nil {
			a.cleanup()
		}
	}()
	ctx1, cancel := context.WithCancel(a.ctxApp)
	defer cancel()
	ff := [...]func() error{
		func() error {
			return a.TblProvider.Run(ctx1)
		},
		func() error {
			return a.App.RunWithCtx(ctx1)
		},
	}

	errs := make([]error, len(ff))
	_ = parallel.ExecAbstract(len(ff), int32(len(ff)-1), func(i int) error {
		defer cancel()
		errs[i] = ff[i]()
		return nil
	})

	select {
	case <-a.ctxApp.Done():
		return a.ctxApp.Err()
	default:
	}
	return multierr.Combine(errs...)
}

func (a *view) cleanup() {
	if a.TblProvider != nil {
		_ = a.TblProvider.Close()
	}
	if a.Visor != nil {
		_ = a.Visor.Close()
	}
	if a.App != nil {
		a.Stop()
	}
}

func (a *view) startCapturingTrace() error {
	go func() {
		var (
			err error
			md  model.TraceScopeModel
		)
		defer func() { a.handleErr(err) }()

		md, err = a.cfg.CmdFlags.ToTraceScopeModel()
		if err != nil {
			return
		}
		err = a.Visor.Run(a.ctxApp, md)
		if errors.Is(err, visor.ErrVisorRunOrStopped) {
			err = nil
		}
	}()
	a.log("Trace capturing has started...")
	return nil
}

func (a *view) stopCapturingTrace() (err error) {
	err = a.Visor.Close()
	if err == nil {
		a.log("Trace capturing has paused")
	}
	if errors.Is(err, visor.ErrVisorAlreadyPaused) {
		err = nil
	}
	return err
}

func (a *view) restartCapturingTrace() (err error) {
	if !a.Visor.IsStarted() {
		return nil
	}
	err = a.stopCapturingTrace()
	if err != nil {
		return err
	}
	return a.startCapturingTrace()
}
