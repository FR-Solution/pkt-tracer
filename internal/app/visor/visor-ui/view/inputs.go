package view

import (
	"fmt"
	"time"

	vf "github.com/wildberries-tech/pkt-tracer/internal/app/visor/flags"
	ui "github.com/wildberries-tech/pkt-tracer/internal/app/visor/visor-ui/tui"

	"github.com/H-BF/corlib/pkg/patterns/observer"
	linq "github.com/ahmetb/go-linq/v3"
	"go.uber.org/multierr"
)

type (
	updFiltersInputFields struct {
		flt vf.Flags
		observer.EventType
	}

	filterInputsMap map[string]ui.InputFace
)

func (f filterInputsMap) Items() (ret []ui.InputFace) {
	linq.From(f).OrderBy(func(i interface{}) interface{} {
		kv := i.(linq.KeyValue)
		return kv.Value.(ui.InputFace).Name()
	}).ForEach(func(i any) {
		kv := i.(linq.KeyValue)
		ret = append(ret, kv.Value.(ui.InputFace))
	})
	return
}

func (f filterInputsMap) Primitives() (ret []ui.Primitive) {
	for _, item := range f.Items() {
		ret = append(ret, item)
	}
	return
}

func (f filterInputsMap) updInputFields(fl vf.Flags) error {
	var errs []error
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.TrId)], fl.TrId...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.Table)], fl.Table...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.Chain)], fl.Chain...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.JumpTarget)], fl.JumpTarget...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.RuleHandle)], fl.RuleHandle...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.Family)], fl.Family...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.Iifname)], fl.Iifname...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.Oifname)], fl.Oifname...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.SMacAddr)], fl.SMacAddr...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.DMacAddr)], fl.DMacAddr...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.SAddr)], fl.SAddr...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.DAddr)], fl.DAddr...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.SPort)], fl.SPort...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.DPort)], fl.DPort...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.SSgName)], fl.SSgName...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.DSgName)], fl.DSgName...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.SSgNet)], fl.SSgNet...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.DSgNet)], fl.DSgNet...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.Length)], fl.Length...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.IpProto)], fl.IpProto...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.Verdict)], fl.Verdict...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.AgentsIds)], fl.AgentsIds...))
	errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(&fl.Query)], fl.Query))
	if fl.TimeDuration != nil {
		errs = append(errs, ui.SetInputValues(f[fl.NameFromTag(fl.TimeDuration)], *fl.TimeDuration))
	}

	return multierr.Combine(errs...)
}

func (m filterInputsMap) GetInputValues(f *vf.Flags) (err error) {
	var (
		errs      []error
		durations []time.Duration
	)
	f.TrId, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.TrId)], ",", f.TrId...)
	errs = append(errs, err)
	f.Table, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.Table)], ",", f.Table...)
	errs = append(errs, err)
	f.Chain, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.Chain)], ",", f.Chain...)
	errs = append(errs, err)
	f.JumpTarget, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.JumpTarget)], ",", f.JumpTarget...)
	errs = append(errs, err)
	f.RuleHandle, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.RuleHandle)], ",", f.RuleHandle...)
	errs = append(errs, err)
	f.Family, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.Family)], ",", f.Family...)
	errs = append(errs, err)
	f.Iifname, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.Iifname)], ",", f.Iifname...)
	errs = append(errs, err)
	f.Oifname, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.Oifname)], ",", f.Oifname...)
	errs = append(errs, err)
	f.SMacAddr, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.SMacAddr)], ",", f.SMacAddr...)
	errs = append(errs, err)
	f.DMacAddr, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.DMacAddr)], ",", f.DMacAddr...)
	errs = append(errs, err)
	f.SAddr, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.SAddr)], ",", f.SAddr...)
	errs = append(errs, err)
	f.DAddr, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.DAddr)], ",", f.DAddr...)
	errs = append(errs, err)
	f.SPort, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.SPort)], ",", f.SPort...)
	errs = append(errs, err)
	f.DPort, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.DPort)], ",", f.DPort...)
	errs = append(errs, err)
	f.SSgName, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.SSgName)], ",", f.SSgName...)
	errs = append(errs, err)
	f.DSgName, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.DSgName)], ",", f.DSgName...)
	errs = append(errs, err)
	f.SSgNet, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.SSgNet)], ",", f.SSgNet...)
	errs = append(errs, err)
	f.DSgNet, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.DSgNet)], ",", f.DSgNet...)
	errs = append(errs, err)
	f.Length, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.Length)], ",", f.Length...)
	errs = append(errs, err)
	f.IpProto, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.IpProto)], ",", f.IpProto...)
	errs = append(errs, err)
	f.Verdict, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.Verdict)], ",", f.Verdict...)
	errs = append(errs, err)
	f.AgentsIds, err = ui.GetInputValuesByType(m[f.NameFromTag(&f.AgentsIds)], ",", f.AgentsIds...)
	errs = append(errs, err)
	if f.TimeDuration != nil {
		durations, err = ui.GetInputValuesByType(m[f.NameFromTag(f.TimeDuration)], ",", *f.TimeDuration)
		errs = append(errs, err)
		if len(durations) > 0 {
			f.TimeDuration = &durations[0]
		}
	}

	f.Query = m[f.NameFromTag(&f.Query)].GetText()
	_, err = vf.QueryFlag(f.Query).ToSql()
	errs = append(errs, err)

	return multierr.Combine(errs...)
}

func newFilterInputs(fl vf.Flags) filterInputsMap {
	const (
		fieldWidth = 0
		rank       = 10
	)
	directOrder := newDirectOrderer(rank)
	return filterInputsMap{
		fl.NameFromTag(&fl.TrId): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.TrId).Name),
			Label:       fl.GetFieldFlagParams(&fl.TrId).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.TrId).Example,
			FieldWidth:  fieldWidth,
		}, fl.TrId...),
		fl.NameFromTag(&fl.Table): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.Table).Name),
			Label:       fl.GetFieldFlagParams(&fl.Table).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.Table).Example,
			FieldWidth:  fieldWidth,
		}, fl.Table...),
		fl.NameFromTag(&fl.Chain): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.Chain).Name),
			Label:       fl.GetFieldFlagParams(&fl.Chain).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.Chain).Example,
			FieldWidth:  fieldWidth,
		}, fl.Chain...),
		fl.NameFromTag(&fl.JumpTarget): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.JumpTarget).Name),
			Label:       fl.GetFieldFlagParams(&fl.JumpTarget).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.JumpTarget).Example,
			FieldWidth:  fieldWidth,
		}, fl.JumpTarget...),
		fl.NameFromTag(&fl.RuleHandle): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.RuleHandle).Name),
			Label:       fl.GetFieldFlagParams(&fl.RuleHandle).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.RuleHandle).Example,
			FieldWidth:  fieldWidth,
		}, fl.RuleHandle...),
		fl.NameFromTag(&fl.Family): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.Family).Name),
			Label:       fl.GetFieldFlagParams(&fl.Family).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.Family).Example,
			FieldWidth:  fieldWidth,
		}, fl.Family...),
		fl.NameFromTag(&fl.Iifname): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.Iifname).Name),
			Label:       fl.GetFieldFlagParams(&fl.Iifname).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.Iifname).Example,
			FieldWidth:  fieldWidth,
		}, fl.Iifname...),
		fl.NameFromTag(&fl.Oifname): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.Oifname).Name),
			Label:       fl.GetFieldFlagParams(&fl.Oifname).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.Oifname).Example,
			FieldWidth:  fieldWidth,
		}, fl.Oifname...),
		fl.NameFromTag(&fl.SMacAddr): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.SMacAddr).Name),
			Label:       fl.GetFieldFlagParams(&fl.SMacAddr).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.SMacAddr).Example,
			FieldWidth:  fieldWidth,
		}, fl.SMacAddr...),
		fl.NameFromTag(&fl.DMacAddr): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.DMacAddr).Name),
			Label:       fl.GetFieldFlagParams(&fl.DMacAddr).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.DMacAddr).Example,
			FieldWidth:  fieldWidth,
		}, fl.DMacAddr...),
		fl.NameFromTag(&fl.SAddr): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.SAddr).Name),
			Label:       fl.GetFieldFlagParams(&fl.SAddr).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.SAddr).Example,
			FieldWidth:  fieldWidth,
		}, fl.SAddr...),
		fl.NameFromTag(&fl.DAddr): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.DAddr).Name),
			Label:       fl.GetFieldFlagParams(&fl.DAddr).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.DAddr).Example,
			FieldWidth:  fieldWidth,
		}, fl.DAddr...),

		fl.NameFromTag(&fl.SPort): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.SPort).Name),
			Label:       fl.GetFieldFlagParams(&fl.SPort).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.SPort).Example,
			FieldWidth:  fieldWidth,
		}, fl.SPort...),
		fl.NameFromTag(&fl.DPort): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.DPort).Name),
			Label:       fl.GetFieldFlagParams(&fl.DPort).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.DPort).Example,
			FieldWidth:  fieldWidth,
		}, fl.DPort...),
		fl.NameFromTag(&fl.SSgName): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.SSgName).Name),
			Label:       fl.GetFieldFlagParams(&fl.SSgName).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.SSgName).Example,
			FieldWidth:  fieldWidth,
		}, fl.SSgName...),
		fl.NameFromTag(&fl.DSgName): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.DSgName).Name),
			Label:       fl.GetFieldFlagParams(&fl.DSgName).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.DSgName).Example,
			FieldWidth:  fieldWidth,
		}, fl.DSgName...),
		fl.NameFromTag(&fl.SSgNet): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.SSgNet).Name),
			Label:       fl.GetFieldFlagParams(&fl.SSgNet).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.SSgNet).Example,
			FieldWidth:  fieldWidth,
		}, fl.SSgNet...),
		fl.NameFromTag(&fl.DSgNet): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.DSgNet).Name),
			Label:       fl.GetFieldFlagParams(&fl.DSgNet).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.DSgNet).Example,
			FieldWidth:  fieldWidth,
		}, fl.DSgNet...),
		fl.NameFromTag(&fl.Length): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.Length).Name),
			Label:       fl.GetFieldFlagParams(&fl.Length).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.Length).Example,
			FieldWidth:  fieldWidth,
		}, fl.Length...),
		fl.NameFromTag(&fl.IpProto): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.IpProto).Name),
			Label:       fl.GetFieldFlagParams(&fl.IpProto).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.IpProto).Example,
			FieldWidth:  fieldWidth,
		}, fl.IpProto...),
		fl.NameFromTag(&fl.Verdict): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.Verdict).Name),
			Label:       fl.GetFieldFlagParams(&fl.Verdict).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.Verdict).Example,
			FieldWidth:  fieldWidth,
		}, fl.Verdict...),
		fl.NameFromTag(&fl.AgentsIds): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.AgentsIds).Name),
			Label:       fl.GetFieldFlagParams(&fl.AgentsIds).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.AgentsIds).Example,
			FieldWidth:  fieldWidth,
		}, fl.AgentsIds...),
		fl.NameFromTag(&fl.Query): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.Query).Name),
			Label:       fl.GetFieldFlagParams(&fl.Query).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.Query).Example,
			FieldWidth:  fieldWidth,
		}, fl.Query),
		fl.NameFromTag(fl.TimeDuration): ui.NewInputByType(ui.InputOPtions{
			Name:        directOrder(fl.GetFieldFlagParams(&fl.TimeDuration).Name),
			Label:       fl.GetFieldFlagParams(&fl.TimeDuration).Name,
			PlaceHolder: fl.GetFieldFlagParams(&fl.TimeDuration).Example,
			FieldWidth:  fieldWidth,
		}, *fl.TimeDuration),
	}
}

func newDirectOrderer(offset int) func(string) string {
	cnt := offset
	return func(s string) string {
		cnt++
		return fmt.Sprintf("%d %s", cnt, s)
	}
}
