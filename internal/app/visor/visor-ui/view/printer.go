package view

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/wildberries-tech/pkt-tracer/internal/app/visor"
	ui "github.com/wildberries-tech/pkt-tracer/internal/app/visor/visor-ui/tui"
	model "github.com/wildberries-tech/pkt-tracer/internal/models/trace"
	"github.com/wildberries-tech/pkt-tracer/internal/nftrace/printer"
)

var (
	portRE  = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)`)
	protoRE = regexp.MustCompile(`proto=(\w+)`)
)

type (
	viewPrinter struct{}
)

func NewPrinter() visor.Printer {
	return &viewPrinter{}
}

func (p *viewPrinter) Print(traces []model.FetchTraceModel) {
	v := GetViewer().(*view)
	if v != nil {
		v.print(traces)
	}
}

// print - print trace (overloaded method for printer)
func (a *view) print(traces []model.FetchTraceModel) {
	tracePanel := a.primitives.At(panelTraceName).(*ui.Panel)
	printer.PrintTrace(traces, false, func(msg string, keysAndValues ...interface{}) {
		tracePanel.Printf(markLinesWithTrace(tracePanel, msg, keysAndValues...)) //nolint:govet
	}, func(trace model.FetchTraceModel) {
		tracePanel.CacheLine.Put(tracePanel.GetPrintCount(), trace)
	})
}

func markLinesWithTrace(p *ui.Panel, msg string, keysAndValues ...interface{}) string {
	return fmt.Sprintf(`["%d"]`, p.GetPrintCount()+1) + colorizeTrace(msg, keysAndValues...) + `[""]`
}

func markLinesWithRule(tbl string, tblId uint64) string {
	strs := strings.Split(tbl, "\n")
	for i := range strs {
		if strings.Contains(strs[i], "#handle") {
			if hndlParts := strings.Split(strs[i], "#handle "); len(hndlParts) > 1 {
				val, _ := strconv.ParseUint(hndlParts[1], 10, 64)
				strs[i] = fmt.Sprintf(`["%d"]%s[""]`, tblId^val, strs[i])
			}
		}
	}
	return strings.Join(strs, "\n")
}

func colorizeTrace(msg string, keysAndValues ...interface{}) string {
	ret := fmt.Sprintf(msg, keysAndValues...)

	ret = portRE.ReplaceAllStringFunc(ret, func(s string) string {
		match := portRE.FindStringSubmatch(s)
		ip, port := match[1], match[2]
		return fmt.Sprintf("%s:[yellow]%s[white]", ip, port)
	})

	ret = protoRE.ReplaceAllStringFunc(ret, func(s string) string {
		match := protoRE.FindStringSubmatch(s)
		return fmt.Sprintf("proto=[green]%s[white]", match[1])
	})

	return ret
}
